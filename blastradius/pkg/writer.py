"""Batched writer for the package graph.

Write forms follow the shapes HydraDB actually accepts, which are narrower than
the Cypher subset suggests:

* nodes are ``UNWIND`` + ``MERGE`` by id + ``SET`` -- folding properties into
  the ``MERGE`` pattern is rejected, because the pattern is the identity being
  matched on;
* edges are ``UNWIND`` + ``MATCH`` both endpoints + ``MERGE`` with an explicit
  relationship id, and both endpoints must carry **exactly one label**, so
  rows are bucketed by ``(edge type, source label, destination label)`` rather
  than by edge type alone;
* a list parameter is only accepted as ``UNWIND`` input, and only over the
  client transport.

Every edge is written twice, forwards and inverted. That is not an
optimisation: plain ``MATCH`` can only pin the *source* of a traversal, so
without the inverse a "who reaches this" question cannot be expressed at all.
The ``algo.*`` procedures do accept ``relDirection: 'incoming'``, which would
make half these edges redundant -- that is benchmarked before it is trusted
(PLAN.md experiment A), not assumed.

Idempotence comes from ids: every id is a persisted function of a natural key,
so re-running ingest re-``MERGE``s the same rows rather than duplicating them.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .. import schema
from ..hydra_client import HydraClient
from ..ids import IdAllocator

__all__ = ["NODE_PROPS", "EDGE_PROPS", "PackageGraphWriter", "WriteReport"]


#: Every property of a label is written on every node of that label.
#: `WHERE` has no IS NULL, so a property that is sometimes absent can never be
#: tested for -- an absent value is not "null", it is unqueryable. Sentinels
#: from schema.py stand in for unknowns.
NODE_PROPS: dict[str, tuple[str, ...]] = {
    schema.PACKAGE: (
        "key", "name", "scope", "latest_version", "version_count",
        # Which registry this name belongs to. npm's `requests` and PyPI's
        # `requests` are unrelated projects; the purl key already separates
        # them, and this is what lets a query filter or a UI label them
        # without parsing the key back apart.
        "ecosystem",
        "downloads", "deprecated", "source", "ingested_at",
    ),
    # Superset of the sample loader's PackageVersion properties, so a graph
    # written by this pipeline still answers the queries that shipped with it.
    schema.PACKAGE_VERSION: (
        "key", "name", "version", "ecosystem", "dev", "integrity",
        "published_at", "withdrawn_at", "license", "deprecated",
        "has_install_script", "description", "source", "ingested_at",
    ),
    schema.SERVICE: ("name", "repo", "path"),
    schema.LOCKFILE: (
        "key", "path", "service", "lockfile_version", "observed_at",
        "entry_count", "source", "ingested_at",
    ),
    schema.LOCKFILE_ENTRY: (
        "key", "path", "package_name", "resolved_version", "resolved_url",
        "integrity", "dev", "optional", "peer", "bundled", "depth",
        "source", "ingested_at",
    ),
    schema.MAINTAINER: (
        "key", "username", "email", "package_count", "source", "ingested_at",
    ),
    schema.REPOSITORY: (
        "key", "host", "owner", "name", "url", "package_count",
        "source", "ingested_at",
    ),
    schema.ORGANIZATION: ("key", "name", "kind", "source", "ingested_at"),
    schema.PUBLISHER: ("key", "username", "email", "source", "ingested_at"),
    schema.ADVISORY: (
        # `severity` is the qualitative label the feed published; the numeric
        # `severity_score` is still underived from the vector. Both are kept
        # because they are different claims, and a reader offered only the
        # sentinel score would think the advisory was unrated.
        "key", "advisory_id", "aliases", "summary", "cvss_vector",
        "severity", "severity_score", "published", "modified",
        "source", "ingested_at",
    ),
    schema.INCIDENT: (
        "key", "incident_id", "status", "summary", "live_from", "live_until",
        "source", "ingested_at",
    ),
}

#: Edge properties, same completeness rule. An edge type and its inverse carry
#: the same properties so a query reads the same fields whichever way it walks.
EDGE_PROPS: dict[str, tuple[str, ...]] = {
    schema.HAS_VERSION: ("source",),
    # The resolved parent -> child edge. npm gets its closure from the
    # lockfile and writes REQUIRES/SATISFIED_BY; a Python resolution is
    # already exact, so it writes the resolved edge directly -- and it is the
    # edge the Explorer's reach walk reads, so both ecosystems answer the same
    # question through the same relationship.
    schema.DEPENDS_ON: ("source",),
    schema.REQUIRES: ("range", "dep_type", "optional", "peer", "bundled", "source"),
    schema.SATISFIED_BY: ("range", "dep_type", "source"),
    schema.HAS_LOCKFILE: ("source",),
    schema.HAS_ENTRY: ("source",),
    schema.RESOLVES_VERSION: ("source",),
    schema.RESOLVED_IN: (
        "depth", "via_direct", "dev_only", "first_seen", "last_seen", "source",
    ),
    schema.MAINTAINED_BY: ("source",),
    schema.SOURCED_FROM: ("source",),
    schema.OWNED_BY: ("source",),
    schema.PUBLISHED_BY: ("source",),
    schema.MEMBER_OF: ("source",),
    schema.TYPOSQUAT_OF: (
        "distance", "technique", "popularity_ratio", "source",
    ),
    schema.AFFECTS: (
        "fixed_version", "introduced_version", "fixed_published_at", "source",
    ),
    schema.COMPROMISES: ("source",),
}

#: Defaults per property type, so a caller may omit anything it does not know
#: and still satisfy the write-every-property rule.
_DEFAULTS: dict[str, Any] = {
    "source": "unknown",
    # npm unless a caller says otherwise; every existing write is npm.
    "ecosystem": "npm",
    "ingested_at": schema.UNKNOWN_TS,
    "published_at": schema.UNKNOWN_TS,
    "withdrawn_at": schema.STILL_LIVE,
    "observed_at": schema.UNKNOWN_TS,
    "first_seen": schema.UNKNOWN_TS,
    "last_seen": schema.STILL_LIVE,
    "live_from": schema.UNKNOWN_TS,
    "live_until": schema.STILL_LIVE,
    "published": schema.UNKNOWN_TS,
    "modified": schema.UNKNOWN_TS,
    # UNKNOWN_TS, not STILL_LIVE. "We could not date the fix" and "there is no
    # fix" are different claims, and defaulting to the second would close
    # every window at the end of time and report exposure that was never
    # measured.
    "fixed_published_at": schema.UNKNOWN_TS,
    "severity_score": schema.UNKNOWN_SCORE,
    "depth": schema.NO_DEPTH,
    "downloads": 0,
    "version_count": 0,
    "package_count": 0,
    "entry_count": 0,
    "distance": schema.NO_DEPTH,
    "popularity_ratio": 0,
}


def _default_for(prop: str) -> Any:
    if prop in _DEFAULTS:
        return _DEFAULTS[prop]
    # Booleans are written as 0/1 integers: there is no boolean ordering worth
    # relying on, and sum() over an int column is available where a bool is not.
    if prop in ("dev", "optional", "peer", "bundled", "deprecated",
                "has_install_script", "dev_only"):
        return 0
    return schema.UNKNOWN_STR


def _coerce(value: Any) -> Any:
    """Property values are integers, floats, booleans and strings only."""
    if isinstance(value, bool):
        return 1 if value else 0
    if value is None:
        return schema.UNKNOWN_STR
    if isinstance(value, (list, tuple, set)):
        # No list-valued properties. Joined so STARTS WITH can still find a
        # member prefix, which is the only string predicate available.
        return "|".join(str(v) for v in sorted(value))
    if isinstance(value, (int, float, str)):
        return value
    return str(value)


@dataclass
class WriteReport:
    nodes: dict[str, int] = field(default_factory=dict)
    edges: dict[str, int] = field(default_factory=dict)
    statements: int = 0
    elapsed_ms: float = 0.0

    @property
    def node_total(self) -> int:
        return sum(self.nodes.values())

    @property
    def edge_total(self) -> int:
        return sum(self.edges.values())

    def render(self) -> str:
        lines = ["nodes:"]
        for label, n in sorted(self.nodes.items()):
            lines.append(f"  {label:20} {n:>9,}")
        lines.append(f"  {'TOTAL':20} {self.node_total:>9,}")
        lines.append("")
        lines.append("edges:")
        for etype, n in sorted(self.edges.items()):
            lines.append(f"  {etype:24} {n:>9,}")
        lines.append(f"  {'TOTAL':24} {self.edge_total:>9,}")
        lines.append("")
        lines.append(
            f"{self.statements} statements in {self.elapsed_ms/1000:.1f}s"
        )
        return "\n".join(lines)


class PackageGraphWriter:
    """Stages nodes and edges in memory, then writes them in batched UNWINDs."""

    def __init__(
        self,
        client: HydraClient,
        ids: IdAllocator,
        source: str = "unknown",
        verbose: bool = True,
        parallelism: int = 4,
    ):
        self.client = client
        self.ids = ids
        self.source = source
        self.verbose = verbose
        #: Batches are HTTP round trips against a server that holds no
        #: transaction, so they are independent and safe to overlap. The work
        #: is entirely I/O-bound, which is why threads help despite the GIL.
        self.parallelism = max(1, parallelism)

        self._nodes: dict[str, dict[int, dict]] = {}
        #: Keyed by (edge type, source label, destination label): a write
        #: UNWIND requires exactly one label per endpoint, and an edge type
        #: like RESOLVED_IN spans more than one label pair.
        self._edges: dict[tuple[str, str, str], dict[int, dict]] = {}
        self._label_of: dict[int, str] = {}
        self.report = WriteReport()

    # -- staging -----------------------------------------------------------

    def node(self, label: str, natural_key: str, **props: Any) -> int:
        """Stage one node, returning its id. Safe to call repeatedly."""
        if label not in NODE_PROPS:
            raise KeyError(f"no property schema for label {label!r}")
        node_id = self.ids.get(label, natural_key)
        row = {"id": node_id}
        props.setdefault("key", natural_key)
        props.setdefault("source", self.source)
        for prop in NODE_PROPS[label]:
            row[prop] = _coerce(props.get(prop, _default_for(prop)))
        # Later stagings win, so enrichment passes can fill in what an earlier
        # cheaper pass left at a sentinel.
        existing = self._nodes.setdefault(label, {}).get(node_id)
        if existing:
            for key, value in row.items():
                if value not in (schema.UNKNOWN_STR, schema.UNKNOWN_TS, None):
                    existing[key] = value
        else:
            self._nodes[label][node_id] = row
        self._label_of[node_id] = label
        return node_id

    def register(self, label: str, node_id: int) -> int:
        """Record an existing node's label without staging a write.

        An edge statement MATCHes both endpoints by label, so the writer has to
        know the label of a node it did not create. Restaging the node to teach
        it that would write a full property row built from defaults, and every
        sentinel in that row would overwrite the real value already in the
        graph -- which is how creating an incident silently blanked the
        published date, licence and provenance of the very version it pointed
        at.
        """
        self._label_of[node_id] = label
        return node_id

    def edge(self, etype: str, src: int, dst: int, **props: Any) -> None:
        """Stage an edge, and its inverse only where a query actually needs one.

        Measured, not assumed: a single-hop backward pattern with the
        destination pinned is accepted by the server, so only the one
        relationship walked backwards for multiple hops needs materialising in
        both directions. See schema.PKG_NEEDS_INVERSE.
        """
        self._stage(etype, src, dst, props)
        if etype in schema.PKG_NEEDS_INVERSE:
            inverse = schema.PKG_INVERSE_OF.get(etype)
            if inverse:
                self._stage(inverse, dst, src, props, prop_source=etype)

    def _stage(
        self,
        etype: str,
        src: int,
        dst: int,
        props: dict,
        prop_source: str | None = None,
    ) -> None:
        try:
            src_label = self._label_of[src]
            dst_label = self._label_of[dst]
        except KeyError:
            raise KeyError(
                f"{etype}: endpoint {src if src not in self._label_of else dst} "
                f"was never staged, so its label is unknown and the MATCH "
                f"cannot be written. Stage both nodes before the edge."
            ) from None

        # An inverse carries the same properties as its forward edge, so a
        # reader sees identical fields whichever direction it walks.
        schema_key = prop_source or etype
        fields = EDGE_PROPS.get(schema_key, ("source",))
        rel_id = self.ids.get(etype, f"{src}->{dst}")
        row = {"src": src, "dst": dst, "rel": rel_id}
        props.setdefault("source", self.source)
        for prop in fields:
            row[prop] = _coerce(props.get(prop, _default_for(prop)))
        self._edges.setdefault((etype, src_label, dst_label), {})[rel_id] = row

    # -- writing -----------------------------------------------------------

    def _node_statement(self, label: str) -> str:
        sets = ", ".join(f"n.{p} = row.{p}" for p in NODE_PROPS[label])
        # MERGE by id then SET: folding properties into the MERGE pattern is
        # rejected, since the pattern is the identity being matched on.
        return f"UNWIND $rows AS row MERGE (n {{id: row.id}}) SET n:{label}, {sets}"

    def _edge_statement(
        self, etype: str, src_label: str, dst_label: str, fields: tuple[str, ...]
    ) -> str:
        sets = ", ".join(f"r.{p} = row.{p}" for p in fields)
        return (
            "UNWIND $rows AS row "
            f"MATCH (s:{src_label} {{id: row.src}}), (d:{dst_label} {{id: row.dst}}) "
            f"MERGE (s)-[r:{etype} {{id: row.rel}}]->(d)"
            + (f" SET {sets}" if sets else "")
        )

    def flush(self) -> WriteReport:
        """Write everything staged. Idempotent -- reruns MERGE, never duplicate."""
        import time

        started = time.perf_counter()

        node_jobs: list[tuple[str, str, list[dict]]] = []
        for label, rows in self._nodes.items():
            node_jobs.append((label, self._node_statement(label), list(rows.values())))

        edge_jobs: list[tuple[str, str, list[dict]]] = []
        for (etype, src_label, dst_label), rows in self._edges.items():
            fields = tuple(
                k for k in next(iter(rows.values())).keys()
                if k not in ("src", "dst", "rel")
            )
            edge_jobs.append((
                f"{etype} ({src_label}->{dst_label})",
                self._edge_statement(etype, src_label, dst_label, fields),
                list(rows.values()),
            ))

        def run(job: tuple[str, str, list[dict]]) -> tuple[str, int]:
            name, statement, rows = job
            sent = self.client.batch(statement, rows, progress=False)
            return name, sent

        def run_phase(jobs: list[tuple[str, str, list[dict]]]) -> list[tuple[str, int]]:
            if not jobs:
                return []
            if self.parallelism > 1 and len(jobs) > 1:
                with ThreadPoolExecutor(max_workers=self.parallelism) as pool:
                    return list(pool.map(run, jobs))
            return [run(job) for job in jobs]

        # Two phases, each internally parallel. An edge statement MATCHes both
        # of its endpoints, so it fails outright if the node has not landed
        # yet -- and with no transactions there is nothing to order the two
        # otherwise. Running both phases in one pool is a race that hides
        # whenever there happen to be more node jobs than worker threads,
        # which is exactly how it survived a large ingest and then failed on a
        # two-node one.
        results = run_phase(node_jobs)
        node_names = {name for name, _ in results}
        results += run_phase(edge_jobs)

        for name, sent in results:
            if name in node_names:
                self.report.nodes[name] = self.report.nodes.get(name, 0) + sent
            else:
                etype = name.split(" ", 1)[0]
                self.report.edges[etype] = self.report.edges.get(etype, 0) + sent
            self._log(f"  {name:36} {sent:>8,}")

        self.report.statements += len(node_jobs) + len(edge_jobs)
        self.report.elapsed_ms += (time.perf_counter() - started) * 1000
        self.ids.commit()
        self._nodes.clear()
        self._edges.clear()
        return self.report

    def staged_counts(self) -> tuple[int, int]:
        """(nodes, edges) currently staged but not yet written."""
        return (
            sum(len(v) for v in self._nodes.values()),
            sum(len(v) for v in self._edges.values()),
        )

    def _log(self, message: str) -> None:
        if self.verbose:
            print(message, flush=True)
