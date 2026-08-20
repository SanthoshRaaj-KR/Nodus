"""The whole graph, as circles, with enough metadata to explain each one.

Every other view here is scoped: the macro view answers about one version, the
micro view about one call chain. This one answers nothing in particular -- it
is the map you look at before you know what you are asking, and the surface a
live alert lands on.

**Why it is built in one sweep and then cached.** Node reads are label scans,
which this node answers in tens of milliseconds. Edge reads are the expensive
shape: an unpinned `(a)-[e:TYPE]->(b)` sweep costs 500-770 ms, and there are
nine of them here. Cold, that is several seconds; served again it must be
instant, so the payload is cached against the node's `read_epoch` and rebuilt
only when a write actually lands. An ingest therefore invalidates it for free.

**What is left out, and why it is a choice rather than an oversight.**
``LockfileEntry`` is one node per resolved dependency per project -- 649 of
them on the current corpus -- and each is joined 1:1 to a ``PackageVersion``
that already carries everything the entry knows. Drawing both doubles the node
count to say the same thing twice. ``SATISFIED_BY`` is excluded for the
opposite reason: at 4,210 edges it is the densest relation in the graph and it
encodes *possibility*, not installation, so it would dominate the picture with
exactly the range-only signal the rest of the project exists to keep separate
from the truth. Both are available on request, and the counts always report
what was omitted.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .. import schema
from ..hydra_client import HydraClient

__all__ = ["GraphSpec", "build_full_graph", "NODE_FIELDS", "EDGE_SWEEPS"]


#: Per label: the properties worth carrying to the browser for the hover and
#: click panels. Deliberately not "every property" -- the payload is sent whole
#: and `ingested_at` on 1,317 versions is 1,317 numbers nobody reads.
NODE_FIELDS: dict[str, tuple[str, ...]] = {
    schema.SERVICE: ("name", "repo", "path"),
    schema.PACKAGE: ("name", "latest_version", "version_count", "downloads",
                     "deprecated"),
    schema.PACKAGE_VERSION: ("name", "version", "published_at", "license",
                             "has_install_script", "deprecated", "integrity"),
    schema.MAINTAINER: ("username", "email", "package_count"),
    schema.REPOSITORY: ("host", "owner", "name", "url"),
    schema.PUBLISHER: ("username", "email"),
    schema.ADVISORY: ("advisory_id", "severity", "summary", "cvss_vector"),
    schema.ORGANIZATION: ("name", "kind"),
    schema.LOCKFILE: ("path", "service", "entry_count"),
    schema.INCIDENT: ("incident_id", "status", "summary"),
    schema.LOCKFILE_ENTRY: ("package_name", "resolved_version", "depth", "dev"),
}

#: Which property reads best as the node's label on screen.
DISPLAY_FIELD: dict[str, str] = {
    schema.SERVICE: "name",
    schema.PACKAGE: "name",
    schema.PACKAGE_VERSION: "key",
    schema.MAINTAINER: "username",
    schema.REPOSITORY: "url",
    schema.PUBLISHER: "username",
    schema.ADVISORY: "advisory_id",
    schema.ORGANIZATION: "name",
    schema.LOCKFILE: "service",
    schema.INCIDENT: "incident_id",
    schema.LOCKFILE_ENTRY: "package_name",
}

#: (edge type, source label, destination label). Order matters only for the
#: report; the browser treats them as one set.
EDGE_SWEEPS: tuple[tuple[str, str, str], ...] = (
    (schema.HAS_VERSION, schema.PACKAGE, schema.PACKAGE_VERSION),
    (schema.RESOLVED_IN, schema.PACKAGE_VERSION, schema.SERVICE),
    (schema.MAINTAINED_BY, schema.PACKAGE, schema.MAINTAINER),
    (schema.SOURCED_FROM, schema.PACKAGE_VERSION, schema.REPOSITORY),
    (schema.PUBLISHED_BY, schema.PACKAGE_VERSION, schema.PUBLISHER),
    (schema.OWNED_BY, schema.PACKAGE, schema.ORGANIZATION),
    (schema.AFFECTS, schema.ADVISORY, schema.PACKAGE_VERSION),
    (schema.COMPROMISES, schema.INCIDENT, schema.PACKAGE_VERSION),
    (schema.REQUIRES, schema.PACKAGE_VERSION, schema.PACKAGE),
    (schema.HAS_LOCKFILE, schema.SERVICE, schema.LOCKFILE),
    (schema.TYPOSQUAT_OF, schema.PACKAGE, schema.PACKAGE),
)

#: Sweeps held back by default, with the reason each is expensive to draw.
OPTIONAL_SWEEPS: dict[str, tuple[tuple[str, str, str], str]] = {
    "satisfied_by": (
        (schema.SATISFIED_BY, schema.PACKAGE_VERSION, schema.PACKAGE_VERSION),
        "4,210 edges encoding what a range admits, not what was installed",
    ),
    "lockfile_entries": (
        (schema.RESOLVES_VERSION, schema.LOCKFILE_ENTRY, schema.PACKAGE_VERSION),
        "one node per resolved dependency, 1:1 with a PackageVersion",
    ),
}

#: Labels drawn by default. LockfileEntry is opt-in for the reason above.
DEFAULT_LABELS: tuple[str, ...] = (
    schema.SERVICE, schema.PACKAGE, schema.PACKAGE_VERSION, schema.MAINTAINER,
    schema.REPOSITORY, schema.PUBLISHER, schema.ADVISORY, schema.ORGANIZATION,
    schema.LOCKFILE, schema.INCIDENT,
)


@dataclass
class GraphSpec:
    """What to draw. Every field is echoed back in the payload."""

    labels: tuple[str, ...] = DEFAULT_LABELS
    include_satisfied_by: bool = False
    include_lockfile_entries: bool = False
    #: Hard ceiling. Not a silent truncation: if it bites, the payload says so
    #: and names how many nodes were dropped, because a map missing a third of
    #: itself with no warning is worse than no map.
    max_nodes: int = 20_000


def _sweep_nodes(
    client: HydraClient, label: str
) -> list[dict]:
    """Every node of one label, with the fields worth showing.

    A label scan, which this node answers in tens of milliseconds -- and which
    admission control rejects outright past 250,000 candidates. That ceiling is
    far above any fleet graph and far below the ecosystem, which is exactly the
    line this view sits on.
    """
    fields = NODE_FIELDS.get(label, ())
    projection = ", ".join(f"n.{f} AS {f}" for f in fields)
    statement = (
        f"MATCH (n:{label}) RETURN n.id AS id"
        + (f", {projection}" if projection else "")
    )
    rows = client.query(statement)
    out: list[dict] = []
    display = DISPLAY_FIELD.get(label, "name")
    for row in rows:
        data = dict(row)
        node_id = data.pop("id", None)
        if node_id is None:
            continue
        out.append({
            "id": node_id,
            "label": label,
            "name": str(data.get(display) or data.get("name") or node_id),
            "meta": {k: v for k, v in data.items() if v not in ("", None)},
        })
    return out


def _sweep_edges(
    client: HydraClient, etype: str, src: str, dst: str
) -> list[list[int]]:
    """One unpinned edge sweep. The expensive half of this view."""
    rows = client.query(
        f"MATCH (a:{src})-[e:{etype}]->(b:{dst}) "
        "RETURN a.id AS source, b.id AS target"
    )
    return [
        [r["source"], r["target"]]
        for r in rows
        if r.get("source") is not None and r.get("target") is not None
    ]


def build_full_graph(
    client: HydraClient, spec: GraphSpec | None = None
) -> dict[str, Any]:
    """Sweep the whole graph into one payload the browser can lay out."""
    spec = spec or GraphSpec()
    started = time.perf_counter()

    labels = list(spec.labels)
    if spec.include_lockfile_entries and schema.LOCKFILE_ENTRY not in labels:
        labels.append(schema.LOCKFILE_ENTRY)

    nodes: list[dict] = []
    per_label: dict[str, int] = {}
    for label in labels:
        try:
            found = _sweep_nodes(client, label)
        except Exception:  # noqa: BLE001 - a label with no nodes is not an error
            found = []
        per_label[label] = len(found)
        nodes.extend(found)

    dropped = 0
    if len(nodes) > spec.max_nodes:
        dropped = len(nodes) - spec.max_nodes
        nodes = nodes[: spec.max_nodes]

    known = {n["id"] for n in nodes}

    sweeps = list(EDGE_SWEEPS)
    if spec.include_satisfied_by:
        sweeps.append(OPTIONAL_SWEEPS["satisfied_by"][0])
    if spec.include_lockfile_entries:
        sweeps.append(OPTIONAL_SWEEPS["lockfile_entries"][0])

    edges: list[dict] = []
    per_edge: dict[str, int] = {}
    for etype, src, dst in sweeps:
        try:
            pairs = _sweep_edges(client, etype, src, dst)
        except Exception:  # noqa: BLE001
            pairs = []
        # An edge to a node that was not drawn would be a line to nowhere.
        kept = [p for p in pairs if p[0] in known and p[1] in known]
        per_edge[etype] = per_edge.get(etype, 0) + len(kept)
        edges.extend({"source": a, "target": b, "type": etype} for a, b in kept)

    omitted: list[dict] = []
    if not spec.include_satisfied_by:
        omitted.append({
            "what": schema.SATISFIED_BY,
            "why": OPTIONAL_SWEEPS["satisfied_by"][1],
        })
    if not spec.include_lockfile_entries:
        omitted.append({
            "what": schema.LOCKFILE_ENTRY,
            "why": OPTIONAL_SWEEPS["lockfile_entries"][1],
        })
    if dropped:
        omitted.append({
            "what": "nodes past max_nodes",
            "why": f"{dropped:,} node(s) beyond the {spec.max_nodes:,} ceiling",
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "by_label": per_label,
            "by_edge": per_edge,
            "build_ms": round((time.perf_counter() - started) * 1000, 1),
        },
        "omitted": omitted,
    }
