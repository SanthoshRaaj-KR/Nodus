"""Orchestrate the ingest: lockfiles + AST scan -> HydraDB.

Write forms come straight from the proven shapes in the HydraDB README:
nodes are ``UNWIND`` + ``MERGE`` by id + ``SET``, edges are ``UNWIND`` +
``MATCH`` both endpoints + ``MERGE`` with an explicit relationship id. Nothing
else parses.

Every edge is written twice, forwards and inverted, because HydraDB can only
pin the *source* of a variable-length traversal. The inverse is not an
optimisation here -- without it the reachability queries cannot be expressed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .. import schema
from ..hydra_client import HydraClient
from ..ids import IdAllocator
from .bridge import link_imports
from .lockfile import ParsedLock, find_lockfiles, parse_package_lock

SCANNER = Path(__file__).resolve().parent.parent.parent / "scanner" / "scan.mjs"

#: Property lists per label. Order is irrelevant but completeness is not:
#: `WHERE` has no IS NULL, so a property that is sometimes absent can never be
#: tested for. Every row writes every property, using schema sentinels.
NODE_PROPS = {
    schema.SERVICE: ("name", "repo", "path"),
    schema.PACKAGE_VERSION: (
        "key", "name", "version", "dev", "integrity", "published_at", "withdrawn_at",
    ),
    schema.FILE: ("path", "service", "lang"),
    schema.FUNCTION: ("name", "file", "line", "exported", "service"),
    schema.EXTERNAL_IMPORT: ("specifier", "service", "names", "file"),
    schema.ROUTE: ("method", "pattern", "file", "line", "service"),
    schema.ARTIFACT: ("path", "kind", "sha256", "service", "first_seen"),
}


@dataclass
class IngestReport:
    nodes: dict[str, int] = field(default_factory=dict)
    edges: dict[str, int] = field(default_factory=dict)
    services: list[str] = field(default_factory=list)
    unmatched_imports: list[str] = field(default_factory=list)
    unresolved_deps: list[str] = field(default_factory=list)
    scanner_stats: dict[str, dict] = field(default_factory=dict)

    def render(self) -> str:
        lines = [f"services: {', '.join(self.services) or '(none)'}", "", "nodes:"]
        for label, n in sorted(self.nodes.items()):
            lines.append(f"  {label:22} {n:>8,}")
        lines.append("")
        lines.append("edges:")
        for etype, n in sorted(self.edges.items()):
            inverse = " (inverse)" if etype in schema.INVERSE_OF.values() else ""
            lines.append(f"  {etype:22} {n:>8,}{inverse}")
        total_nodes = sum(self.nodes.values())
        total_edges = sum(self.edges.values())
        lines.append("")
        lines.append(f"  total {total_nodes:,} nodes, {total_edges:,} edges")
        if self.unmatched_imports:
            sample = ", ".join(sorted(set(self.unmatched_imports))[:8])
            lines.append(
                f"\nimports matching no lockfile entry "
                f"({len(set(self.unmatched_imports))}): {sample}"
                "\n  (node builtins and unlisted packages both land here)"
            )
        if self.unresolved_deps:
            sample = ", ".join(sorted(set(self.unresolved_deps))[:8])
            lines.append(f"\ndeclared deps with no lockfile entry: {sample}")
        return "\n".join(lines)


class Loader:
    """Accumulates rows in memory, then writes them in batched UNWINDs."""

    def __init__(self, client: HydraClient, ids: IdAllocator, verbose: bool = True):
        self.client = client
        self.ids = ids
        self.verbose = verbose
        self._nodes: dict[str, dict[int, dict]] = {}
        # Keyed by (edge type, source label, destination label): the server
        # requires UNWIND MATCH endpoints to carry exactly one label each, so a
        # single edge type that spans several label pairs -- REQUIRED_BY covers
        # both PackageVersion->PackageVersion and PackageVersion->Service --
        # has to be written as one batch per pair.
        self._edges: dict[tuple[str, str, str], dict[int, dict]] = {}
        self._label_of: dict[int, str] = {}
        self.report = IngestReport()

    # -- staging ----------------------------------------------------------

    def node(self, label: str, natural_key: str, **props) -> int:
        """Stage one node; returns its id. Re-staging the same key is a no-op.

        ``natural_key`` is the stable identity string, not a graph property --
        note that PackageVersion also has a property literally called ``key``,
        which is why this parameter is not.
        """
        node_id = self.ids.get(label, natural_key)
        row = {"id": node_id}
        for prop in NODE_PROPS[label]:
            row[prop] = props.get(prop, schema.UNKNOWN_STR)
        self._nodes.setdefault(label, {})[node_id] = row
        self._label_of[node_id] = label
        return node_id

    def edge(self, etype: str, src: int, dst: int, **props) -> None:
        """Stage an edge and, when one is defined, its materialised inverse."""
        self._stage_edge(etype, src, dst, props)
        inverse = schema.INVERSE_OF.get(etype)
        if inverse:
            self._stage_edge(inverse, dst, src, props)

    def _stage_edge(self, etype: str, src: int, dst: int, props: dict) -> None:
        try:
            src_label = self._label_of[src]
            dst_label = self._label_of[dst]
        except KeyError as exc:
            raise KeyError(
                f"cannot write a {etype} edge touching node {exc.args[0]}: it was "
                f"never staged, so its label is unknown and the MATCH cannot be "
                f"written. Stage both endpoints before the edge."
            ) from None
        rel_id = self.ids.get(etype, f"{src}->{dst}")
        row = {"rel": rel_id, "src": src, "dst": dst}
        row.update(props)
        self._edges.setdefault((etype, src_label, dst_label), {})[rel_id] = row

    # -- writing ----------------------------------------------------------

    def flush(self) -> IngestReport:
        """Write everything staged. Nodes first -- edges MATCH both endpoints."""
        for label, rows in self._nodes.items():
            props = NODE_PROPS[label]
            sets = ", ".join(f"n.{p} = row.{p}" for p in props)
            statement = (
                f"UNWIND $rows AS row MERGE (n {{id: row.id}}) SET n:{label}, {sets}"
            )
            sent = self.client.batch(
                statement, list(rows.values()), progress=self.verbose, label=label
            )
            self.report.nodes[label] = sent

        for (etype, src_label, dst_label), rows in self._edges.items():
            values = list(rows.values())
            extra = [k for k in values[0] if k not in ("rel", "src", "dst")]
            statement = (
                "UNWIND $rows AS row "
                f"MATCH (s:{src_label} {{id: row.src}}), (d:{dst_label} {{id: row.dst}}) "
                f"MERGE (s)-[r:{etype} {{id: row.rel}}]->(d)"
            )
            if extra:
                statement += " SET " + ", ".join(f"r.{p} = row.{p}" for p in extra)
            sent = self.client.batch(
                statement,
                values,
                progress=self.verbose,
                label=f"{etype} ({src_label}->{dst_label})",
            )
            self.report.edges[etype] = self.report.edges.get(etype, 0) + sent

        self.ids.commit()
        return self.report

    def _log(self, message: str) -> None:
        if self.verbose:
            print(message, flush=True)

    # -- the two graphs ---------------------------------------------------

    def load_macro(self, lock: ParsedLock) -> dict[str, int]:
        """Lockfile -> Service, PackageVersion, DEPENDS_ON (+ REQUIRED_BY)."""
        service_ids: dict[str, int] = {}
        for ws_path, name in lock.services.items():
            service_ids[name] = self.node(
                schema.SERVICE,
                name,
                name=name,
                repo=lock.repo,
                path=ws_path or ".",
            )

        pv_ids: dict[str, int] = {}
        for key, pv in lock.packages.items():
            pv_ids[key] = self.node(
                schema.PACKAGE_VERSION,
                key,
                key=key,
                name=pv.name,
                version=pv.version,
                dev=pv.dev,
                integrity=pv.integrity,
                published_at=schema.UNKNOWN_TS,
                withdrawn_at=schema.STILL_LIVE,
            )

        for service, pv_key, dev in lock.direct:
            if service in service_ids and pv_key in pv_ids:
                self.edge(
                    schema.DEPENDS_ON,
                    service_ids[service],
                    pv_ids[pv_key],
                    direct=True,
                    dev=dev,
                )

        for parent, child in lock.edges:
            if parent in pv_ids and child in pv_ids:
                self.edge(
                    schema.DEPENDS_ON,
                    pv_ids[parent],
                    pv_ids[child],
                    direct=False,
                    dev=False,
                )

        self._write_closure(lock, service_ids, pv_ids)
        self.report.unresolved_deps.extend(lock.unresolved)
        return pv_ids

    def _write_closure(
        self,
        lock: ParsedLock,
        service_ids: dict[str, int],
        pv_ids: dict[str, int],
    ) -> None:
        """Flatten DEPENDS_ON into PRESENT_IN, one hop from package to service.

        A variable-length traversal has to declare a maximum depth, and real
        npm trees go deeper than any bound worth hardcoding -- so answering
        "is this package in that service" with a bounded walk would silently
        miss the deep cases. Doing the closure here instead makes the query
        exact at any depth and turns it into a single hop.

        Breadth-first so the recorded depth is the shortest chain, which is
        the one worth showing a human first.
        """
        adjacency: dict[str, list[str]] = {}
        for parent, child in lock.edges:
            adjacency.setdefault(parent, []).append(child)

        direct_by_service: dict[str, list[tuple[str, bool]]] = {}
        for service, pv_key, dev in lock.direct:
            direct_by_service.setdefault(service, []).append((pv_key, dev))

        for service, roots in direct_by_service.items():
            service_id = service_ids.get(service)
            if service_id is None:
                continue

            # depth 1 = a direct dependency; dev-ness is inherited from the
            # direct edge that first reached the package.
            seen: dict[str, tuple[int, bool]] = {}
            frontier: list[tuple[str, int, bool]] = []
            for pv_key, dev in roots:
                if pv_key not in seen:
                    seen[pv_key] = (1, dev)
                    frontier.append((pv_key, 1, dev))

            while frontier:
                nxt: list[tuple[str, int, bool]] = []
                for key, depth, dev in frontier:
                    for child in adjacency.get(key, ()):
                        if child in seen:
                            continue
                        seen[child] = (depth + 1, dev)
                        nxt.append((child, depth + 1, dev))
                frontier = nxt

            for pv_key, (depth, dev) in seen.items():
                pv_id = pv_ids.get(pv_key)
                if pv_id is not None:
                    self.edge(
                        schema.PRESENT_IN,
                        pv_id,
                        service_id,
                        depth=depth,
                        dev=dev,
                        direct=depth == 1,
                    )

    def load_micro(self, scan: dict, service_id: int) -> dict[str, int]:
        """Scanner output -> File, Function, Route, ExternalImport and edges."""
        service = scan["service"]
        keys: dict[str, int] = {}

        for f in scan["files"]:
            fid = self.node(
                schema.FILE, f["key"], path=f["path"], service=service, lang=f["lang"]
            )
            keys[f["key"]] = fid
            self.edge(schema.DECLARED_IN, fid, service_id)

        for fn in scan["functions"]:
            fid = self.node(
                schema.FUNCTION,
                fn["key"],
                name=fn["name"],
                file=fn["file"],
                line=fn["line"],
                exported=fn["exported"],
                service=service,
            )
            keys[fn["key"]] = fid
            file_id = keys.get(f"{service}::{fn['file']}")
            if file_id:
                self.edge(schema.CONTAINS, file_id, fid)

        for imp in scan["externalImports"]:
            iid = self.node(
                schema.EXTERNAL_IMPORT,
                imp["key"],
                specifier=imp["specifier"],
                service=service,
                names=",".join(imp["names"]),
                file=imp["file"],
            )
            keys[imp["key"]] = iid

        for route in scan["routes"]:
            rid = self.node(
                schema.ROUTE,
                route["key"],
                method=route["method"],
                pattern=route["pattern"],
                file=route["file"],
                line=route["line"],
                service=service,
            )
            keys[route["key"]] = rid
            handler = keys.get(route["handler"])
            if handler:
                self.edge(schema.HANDLED_BY, rid, handler)

        for caller, callee in scan["calls"]:
            if caller in keys and callee in keys:
                self.edge(schema.CALLS, keys[caller], keys[callee])

        for fn_key, imp_key in scan["callsExternal"]:
            if fn_key in keys and imp_key in keys:
                self.edge(schema.CALLS_EXTERNAL, keys[fn_key], keys[imp_key])

        self.report.scanner_stats[service] = scan["stats"]
        return keys

    def load_bridge(self, service: str, scan: dict, lock: ParsedLock,
                    keys: dict[str, int], pv_ids: dict[str, int]) -> int:
        """ExternalImport -> PackageVersion, the join between the two graphs."""
        links, unmatched = link_imports(service, scan["externalImports"], lock)
        self.report.unmatched_imports.extend(unmatched)
        linked = 0
        for link in links:
            src = keys.get(link.import_key)
            dst = pv_ids.get(link.package_key)
            if src is not None and dst is not None:
                self.edge(schema.RESOLVES_TO, src, dst, confidence=link.confidence)
                linked += 1
        return linked


def run_scanner(project_dir: Path, service: str) -> dict:
    """Invoke the ts-morph scanner and parse its JSON."""
    result = subprocess.run(
        ["node", str(SCANNER), str(project_dir), "--service", service],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"scanner failed for {service} (exit {result.returncode}):\n{result.stderr[:2000]}"
        )
    return json.loads(result.stdout)


def discover_services(corpus: Path) -> list[Path]:
    """Every directory under ``corpus`` holding a package-lock.json."""
    return sorted({p.parent for p in find_lockfiles(corpus)})


def ingest_corpus(
    corpus: Path | str,
    client: HydraClient,
    ids: IdAllocator,
    ioc_paths: list[str] | None = None,
    content_markers: list[str] | None = None,
    verbose: bool = True,
) -> IngestReport:
    """Full ingest: macro graph, micro graph, bridge, persistence artifacts."""
    corpus = Path(corpus)
    loader = Loader(client, ids, verbose=verbose)
    projects = discover_services(corpus)
    if not projects:
        raise FileNotFoundError(
            f"no package-lock.json found under {corpus}. "
            f"Add a repo to the corpus, or point --corpus somewhere else."
        )

    for project in projects:
        service = project.name
        loader._log(f"\n{service}")

        lock_path = project / "package-lock.json"
        lock = parse_package_lock(lock_path, repo=service)
        loader._log(f"  lockfile: {lock.summary()}")
        pv_ids = loader.load_macro(lock)

        # The root service is the "" workspace entry; fall back to the folder.
        service_name = lock.services.get("", service)
        service_id = loader.ids.get(schema.SERVICE, service_name)

        scan = run_scanner(project, service_name)
        loader._log(f"  scanner:  {json.dumps(scan['stats'])}")
        keys = loader.load_micro(scan, service_id)

        linked = loader.load_bridge(service_name, scan, lock, keys, pv_ids)
        loader._log(f"  bridge:   {linked} import -> package links")

        from .persistence import scan_service

        artifacts = scan_service(project, ioc_paths, content_markers)
        for artifact in artifacts:
            aid = loader.node(
                schema.ARTIFACT,
                f"{service_name}::{artifact.key}",
                path=artifact.path,
                kind=artifact.kind,
                sha256=artifact.sha256,
                service=service_name,
                first_seen=artifact.first_seen,
            )
            loader.edge(schema.HAS_ARTIFACT, service_id, aid)
        if artifacts:
            loader._log(f"  artifacts: {len(artifacts)} persistence candidate(s)")

        loader.report.services.append(service_name)

    loader._log("\nwriting to HydraDB...")
    return loader.flush()


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Ingest a corpus into HydraDB")
    parser.add_argument("--corpus", default="corpus", help="directory of repos")
    parser.add_argument("--url", default="http://127.0.0.1:8443")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    client = HydraClient(base_url=args.url)
    with IdAllocator() as ids:
        report = ingest_corpus(
            Path(args.corpus), client, ids, verbose=not args.quiet
        )
    print("\n" + report.render())
    return 0


if __name__ == "__main__":
    sys.exit(main())
