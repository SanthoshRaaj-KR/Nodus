"""Command line for the package blast-radius graph.

    python -m blastradius.pkg.cli corpus  --count 24
    python -m blastradius.pkg.cli ingest  --osv ../osv_scan_results.csv
    python -m blastradius.pkg.cli simulate lodash@4.17.21
    python -m blastradius.pkg.cli compare lodash@4.17.21
    python -m blastradius.pkg.cli bench
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import schema
from ..hydra_client import HydraClient, HydraError
from ..ids import IdAllocator
from .bench import run_benchmarks
from .blast import BlastRadiusEngine, Confidence
from .corpus import generate_corpus
from .incident import create_incident
from .ingest import IngestConfig, ingest
from .registry import RegistryClient

DEFAULT_CORPUS = Path(__file__).resolve().parents[2] / "corpus" / "fleet"
DEFAULT_IDS = Path(__file__).resolve().parents[2] / "data" / "ids.sqlite"

RULE = "=" * 72


def _split_spec(spec: str) -> tuple[str, str]:
    """``lodash@4.17.21`` -> ("lodash", "4.17.21"); scoped names keep their @."""
    if "@" not in spec.lstrip("@"):
        raise SystemExit(f"expected name@version, got {spec!r}")
    at = spec.rindex("@")
    if at == 0:
        raise SystemExit(f"expected name@version, got {spec!r}")
    return spec[:at], spec[at + 1 :]


def _client(args) -> HydraClient:
    return HydraClient(base_url=args.hydra, timeout_ms=args.timeout_ms)


def _require_node(client: HydraClient) -> None:
    if not client.ready():
        raise SystemExit(
            "HydraDB is not reachable.\n"
            "  Start Docker Desktop, then:  python -m blastradius.cli up\n"
            "  (the node listens on http://127.0.0.1:8443)"
        )


# --------------------------------------------------------------------------


def cmd_corpus(args) -> int:
    projects = generate_corpus(
        args.corpus, count=args.count, clean=args.clean, verbose=True
    )
    total = sum(p.entry_count for p in projects)
    print(f"\n{len(projects)} projects, {total:,} lockfile entries")
    print(f"corpus at {args.corpus}")
    return 0


def cmd_ingest(args) -> int:
    client = _client(args)
    _require_node(client)
    ids = IdAllocator(args.ids)
    config = IngestConfig(
        versions_per_package=args.versions_per_package,
        max_satisfied_by=args.max_satisfied_by,
        fetch_full_metadata=not args.abbreviated,
        detect_typosquats=not args.no_typosquat,
    )
    report = ingest(
        client, ids, corpus=args.corpus, osv_csv=args.osv,
        registry=RegistryClient(offline=args.offline), config=config,
    )
    print("\n" + RULE)
    print(report.render())
    if report.write:
        print("\n" + report.write.render())
    ids.close()
    return 0


def cmd_simulate(args) -> int:
    name, version = _split_spec(args.spec)
    client = _client(args)
    _require_node(client)
    ids = IdAllocator(args.ids)

    print(RULE)
    print("SYNTHETIC INCIDENT")
    print(RULE)
    try:
        incident = create_incident(
            client, ids, name, version,
            incident_id=args.incident_id, window_hours=args.window_hours,
        )
    except LookupError as exc:
        raise SystemExit(str(exc))

    engine = BlastRadiusEngine(client, ids, max_depth=args.max_depth)
    result = engine.analyse(name, version, include_paths=args.paths)

    if not result.exists:
        raise SystemExit(f"{args.spec} is not in the graph")

    print()
    print(RULE)
    print(f"BLAST RADIUS: {result.target}")
    print(RULE)

    meta = result.metadata
    print(f"\npublished    {meta.get('published_at')}")
    print(f"license      {meta.get('license') or '(unknown)'}")
    print(f"install hook {'YES' if meta.get('has_install_script') else 'no'}")

    _section("DIRECT DEPENDENT PACKAGE VERSIONS", [
        f"{r['name']}@{r['version']}  (range {r['range']}, {r['dep_type']})"
        for r in result.direct_dependents
    ])
    _section("TRANSITIVE DEPENDENT PACKAGE VERSIONS", [
        f"{r['name']}@{r['version']}" for r in result.transitive_dependents
    ], limit=20)
    _section("LOCKFILES RESOLVING THIS EXACT VERSION", [
        f"{r['package_name']}@{r['resolved_version']}  depth={r['depth']}"
        f"{'  (dev)' if r['dev'] else ''}"
        for r in result.lockfile_entries
    ])
    _section("EXPOSED PROJECTS", [
        f"{r['service']:28} depth={r['depth']}  via {r['via_direct']}"
        f"{'  (dev only)' if r['dev_only'] else ''}"
        for r in result.exposed_projects
    ])
    _section("RESOLVED WHILE THE VERSION WAS LIVE", [
        f"{r['service']:28} depth={r['depth']}"
        for r in result.live_window_projects
    ])
    _section("SHARED-MAINTAINER PACKAGES", [
        f"{r['package']:34} via {r['maintainer']}"
        for r in result.shared_maintainer
    ], limit=15)
    _section("SHARED-REPOSITORY PACKAGES", [
        f"{r['package']:34} {r['repository']}"
        for r in result.shared_repository
    ], limit=15)
    _section("SHARED-PUBLISHER PACKAGES", [
        f"{r['package']}@{r['version']:20} via {r['publisher']}"
        for r in result.shared_publisher
    ], limit=15)
    _section("TYPOSQUAT NEIGHBOURS", [
        f"{r['name']:34} {r['technique']} d={r['distance']}"
        for r in result.typosquats
    ])

    print(f"\n{RULE}")
    print("FINDINGS")
    print(RULE)
    by_confidence = {}
    for finding in result.findings:
        by_confidence.setdefault(finding.confidence, []).append(finding)
    for level in (Confidence.CERTAIN, Confidence.HIGH, Confidence.MEDIUM,
                  Confidence.LOW, Confidence.INVESTIGATE):
        items = by_confidence.get(level, [])
        if items:
            print(f"\n{level}: {len(items)}")
            for finding in items[:6]:
                print(f"  - {finding.entity_type} {finding.entity}: {finding.status}")

    if args.why:
        target = args.why.lower()
        for finding in result.findings:
            if finding.entity.lower() == target:
                print()
                print(finding.explain())
                break
        else:
            print(f"\nno finding for {args.why!r}")

    print(f"\n{RULE}")
    print("PERFORMANCE")
    print(RULE)
    print(result.timing_table())
    ids.close()
    return 0


def cmd_compare(args) -> int:
    """Show what a range-only tool would report against the lockfile truth.

    This is the accuracy claim, measured rather than asserted: a range that
    admits a version is not a project that resolved it.
    """
    name, version = _split_spec(args.spec)
    client = _client(args)
    _require_node(client)
    ids = IdAllocator(args.ids)
    engine = BlastRadiusEngine(client, ids, max_depth=args.max_depth)
    result = engine.analyse(name, version)
    if not result.exists:
        raise SystemExit(f"{args.spec} is not in the graph")

    confirmed = {p["service"] for p in result.exposed_projects}
    candidates = {d["key"] for d in result.direct_dependents}

    print(RULE)
    print(f"RANGE-ONLY vs LOCKFILE TRUTH for {result.target}")
    print(RULE)
    print(f"\npackage versions whose declared range ADMITS this version: "
          f"{len(candidates)}")
    for key in sorted(candidates)[:15]:
        print(f"    {key}")
    print(f"\nprojects whose lockfile actually RESOLVED it: {len(confirmed)}")
    for service in sorted(confirmed):
        print(f"    {service}")
    print()
    if candidates and not confirmed:
        print("A range-only tool would flag every dependent above.")
        print("None of them resolved this version. All would be false positives.")
    elif candidates:
        print(f"A range-only tool reports {len(candidates)} candidate(s); "
              f"{len(confirmed)} project(s) actually resolved the version.")
    ids.close()
    return 0


def cmd_bench(args) -> int:
    name, version = _split_spec(args.spec)
    client = _client(args)
    _require_node(client)
    ids = IdAllocator(args.ids)
    try:
        bench = run_benchmarks(
            client, ids, name, version,
            repeats=args.repeats, max_depth=args.max_depth,
        )
    except LookupError as exc:
        raise SystemExit(str(exc))

    print(RULE)
    print(f"BENCHMARKS: {name}@{version}  ({args.repeats} runs each)")
    print(RULE)
    print()
    print(f"graph: {bench.graph_nodes:,} nodes sampled across core labels")
    print()
    print(bench.table())
    for note in bench.notes:
        print()
        print(note)
    ids.close()
    return 0


def _section(title: str, rows: list[str], limit: int = 40) -> None:
    print(f"\n{title}")
    if not rows:
        print("    (none)")
        return
    for row in rows[:limit]:
        print(f"    {row}")
    if len(rows) > limit:
        print(f"    ... and {len(rows) - limit} more")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="blastradius.pkg.cli")
    parser.add_argument("--hydra", default="http://127.0.0.1:8443")
    parser.add_argument("--ids", default=str(DEFAULT_IDS))
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--timeout-ms", type=int, default=25_000)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("corpus", help="generate projects with real lockfiles")
    p.add_argument("--count", type=int, default=24)
    p.add_argument("--clean", action="store_true")
    p.set_defaults(func=cmd_corpus)

    p = sub.add_parser("ingest", help="load the corpus into HydraDB")
    p.add_argument("--osv", default=None, help="OSV scan CSV")
    p.add_argument("--versions-per-package", type=int, default=3)
    p.add_argument("--max-satisfied-by", type=int, default=8)
    p.add_argument("--abbreviated", action="store_true",
                   help="skip maintainer/repository metadata (much faster)")
    p.add_argument("--no-typosquat", action="store_true")
    p.add_argument("--offline", action="store_true",
                   help="use only the registry cache")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("simulate", help="create a synthetic incident and report")
    p.add_argument("spec", help="name@version, e.g. lodash@4.17.21")
    p.add_argument("--incident-id", default="SYNTHETIC-001")
    p.add_argument("--window-hours", type=int, default=6)
    p.add_argument("--max-depth", type=int, default=5)
    p.add_argument("--paths", action="store_true", help="reconstruct whole paths")
    p.add_argument("--why", default=None, help="explain one entity in full")
    p.set_defaults(func=cmd_simulate)

    p = sub.add_parser("compare", help="range-only candidates vs lockfile truth")
    p.add_argument("spec")
    p.add_argument("--max-depth", type=int, default=5)
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("bench", help="measure query latency and the experiments")
    p.add_argument("spec")
    p.add_argument("--repeats", type=int, default=7)
    p.add_argument("--max-depth", type=int, default=5)
    p.set_defaults(func=cmd_bench)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except HydraError as exc:
        print(f"HydraDB error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
