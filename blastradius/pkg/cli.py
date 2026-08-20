"""Command line for the package blast-radius graph.

    python -m blastradius.pkg.cli corpus  --count 24
    python -m blastradius.pkg.cli ingest  --osv ../osv_scan_results.csv
    python -m blastradius.pkg.cli ingest  --osv-scan ../my-app   # scan, then ingest
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
from .blast import BlastRadius, BlastRadiusEngine, Confidence
from .corpus import generate_corpus
from .incident import clear_incident, create_incident, incident_id_for
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

    osv_csv = args.osv
    if args.osv_scan:
        # Scan first, then ingest what it found. Handing this command a repo
        # instead of a CSV is the difference between "the advisories somebody
        # wrote down" and "the advisories this code actually has".
        from .osvscan import scan_repository

        run = scan_repository(args.osv_scan, verbose=True)
        print("\n" + RULE)
        print(run.render())
        print(RULE)
        osv_csv = run.csv_path if run.findings else None
        run.write_log(Path(run.csv_path).parent / "scan-log.md")

    ids = IdAllocator(args.ids)
    config = IngestConfig(
        versions_per_package=args.versions_per_package,
        max_satisfied_by=args.max_satisfied_by,
        fetch_full_metadata=not args.abbreviated,
        detect_typosquats=not args.no_typosquat,
    )
    report = ingest(
        client, ids, corpus=args.corpus, osv_csv=osv_csv,
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
            incident_id=args.incident_id or incident_id_for(name, version),
            window_hours=args.window_hours,
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


def cmd_retract(args) -> int:
    """Take a simulated incident back off a version."""
    name, version = _split_spec(args.spec)
    client = _client(args)
    _require_node(client)
    ids = IdAllocator(args.ids)
    removed = clear_incident(
        client, ids, name, version, incident_id=args.incident_id
    )
    print(
        f"incident on {name}@{version}: "
        + ("retracted" if removed else "nothing was marked")
    )
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


def cmd_anomalies(args) -> int:
    """Publish-time signals over the packages this graph knows about.

    Reads the registry cache rather than the graph: the signals are about
    *metadata history* -- when versions appeared, who pushed them, what
    changed between them -- and the graph stores the current state of each
    version rather than the sequence. `--offline` keeps it reproducible.
    """
    from .anomaly import Signal, analyse_correlated_burst, analyse_package

    names = list(args.packages or [])
    if not names:
        # Package names come from the local id map, never a label scan: the
        # scan is rejected outright past 250k nodes by admission control, and
        # this is the L0 layer that exists to avoid it.
        ids_probe = IdAllocator(args.ids)
        try:
            from .identity import parse_purl

            for key, _ in ids_probe.keys_with_prefix(schema.PACKAGE, "pkg:npm/"):
                parsed = parse_purl(key)
                if parsed is not None and not parsed.version:
                    names.append(parsed.name)
        finally:
            ids_probe.close()

    if not names:
        print(
            "\nNo packages to analyse. Ingest first, or name them:\n"
            "    python -m blastradius.pkg.cli anomalies --packages lodash debug\n"
        )
        return 1

    names = names[: args.limit_packages]
    registry = RegistryClient(offline=args.offline)
    failures: list[str] = []
    fetched = registry.packuments(
        names, full=True,
        on_error=lambda n, exc: failures.append(f"{n}: {type(exc).__name__}"),
    )

    print(RULE)
    print(f"PUBLISH ANOMALIES over {len(fetched)} package(s)")
    print(RULE)
    if failures:
        # Never silent: a package we could not read is not a package with
        # nothing to report, and the difference matters here more than usual.
        print(
            f"\n  {len(failures)} package(s) could not be read"
            f"{' (offline: not in cache)' if args.offline else ''} "
            f"and were not assessed."
        )
        for line in failures[:5]:
            print(f"      {line}")

    per_signal: dict[str, list] = {}
    for packument in fetched.values():
        for signal in analyse_package(packument):
            per_signal.setdefault(signal.signal, []).append(signal)

    print(f"\n  {'signal':<28} {'count':>7}")
    print(f"  {'-'*28} {'-'*7}")
    for name in sorted(Signal.ALL):
        found = per_signal.get(name, [])
        if found or args.verbose:
            print(f"  {name:<28} {len(found):>7}")

    for name in sorted(per_signal):
        found = per_signal[name]
        print(f"\n  {name}  ({len(found)})")
        for signal in found[: args.limit]:
            print(f"      {signal.explain()}")
        if len(found) > args.limit:
            print(f"      ... and {len(found) - args.limit} more")

    bursts = analyse_correlated_burst(list(fetched.values()))
    print("\n\n  CORRELATED BURSTS -- one account, many packages, one window")
    print("  This is the shape the TanStack worm had.")
    if not bursts:
        print("\n      none found")
    for burst in bursts[: args.limit]:
        print(f"\n      {burst.explain()}")
        for pkg, versions in sorted(burst.packages.items())[:6]:
            print(f"          {pkg}: {', '.join(versions[:4])}")

    print(
        "\n\n  Every signal above is INVESTIGATE. None of them asserts that a\n"
        "  package is malicious.\n"
    )
    return 0


def cmd_frontier(args) -> int:
    """What the credentials behind a compromise could publish to next.

    The complement of `simulate`: that one answers "who already has it", this
    one answers "where does it go from here". Read-only -- it marks nothing and
    needs no incident, because publish rights exist whether or not anyone has
    abused them yet.
    """
    from .frontier import FrontierEngine

    name, version = _split_spec(args.spec)
    client = _client(args)
    _require_node(client)
    ids = IdAllocator(args.ids)
    try:
        engine = FrontierEngine(client, ids)
        result = BlastRadius(target=f"{name}@{version}")
        frontier = engine.analyse(
            name, version, result=result,
            measure_impact=not args.no_impact,
        )

        print(RULE)
        print(frontier.render(limit=args.limit))
        print()
        if args.timings and result.timings:
            print(f"\n  {'query':<38} {'ms':>8} {'rows':>7}")
            print(f"  {'-'*38} {'-'*8} {'-'*7}")
            for t in result.timings:
                print(f"  {t.label:<38} {t.ms:>8.2f} {t.rows:>7}")
            total = sum(t.ms for t in result.timings)
            print(f"  {'total':<38} {total:>8.2f}")
            print()
    finally:
        ids.close()
    return 0


def cmd_scale(args) -> int:
    """Both sweeps, and the conclusion each one supports.

    Destructive by nature: every point needs a graph of a known size, and the
    only way to get one here is to drop the store between points. That is
    stated up front rather than discovered afterwards, because the corpus
    ingest does not survive it.
    """
    from .scale import (
        ScaleSpec, render_sweep, render_verdict, sweep_answer_size,
        sweep_graph_size,
    )

    if not args.yes:
        print(
            "\nThis DESTROYS the current graph and id map -- it resets the store\n"
            "once per measured point. Rebuild afterwards with:\n"
            "    python -m blastradius.cli pipeline --reset\n"
            "\nRe-run with --yes to proceed.\n"
        )
        return 1

    sizes = sorted(args.sizes or [200, 2_000, 20_000])
    fanouts = args.fanouts or [1, 10, 100, 1_000]

    # Services scale with the graph, so "graph size" grows in every dimension
    # -- versions, services and the RESOLVED_IN closure alike. Holding services
    # flat would grow the node count while leaving the adjacency Q5 walks
    # almost unchanged, which is a much weaker claim than the one being made.
    largest = sizes[-1]

    def services_for(size: int) -> int:
        return max(args.probe_fanout, round(args.services * size / largest))

    specs = [
        ScaleSpec(
            packages=max(1, size // args.versions_per_package),
            versions_per_package=args.versions_per_package,
            services=services_for(size),
            deps_per_service=args.deps_per_service,
            probe_fanout=args.probe_fanout,
            probes=args.probes,
        )
        for size in sizes
    ]

    # Sweep B measures answer sizes up to max(fanouts), which is impossible if
    # the graph holds fewer services than that. Widen the base rather than
    # letting the sweep silently clamp every large point to the same number.
    base = specs[-1]
    if base.services < max(fanouts):
        base = ScaleSpec(
            packages=base.packages,
            versions_per_package=base.versions_per_package,
            services=max(fanouts),
            deps_per_service=base.deps_per_service,
            probe_fanout=base.probe_fanout,
            probes=base.probes,
            seed=base.seed,
        )

    print(RULE)
    print("SCALE: does Q5 cost track the answer, or the graph?")
    print(RULE)
    print(
        "\nSynthetic graphs, written through the real writer and measured\n"
        "through the real engine. Every point asserts Q5 returned exactly the\n"
        "services attached to its probe, so a fast wrong answer cannot pass."
    )

    print("\n\nSWEEP A -- graph grows, answer held constant")
    print("  If the closure claim holds, this line is flat.")
    a = sweep_graph_size(args.hydra, specs, repeats=args.repeats)
    print()
    print(render_sweep(a, "graph"))

    print("\n\nSWEEP B -- graph held constant, answer grows")
    print("  The control. This line must rise, or Sweep A proves nothing.")
    b = sweep_answer_size(args.hydra, base, fanouts, repeats=args.repeats)
    print()
    print(render_sweep(b, "answer"))

    print("\n\nVERDICT")
    print(RULE)
    print(render_verdict(a, b))

    print(
        "\n\nThe graph is empty now. Rebuild with:\n"
        "    python -m blastradius.cli pipeline --reset\n"
    )
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
    p.add_argument("--osv-scan", default=None, metavar="REPO",
                   help="scan REPO for vulnerabilities first, then ingest what it found")
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
    p.add_argument("--incident-id", default=None,
                   help="default: one id per target, so simulating a second "
                        "version does not leave the first still marked")
    p.add_argument("--window-hours", type=int, default=6)
    p.add_argument("--max-depth", type=int, default=5)
    p.add_argument("--paths", action="store_true", help="reconstruct whole paths")
    p.add_argument("--why", default=None, help="explain one entity in full")
    p.set_defaults(func=cmd_simulate)

    p = sub.add_parser("retract", help="remove a simulated incident")
    p.add_argument("spec")
    p.add_argument("--incident-id", default=None)
    p.set_defaults(func=cmd_retract)

    p = sub.add_parser("compare", help="range-only candidates vs lockfile truth")
    p.add_argument("spec")
    p.add_argument("--max-depth", type=int, default=5)
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("bench", help="measure query latency and the experiments")
    p.add_argument("spec")
    p.add_argument("--repeats", type=int, default=7)
    p.add_argument("--max-depth", type=int, default=5)
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser(
        "anomalies", help="publish-time signals: bursts, install scripts, publishers"
    )
    p.add_argument("--packages", nargs="+", default=None,
                   help="names to assess (default: everything in the id map)")
    p.add_argument("--offline", action="store_true",
                   help="registry cache only, no network")
    p.add_argument("--limit", type=int, default=10,
                   help="rows printed per signal (counts are always true)")
    p.add_argument("--limit-packages", type=int, default=400)
    p.add_argument("--verbose", action="store_true",
                   help="list signals that fired zero times too")
    p.set_defaults(func=cmd_anomalies)

    p = sub.add_parser(
        "frontier",
        help="what the credentials behind this compromise could publish to next",
    )
    p.add_argument("spec", help="name@version, e.g. lodash@4.17.21")
    p.add_argument("--limit", type=int, default=20,
                   help="frontier rows to print (the count is always the true one)")
    p.add_argument("--no-impact", action="store_true",
                   help="skip the fleet-impact query per row")
    p.add_argument("--timings", action="store_true", help="per-query latency")
    p.set_defaults(func=cmd_frontier)

    p = sub.add_parser(
        "scale", help="does Q5 cost track the answer or the graph? (DESTRUCTIVE)"
    )
    p.add_argument("--yes", action="store_true",
                   help="required: this drops the store once per measured point")
    p.add_argument("--sizes", type=int, nargs="+", default=None,
                   metavar="N", help="version counts to sweep (default 200 2000 20000)")
    p.add_argument("--fanouts", type=int, nargs="+", default=None,
                   metavar="N", help="answer sizes for sweep B (default 1 10 100 1000)")
    p.add_argument("--versions-per-package", type=int, default=4)
    p.add_argument("--services", type=int, default=200)
    p.add_argument("--deps-per-service", type=int, default=300)
    p.add_argument("--probe-fanout", type=int, default=5)
    p.add_argument("--probes", type=int, default=3)
    p.add_argument("--repeats", type=int, default=9)
    p.set_defaults(func=cmd_scale)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except HydraError as exc:
        print(f"HydraDB error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
