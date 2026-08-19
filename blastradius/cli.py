"""Terminal front end: one query, both graphs.

Prints the macro (lockfile) answer and the micro (call graph) answer side by
side, because they answer different questions and the gap between them is the
whole point -- "you have it" versus "a request can reach it".

    python -m blastradius.cli check ua-parser-js@0.7.29
    python -m blastradius.cli check express --range ">=4.18.0 <4.19.0"
    python -m blastradius.cli advisory advisories/GHSA-vuln-pkg-2026.json
    python -m blastradius.cli services
    python -m blastradius.cli stats
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import schema
from .hydra_client import HydraClient, HydraError
from .query import blast
from .query.advisory import Advisory

#: Default home for advisories generated from a live scan. Named here rather
#: than in the parser so `osv-scan` and `pipeline` cannot disagree about it.
DEFAULT_ADVISORY_DIR = Path(__file__).resolve().parent.parent / "advisories" / "generated"

# ANSI, switched off when stdout is redirected so piped output stays clean.
_TTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


BOLD = lambda s: _c("1", s)  # noqa: E731
DIM = lambda s: _c("2", s)  # noqa: E731
RED = lambda s: _c("31;1", s)  # noqa: E731
ORANGE = lambda s: _c("33;1", s)  # noqa: E731
YELLOW = lambda s: _c("33", s)  # noqa: E731
GREEN = lambda s: _c("32", s)  # noqa: E731
BLUE = lambda s: _c("36", s)  # noqa: E731

TIER_COLOUR = {
    blast.TIER_CONFIRMED: RED,
    blast.TIER_REACHABLE: ORANGE,
    blast.TIER_IMPORTED: YELLOW,
    blast.TIER_INSTALLED: GREEN,
}


def rule(title: str = "", width: int = 74) -> str:
    if not title:
        return DIM("-" * width)
    pad = "-" * max(3, width - len(title) - 3)
    return DIM("-- ") + BOLD(title) + DIM(" " + pad[: max(0, width - len(title) - 4)])


def _report(client: HydraClient, advisory: Advisory, show_paths: bool) -> int:
    """Print the full macro + micro report. Returns a shell exit code."""
    result = blast.assess(client, advisory)

    print()
    print(rule(f"{advisory.advisory_id}  {advisory.package}"))
    if advisory.affected_versions:
        wanted = ", ".join(advisory.affected_versions)
    else:
        wanted = advisory.affected_range or "(none specified)"
    print(f"  advisory covers : {wanted}")

    if not result.affected_keys:
        print(f"  held in corpus  : {RED('nothing matching')}")
        print()
        print(GREEN("  No version of this package in the corpus matches. Nothing exposed."))
        print()
        return 0

    print(f"  held in corpus  : {BOLD(', '.join(result.affected_keys))}")
    print()

    # ---------------- MACRO ----------------
    print(rule("MACRO  lockfile dependency graph"))
    if not result.findings:
        print(GREEN("  Affected versions are present but no service depends on them."))
        print()
        return 0

    width = max(len(f.service) for f in result.findings)
    for finding in sorted(result.findings, key=lambda f: (f.rank, f.service)):
        kind = "direct" if finding.min_depth == 1 else f"transitive (depth {finding.min_depth})"
        dev = DIM("  [dev-only]") if finding.dev_only else ""
        print(f"  {BOLD(finding.service.ljust(width))}  {kind}{dev}")
        print(f"  {' ' * width}  {DIM(', '.join(finding.packages))}")
    print()

    if show_paths:
        print(rule("MACRO  dependency chains (algo.MSpaths)"))
        try:
            paths = blast.dependency_paths(
                client,
                result.affected_keys,
                [f.service for f in result.findings],
            )
            if paths:
                for path in paths[:10]:
                    print(f"  {_render_path(path)}")
            else:
                print(DIM("  no chain returned (direct dependencies have no intermediate hops)"))
        except HydraError as exc:
            print(YELLOW(f"  path procedure unavailable: {str(exc).splitlines()[0]}"))
        print()

    # ---------------- MICRO ----------------
    print(rule("MICRO  source call graph"))
    any_micro = False
    for finding in sorted(result.findings, key=lambda f: (f.rank, f.service)):
        if not (finding.functions or finding.routes or finding.artifacts):
            continue
        any_micro = True
        print(f"  {BOLD(finding.service)}")
        for fn in finding.functions:
            print(
                f"    calls {BLUE(fn['specifier'])} from {fn['name']}() "
                + DIM(f"({fn['file']}:{fn['line']})")
            )
        for route in finding.routes:
            print(
                f"    {ORANGE(route['method'].ljust(6))}{BOLD(route['pattern'])} "
                f"-> {route['handler']} " + DIM(f"({route['file']}:{route['line']})")
            )
        for artifact in finding.artifacts:
            if artifact.get("confirmed"):
                tag, colour = "IOC MATCH", RED
            else:
                tag, colour = "candidate", YELLOW
            print(
                f"    {colour(tag)} {artifact['path']} " + DIM(f"[{artifact['kind']}]")
            )
    if not any_micro:
        print(DIM("  No source file imports this package. It is installed but never called."))
    print()

    # ---------------- VERDICT ----------------
    print(rule("VERDICT"))
    for finding in sorted(result.findings, key=lambda f: (f.rank, f.service)):
        colour = TIER_COLOUR.get(finding.tier, DIM)
        bits = []
        if finding.routes:
            bits.append(f"{len(finding.routes)} route(s)")
        if finding.functions:
            bits.append(f"{len(finding.functions)} function(s)")
        if finding.artifacts:
            bits.append(f"{len(finding.artifacts)} artifact(s)")
        detail = DIM("  " + ", ".join(bits)) if bits else ""
        print(f"  {colour(finding.tier.ljust(14))} {finding.service}{detail}")

    print()
    timings = "  ".join(f"{k} {v:.0f}ms" for k, v in result.timings_ms.items())
    print(DIM(f"  answered in {result.total_ms:.0f} ms   ({timings})"))
    print(DIM(f"  call-graph depth bound: {result.max_call_depth}"))
    print()

    worst = min(f.rank for f in result.findings)
    return 1 if worst <= 1 else 0


def _unwrap(value):
    """Path properties arrive as single-key type maps: {'String': 'lodash'}."""
    if isinstance(value, dict) and len(value) == 1:
        return next(iter(value.values()))
    return value


def _render_path(path) -> str:
    """One-line rendering of a returned path: node -> node -> node."""
    if not isinstance(path, dict) or "nodes" not in path:
        return str(path)[:200]
    names = []
    for node in path["nodes"]:
        props = {k: _unwrap(v) for k, v in (node.get("properties") or {}).items()}
        label = (node.get("labels") or ["?"])[0]
        ident = props.get("key") or props.get("name") or node.get("id")
        names.append(f"{ident}" if label != "Service" else BOLD(str(ident)))
    return DIM(" -> ").join(str(n) for n in names)


def cmd_check(args) -> int:
    client = HydraClient(base_url=args.url)
    package, _, version = args.package.rpartition("@")
    if not package:  # no @ in the argument at all
        package, version = args.package, ""

    advisory = Advisory(
        advisory_id=args.id,
        package=package,
        affected_versions=[version] if version and not args.range else [],
        affected_range=args.range or ("" if version else "*"),
        # Deliberately no IOC globs. A bare `check` knows nothing about what
        # the payload looks like, so artifacts stay candidates and the finding
        # cannot reach P0. Confirmation requires an advisory that names IOCs.
        ioc_paths=[],
    )
    return _report(client, advisory, show_paths=not args.no_paths)


def cmd_advisory(args) -> int:
    client = HydraClient(base_url=args.url)
    advisory = Advisory.load(args.file)
    return _report(client, advisory, show_paths=not args.no_paths)


def cmd_services(args) -> int:
    client = HydraClient(base_url=args.url)
    rows = client.query(
        "MATCH (s:Service) RETURN s.name AS name, s.repo AS repo, s.path AS path "
        "ORDER BY name"
    ).rows
    if not rows:
        print("No services in the graph. Run: python -m blastradius.ingest.load")
        return 1
    print()
    for row in rows:
        packages = client.query(
            "MATCH (s:Service {id: $id})-[:HAS_PACKAGE]->(p:PackageVersion) "
            "RETURN count(*) AS n",
            {"id": _service_id(client, row["name"])},
        ).scalar("n")
        print(f"  {BOLD(row['name']):30} {DIM(row['repo'])}  {packages} packages")
    print()
    return 0


def _service_id(client: HydraClient, name: str) -> int:
    return client.query(
        "MATCH (s:Service) WHERE s.name = $name RETURN s.id AS id", {"name": name}
    ).scalar("id")


#: Both tiers materialise their own inverses, and stats prints one list, so
#: the tag has to know both maps or it silently promotes fifteen derived edge
#: types to looking like primary ones.
_INVERSES = frozenset(schema.INVERSE_OF.values()) | frozenset(schema.PKG_INVERSE_OF.values())


def cmd_stats(args) -> int:
    client = HydraClient(base_url=args.url)
    print()
    print(rule("graph contents"))
    counts = client.counts_by_label(schema.ALL_NODE_LABELS)
    for label, n in counts.items():
        print(f"  {label:22} {n:>8,}")
    print()
    print(rule("edges"))
    for etype in schema.ALL_EDGE_TYPES:
        n = client.query(f"MATCH ()-[r:{etype}]->() RETURN count(*) AS n").scalar("n") or 0
        if n:
            tag = DIM("  (materialised inverse)") if etype in _INVERSES else ""
            print(f"  {etype:22} {n:>8,}{tag}")
    print()
    return 0


# --------------------------------------------------------------------------
# Node lifecycle -- so nothing here needs an unsigned .ps1 to run
# --------------------------------------------------------------------------


def cmd_up(args) -> int:
    from . import node

    print()
    try:
        node.up(verbose=True)
    except node.NodeError as exc:
        print(RED(f"\n{exc}\n"), file=sys.stderr)
        return 2
    print(GREEN("  node is up at http://127.0.0.1:8443"))
    print(DIM("  next: python -m blastradius.cli ingest"))
    print()
    return 0


def cmd_down(args) -> int:
    from . import node

    print()
    try:
        node.down()
    except node.NodeError as exc:
        print(RED(f"{exc}"), file=sys.stderr)
        return 2
    print()
    return 0


def cmd_logs(args) -> int:
    from . import node

    try:
        print(node.logs(args.tail))
    except node.NodeError as exc:
        print(RED(f"{exc}"), file=sys.stderr)
        return 2
    return 0


def cmd_wipe(args) -> int:
    from . import node

    ids_db = Path(__file__).resolve().parent.parent / "data" / "ids.sqlite"
    print()
    print(YELLOW("  This destroys the container, the volume and the id map."))
    if input("  Type 'wipe' to confirm: ").strip() != "wipe":
        print("  cancelled\n")
        return 1
    try:
        node.wipe()
    except node.NodeError as exc:
        print(RED(f"{exc}"), file=sys.stderr)
        return 2
    for leftover in ids_db.parent.glob("ids.sqlite*"):
        leftover.unlink()
        print(f"  removed {leftover.name}")
    print()
    return 0


def cmd_status(args) -> int:
    from . import node

    print()
    print(rule("environment"))
    daemon = node.daemon_ready()
    print(f"  docker daemon   : {GREEN('up') if daemon else RED('not reachable')}")
    if not daemon:
        print(DIM("    Start Docker Desktop, wait for the tray icon to settle, retry."))
        print()
        return 2

    state = node.container_state()
    print(f"  container       : {state if state != 'running' else GREEN('running')}")
    ready = node.readyz()
    print(f"  readyz          : {GREEN('200 OK') if ready else RED('unreachable')}")
    if not ready:
        print(DIM("    Run: python -m blastradius.cli up"))
        print()
        return 2

    print()
    print(rule("graph contents"))
    client = HydraClient(base_url=args.url)
    counts = client.counts_by_label(schema.ALL_NODE_LABELS)
    if not any(counts.values()):
        print(DIM("  empty -- run: python -m blastradius.cli ingest"))
    for label, n in counts.items():
        if n:
            print(f"  {label:22} {n:>8,}")
    print()
    return 0


def cmd_reset(args) -> int:
    """Empty the graph and the id map, leaving a running node behind.

    Done by recreating the store, not by deleting rows. Deleting is the
    obvious implementation and it does not survive contact with the package
    tier: this node costs ~319 ms per node in a batched `DETACH DELETE` and
    ~3.7 ms per edge in a bulk edge delete, so a graph of a few thousand nodes
    needs many minutes and blows the 25 s per-query timeout in the middle,
    leaving the graph half-cleared. Chunking smaller only trades one failure
    for a slower one, and `WITH n LIMIT k` -- the way to bound it server-side
    -- is rejected by the mutation engine.

    Dropping the volume is O(1) and, unlike a row-by-row sweep, cannot finish
    partially. The container comes back up before this returns, so the
    observable contract is unchanged: a running node, an empty graph, and a
    fresh id map ready for the next ingest.

    The id map has to go with the graph. It is what makes an ingest idempotent
    -- same natural key in, same node id out -- so keeping it against an empty
    graph is harmless, but keeping a graph against a deleted map means the
    next ingest allocates from the block base again and writes a second copy
    of everything beside the first.
    """
    from . import node

    print()
    try:
        node.require_daemon()
        node.wipe(verbose=False)
        print("  store dropped")
        node.up(wait=args.wait, verbose=True)
    except node.NodeError as exc:
        print(RED(f"{exc}"), file=sys.stderr)
        return 2

    ids_db = Path(__file__).resolve().parent.parent / "data" / "ids.sqlite"
    for leftover in ids_db.parent.glob("ids.sqlite*"):
        leftover.unlink()
    print(DIM("  id map deleted too, so the next ingest allocates fresh ids"))
    print()
    return 0


def cmd_ingest(args) -> int:
    from .ids import IdAllocator
    from .ingest.load import ingest_corpus

    client = HydraClient(base_url=args.url)
    corpus = Path(args.corpus)
    try:
        with IdAllocator() as ids:
            report = ingest_corpus(corpus, client, ids, verbose=not args.quiet)
    except (HydraError, FileNotFoundError) as exc:
        print(RED(f"\n{exc}\n"), file=sys.stderr)
        return 2
    print("\n" + report.render() + "\n")
    return 0


def _suggest_paths(raw: str) -> None:
    r"""Explain a path that did not resolve, and offer the likely intent.

    Git Bash silently eats an unrecognised backslash escape, so `..\GenReal.ai`
    reaches Python as `..GenReal.ai` -- a name with no separator in it at all,
    and an error that reads as though the directory is missing rather than as a
    quoting problem. Worth naming, because the message otherwise sends you
    looking for the wrong bug.
    """
    cwd = Path.cwd()
    print()
    print(RED(f"  no such directory: {raw}"))
    print(DIM(f"  resolved to : {Path(raw).resolve()}"))
    print(DIM(f"  working dir : {cwd}"))

    if "\\" in raw or ("/" not in raw and not Path(raw).exists()):
        print()
        print(YELLOW("  If you typed a backslash in Git Bash, the shell ate it."))
        print(DIM("  Use forward slashes here; backslashes only work in PowerShell."))

    # Offer real directories whose name resembles what was asked for, ignoring
    # separators and punctuation -- which is exactly what got mangled.
    def norm(text: str) -> str:
        return "".join(c for c in text.lower() if c.isalnum())

    wanted = norm(Path(raw).name or raw)
    seen: list[str] = []
    for parent in (cwd, cwd / "corpus", cwd.parent):
        if not parent.is_dir():
            continue
        for child in sorted(parent.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            candidate = norm(child.name)
            if wanted and (wanted in candidate or candidate in wanted):
                try:
                    rel = child.relative_to(cwd).as_posix()
                except ValueError:
                    rel = child.as_posix()
                if rel not in seen:
                    seen.append(rel)

    if seen:
        print()
        print("  Did you mean:")
        for rel in seen[:5]:
            print(GREEN(f"    python -m blastradius.cli scan {rel}"))
    print()


def cmd_scan(args) -> int:
    """Micro graph only, for an arbitrary Node project with no lockfile."""
    from .ids import IdAllocator
    from .ingest.load import ingest_micro

    client = HydraClient(base_url=args.url)
    try:
        with IdAllocator() as ids:
            report = ingest_micro(
                Path(args.project),
                client,
                ids,
                service_name=args.service,
                verbose=not args.quiet,
            )
    except FileNotFoundError:
        _suggest_paths(args.project)
        return 2
    except (HydraError, RuntimeError) as exc:
        print()
        print(RED(str(exc)), file=sys.stderr)
        print()
        return 2

    print()
    print(report.render())
    print()
    functions = report.nodes.get(schema.FUNCTION, 0)
    if functions > 4000:
        print(YELLOW(f"  {functions:,} functions is past what the Explorer draws well."))
        print(DIM("  It ships the whole graph to the browser; expect it to crawl."))
        print(DIM("  The CLI queries stay fast -- those run in the database."))
        print()
    return 0


# --------------------------------------------------------------------------
# Live vulnerability data
# --------------------------------------------------------------------------


def cmd_osv_scan(args) -> int:
    """Scan a repository for real vulnerabilities and write both graph inputs.

    This is what makes the vulnerable half of the graph dynamic. Before it,
    the only things marking a version were three hand-written advisory files
    and a `simulate` command that names a package by hand -- neither of which
    says anything about the code being scanned.
    """
    from .pkg import osvscan

    try:
        run = osvscan.scan_repository(
            args.repo,
            out_dir=args.out,
            advisory_dir=None if args.no_advisories else args.advisories,
            engine=args.engine,
            include_python=args.python,
            verbose=not args.quiet,
        )
    except FileNotFoundError:
        _suggest_paths(args.repo)
        return 2
    except RuntimeError as exc:
        print()
        print(RED(str(exc)), file=sys.stderr)
        print()
        return 2

    print()
    print(rule("OSV SCAN"))
    print(run.render())

    log_path = Path(args.log) if args.log else Path(run.csv_path).parent / "scan-log.md"
    run.write_log(log_path)
    print()
    print(f"  log report      {log_path}")
    print(f"  machine report  {log_path.with_suffix('.json')}")

    if run.findings:
        print()
        print("  Feed it to the package tier:")
        # --corpus is a global option on that parser, so it goes before the
        # subcommand. Printing it the other way round hands over a command
        # that fails with an argparse error rather than an ingest.
        print(GREEN(
            f"    python -m blastradius.pkg.cli --corpus {args.repo} ingest "
            f"--osv {run.csv_path}"
        ))
    else:
        print()
        print(GREEN("  No known vulnerabilities in the versions this repo resolves."))
    print()
    return 0


def cmd_pipeline(args) -> int:
    """Scan one repository and rebuild the whole graph from it, timed.

    The three commands this replaces -- osv-scan, ingest, pkg ingest -- have
    to agree on which repository they are talking about, and running them
    against different paths yields a graph whose vulnerabilities describe
    somebody else's code. Doing it in one pass makes that impossible to get
    wrong, and it is the only place the end-to-end cost is measured.
    """
    import time

    from .ids import IdAllocator
    from .ingest.load import ingest_corpus
    from .pkg import osvscan
    from .pkg.cli import DEFAULT_IDS
    from .pkg.ingest import IngestConfig
    from .pkg.ingest import ingest as pkg_ingest
    from .pkg.registry import RegistryClient

    repo = Path(args.repo)
    if not repo.is_dir():
        _suggest_paths(args.repo)
        return 2
    repo = repo.resolve()

    started = time.time()
    wall = time.perf_counter()
    steps: list = []

    def stage(name: str, fn):
        print()
        print(rule(name))
        start = time.perf_counter()
        try:
            value, detail = fn()
        except BaseException:
            steps.append(osvscan.Step(name, time.perf_counter() - start, "FAILED"))
            raise
        elapsed = time.perf_counter() - start
        steps.append(osvscan.Step(name, elapsed, detail))
        print(DIM(f"  -> {elapsed:.2f}s  {detail}"))
        return value

    client = HydraClient(base_url=args.url)

    # -- 1. preflight ------------------------------------------------------

    def preflight():
        from . import node

        if not node.daemon_ready():
            raise RuntimeError(
                "Docker is not reachable. Start Docker Desktop, then retry."
            )
        if not node.readyz():
            raise RuntimeError("HydraDB is not up. Run: python -m blastradius.cli up")
        engine = osvscan.osv_scanner_available() or "api.osv.dev (binary not installed)"
        print(f"  node            : {GREEN('ready')}")
        print(f"  scanner         : {engine}")
        return None, "node ready"

    try:
        stage("preflight", preflight)
    except RuntimeError as exc:
        print()
        print(RED(f"  {exc}"), file=sys.stderr)
        print()
        return 2

    # -- 2. reset ----------------------------------------------------------

    if args.reset:

        def do_reset():
            from . import node

            node.wipe(verbose=False)
            node.up(wait=90, verbose=False)
            ids_db = Path(__file__).resolve().parent.parent / "data" / "ids.sqlite"
            for leftover in ids_db.parent.glob("ids.sqlite*"):
                leftover.unlink()
            return None, "store dropped, id map cleared, node back up"

        stage("reset", do_reset)

    # -- 3. scan -----------------------------------------------------------

    def do_scan():
        run = osvscan.scan_repository(
            repo,
            out_dir=args.out,
            advisory_dir=None if args.no_advisories else args.advisories,
            engine=args.engine,
            include_python=args.python,
            verbose=not args.quiet,
        )
        return run, (
            f"{run.findings} finding(s), {run.advisories} advisory(ies) "
            f"via {run.engine}"
        )

    scan_run = stage("osv scan", do_scan)
    # The scan's own stages are kept rather than collapsed: when the pipeline
    # is slow it is almost always inside this one, and a single line reading
    # "scan: 40s" does not say which half.
    steps.extend(
        osvscan.Step(f"  scan: {s.name}", s.seconds, s.detail) for s in scan_run.steps
    )

    # -- 4. code graph + lockfile tier -------------------------------------

    if not args.skip_micro:

        def do_micro():
            with IdAllocator() as ids:
                report = ingest_corpus(repo, client, ids, verbose=not args.quiet)
            return report, (
                f"{sum(report.nodes.values()):,} nodes, "
                f"{sum(report.edges.values()):,} edges"
            )

        stage("code graph ingest", do_micro)

    # -- 5. package tier, with the scan attached ---------------------------

    def do_macro():
        ids = IdAllocator(str(DEFAULT_IDS))
        try:
            report = pkg_ingest(
                client,
                ids,
                corpus=repo,
                osv_csv=scan_run.csv_path if scan_run.findings else None,
                registry=RegistryClient(offline=args.offline),
                config=IngestConfig(
                    fetch_full_metadata=not args.abbreviated,
                    detect_typosquats=not args.no_typosquat,
                ),
                verbose=not args.quiet,
            )
        finally:
            ids.close()
        return report, (
            f"{report.versions:,} versions, {report.advisories:,} advisories, "
            f"{report.closure_edges:,} closure edges"
        )

    pkg_report = stage("package tier ingest", do_macro)

    # -- 6. verify it landed -----------------------------------------------

    def verify():
        counts = client.counts_by_label(schema.ALL_NODE_LABELS)
        try:
            affects = len(
                client.query(
                    "MATCH (a:Advisory)-[:AFFECTS]->(v:PackageVersion) "
                    "RETURN a.advisory_id AS advisory_id, v.key AS key"
                ).rows
            )
        except HydraError:
            affects = 0
        return (counts, affects), (
            f"{counts.get(schema.ADVISORY, 0):,} Advisory nodes, "
            f"{affects:,} AFFECTS edges"
        )

    counts, affects = stage("verify", verify)
    elapsed = time.perf_counter() - wall

    # -- 7. the report -----------------------------------------------------

    print()
    print(rule("PIPELINE"))
    print()
    print(osvscan.render_steps(steps, elapsed))
    print()

    if counts.get(schema.ADVISORY, 0) == 0:
        print(YELLOW("  No Advisory nodes landed. Either the repo has no known"))
        print(YELLOW("  vulnerabilities, or the scanned versions are not the ones"))
        print(YELLOW("  the lockfiles resolved -- check the scan log."))
    else:
        print(
            f"  {GREEN(str(counts[schema.ADVISORY]) + ' advisories')} now sit on "
            f"{affects} package version(s), from a live scan of"
        )
        print(f"  {repo}")
        print()
        print("  Try:")
        for spec, _rows in scan_run.top[:3]:
            print(GREEN(f"    python -m blastradius.pkg.cli simulate {spec}"))
        print(GREEN("    python -m blastradius.cli ui"))

    log_path = (
        Path(args.log)
        if args.log
        else Path(scan_run.csv_path).parent / "pipeline-log.md"
    )
    _write_pipeline_log(
        log_path, repo, scan_run, pkg_report, counts, affects, steps, elapsed, started
    )
    print()
    print(f"  log report      {log_path}")
    print(f"  machine report  {log_path.with_suffix('.json')}")
    print()
    return 0


def _write_pipeline_log(
    path, repo, scan_run, pkg_report, counts, affects, steps, elapsed, started
) -> None:
    """Both shapes of the same run: a table to read, JSON to diff."""
    import time as _time

    from .pkg import osvscan

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(started))
    body = [
        "# Blast Radius pipeline log",
        "",
        f"generated {stamp}",
        "",
        f"- repository: `{repo}`",
        f"- scanner engine: `{scan_run.engine}`",
        f"- findings: {scan_run.findings:,} rows -> {scan_run.advisories:,} "
        f"advisories after alias merge",
        f"- Advisory nodes in graph: {counts.get(schema.ADVISORY, 0):,}",
        f"- AFFECTS edges: {affects:,}",
        "",
        "## Timing",
        "",
        "```",
        osvscan.render_steps(steps, elapsed),
        "```",
        "",
        "## Scan detail",
        "",
        "```",
        scan_run.render(),
        "```",
        "",
        "## Graph contents",
        "",
        "| label | nodes |",
        "|---|---:|",
    ]
    body += [f"| {label} | {n:,} |" for label, n in counts.items() if n]
    body += ["", "## Package tier", "", "```", pkg_report.render(), "```", ""]
    path.write_text("\n".join(body), encoding="utf-8")

    path.with_suffix(".json").write_text(
        json.dumps(
            {
                "repo": str(repo),
                "started_at": started,
                "elapsed_s": round(elapsed, 3),
                "scan": scan_run.to_dict(),
                "graph_counts": {k: v for k, v in counts.items() if v},
                "advisory_nodes": counts.get(schema.ADVISORY, 0),
                "affects_edges": affects,
                "steps": [
                    {
                        "name": s.name.strip(),
                        "seconds": round(s.seconds, 4),
                        "detail": s.detail,
                    }
                    for s in steps
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def cmd_serve(args) -> int:
    import uvicorn

    print(f"\n  UI at http://127.0.0.1:{args.port}\n")
    uvicorn.run("blastradius.api.main:app", host="127.0.0.1", port=args.port, log_level="warning")
    return 0


def _free_port(preferred: int, span: int = 10) -> int:
    """Return `preferred` if it is free, else the next free port after it.

    A stale server from an earlier run holding the port is the normal case
    here, and uvicorn's failure for it is a raw WinError 10048 that says
    nothing about what to do. Rather than die mid-demo, move to the next port
    and say so.
    """
    import socket

    for offset in range(span):
        port = preferred + offset
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
        if offset:
            print(YELLOW(f"  port {preferred} is already in use - using {port} instead"))
            print(DIM(f"  (something is still listening on {preferred}; a previous run, most likely)"))
        return port
    print()
    print(RED(f"  ports {preferred}-{preferred + span - 1} are all in use."))
    print(DIM("  Close whatever is holding them, or pass --port."))
    print()
    raise SystemExit(2)


def cmd_ui(args) -> int:
    """Run the Blast Radius Explorer frontend."""
    import uvicorn

    port = _free_port(args.port)
    print()
    print(f"  Blast Radius Explorer -> http://127.0.0.1:{port}")
    print(DIM("  ctrl-c to stop"))
    print()
    uvicorn.run("ui.server:app", host="127.0.0.1", port=port, log_level="warning")
    return 0


def cmd_doctor(args) -> int:
    """Check every prerequisite and say exactly what to do about each gap."""
    import shutil
    import subprocess

    print()
    print(rule("prerequisites"))
    ok = True

    print(f"  python          : {GREEN(sys.version.split()[0])}")

    node_exe = shutil.which("node")
    if node_exe:
        version = subprocess.run(
            [node_exe, "--version"], capture_output=True, text=True
        ).stdout.strip()
        print(f"  node            : {GREEN(version)}")
    else:
        print(f"  node            : {RED('not found')}  {DIM('install Node.js 18+')}")
        ok = False

    root = Path(__file__).resolve().parent.parent
    ts_morph = root / "scanner" / "node_modules" / "ts-morph"
    if ts_morph.is_dir():
        print(f"  ts-morph        : {GREEN('installed')}")
    else:
        print(f"  ts-morph        : {RED('missing')}  {DIM('cd scanner && npm install')}")
        ok = False

    # The scanner is a Go binary, so a machine without the toolchain cannot
    # pip-install its way out. Missing is a downgrade, not a failure: the scan
    # falls back to api.osv.dev and says so, which is why this does not clear
    # `ok`.
    from .pkg.osvscan import osv_scanner_available

    scanner = osv_scanner_available()
    if scanner:
        version = subprocess.run(
            [scanner, "--version"], capture_output=True, text=True
        ).stdout.splitlines()
        print(f"  osv-scanner     : {GREEN(version[0] if version else 'installed')}")
    else:
        print(f"  osv-scanner     : {YELLOW('not found')}  "
              f"{DIM('scans fall back to api.osv.dev')}")
        print(DIM("                    go install github.com/google/osv-scanner/"
                  "v2/cmd/osv-scanner@latest"))

    for module in ("fastapi", "uvicorn"):
        try:
            __import__(module)
            print(f"  {module:16}: {GREEN('installed')}")
        except ImportError:
            print(f"  {module:16}: {RED('missing')}  {DIM('pip install -r requirements.txt')}")
            ok = False

    from . import node as node_mod

    if node_mod.daemon_ready():
        print(f"  docker daemon   : {GREEN('up')}")
        print(f"  hydradb         : {GREEN('ready') if node_mod.readyz() else YELLOW('not started')}")
        if not node_mod.readyz():
            print(DIM("                    python -m blastradius.cli up"))
    else:
        print(f"  docker daemon   : {RED('not reachable')}  {DIM('start Docker Desktop')}")
        ok = False

    corpus = root / "corpus"
    locks = [p for p in corpus.rglob("package-lock.json") if "node_modules" not in p.parts]
    print(f"  corpus          : {len(locks)} lockfile(s) under {corpus.name}/")

    print()
    print(GREEN("  all good") if ok else YELLOW("  fix the items above, then re-run doctor"))
    print()
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius",
        description="Supply-chain blast radius over a fleet of codebases.",
    )
    parser.add_argument("--url", default="http://127.0.0.1:8443", help="HydraDB HTTP endpoint")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="assess one package[@version]")
    check.add_argument("package", help="e.g. ua-parser-js@0.7.29 or just express")
    check.add_argument("--range", default="", help='npm range, e.g. ">=4.18.0 <4.19.0"')
    check.add_argument("--id", default="AD-HOC", help="advisory id for the report header")
    check.add_argument("--no-paths", action="store_true", help="skip the MSpaths section")
    check.set_defaults(func=cmd_check)

    adv = sub.add_parser("advisory", help="assess from an advisory JSON file")
    adv.add_argument("file", type=Path)
    adv.add_argument("--no-paths", action="store_true")
    adv.set_defaults(func=cmd_advisory)

    svc = sub.add_parser("services", help="list ingested services")
    svc.set_defaults(func=cmd_services)

    st = sub.add_parser("stats", help="node and edge counts")
    st.set_defaults(func=cmd_stats)

    # -- lifecycle --
    doctor = sub.add_parser("doctor", help="check every prerequisite")
    doctor.set_defaults(func=cmd_doctor)

    up = sub.add_parser("up", help="start the HydraDB container")
    up.set_defaults(func=cmd_up)

    dn = sub.add_parser("down", help="stop the container, keep the data")
    dn.set_defaults(func=cmd_down)

    stat = sub.add_parser("status", help="daemon, container, readiness, contents")
    stat.set_defaults(func=cmd_status)

    lg = sub.add_parser("logs", help="tail the node log")
    lg.add_argument("--tail", type=int, default=60)
    lg.set_defaults(func=cmd_logs)

    scan = sub.add_parser("scan", help="micro graph only, from any Node project")
    scan.add_argument("project", help="path to the application directory")
    scan.add_argument("--service", default=None, help="name to file it under")
    scan.add_argument("--quiet", action="store_true")
    scan.set_defaults(func=cmd_scan)

    ing = sub.add_parser("ingest", help="scan the corpus into the graph")
    ing.add_argument("--corpus", default="corpus")
    ing.add_argument("--quiet", action="store_true")
    ing.set_defaults(func=cmd_ingest)

    def _scan_flags(p):
        """Flags shared by osv-scan and pipeline, so the two cannot drift."""
        p.add_argument("--out", default=None,
                       help="where the CSV lands (default data/osv/<repo>/)")
        p.add_argument("--advisories", default=str(DEFAULT_ADVISORY_DIR),
                       help="where the generated advisory JSON lands")
        p.add_argument("--no-advisories", action="store_true",
                       help="write the CSV only, leave the UI chips alone")
        p.add_argument("--engine", choices=("auto", "binary", "api"), default="auto",
                       help="auto uses osv-scanner if installed, else api.osv.dev")
        p.add_argument("--python", action="store_true",
                       help="also resolve requirements.txt with pip (slow)")
        p.add_argument("--log", default=None, help="path for the log report")
        p.add_argument("--quiet", action="store_true")

    osv = sub.add_parser("osv-scan",
                         help="scan a repo for real vulnerabilities (no graph writes)")
    osv.add_argument("repo", help="path to the repository to scan")
    _scan_flags(osv)
    osv.set_defaults(func=cmd_osv_scan)

    pipe = sub.add_parser(
        "pipeline",
        help="scan one repo and rebuild both graph tiers from it, timed",
    )
    pipe.add_argument("repo", help="path to the repository to scan and ingest")
    _scan_flags(pipe)
    pipe.add_argument("--reset", action="store_true",
                      help="empty the graph and id map first")
    pipe.add_argument("--skip-micro", action="store_true",
                      help="package tier only, skip the ts-morph call graph")
    pipe.add_argument("--offline", action="store_true",
                      help="package tier reads only data/registry-cache/")
    pipe.add_argument("--abbreviated", action="store_true",
                      help="skip maintainer/repository metadata (much faster)")
    pipe.add_argument("--no-typosquat", action="store_true")
    pipe.set_defaults(func=cmd_pipeline)

    srv = sub.add_parser("serve", help="run the assessment API + simple UI")
    srv.add_argument("--port", type=int, default=8000)
    srv.set_defaults(func=cmd_serve)

    explorer = sub.add_parser("ui", help="run the Blast Radius Explorer frontend")
    explorer.add_argument("--port", type=int, default=8100)
    explorer.set_defaults(func=cmd_ui)

    rst = sub.add_parser("reset", help="empty the graph + id map, node stays up")
    rst.add_argument("--wait", type=int, default=90,
                     help="seconds to wait for readiness after the restart")
    rst.set_defaults(func=cmd_reset)

    wp = sub.add_parser("wipe", help="destroy container, volume and id map")
    wp.set_defaults(func=cmd_wipe)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except HydraError as exc:
        print(RED(f"\n{exc}\n"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
