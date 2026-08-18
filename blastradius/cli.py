"""Terminal front end: one query, both graphs.

Prints the macro (lockfile) answer and the micro (call graph) answer side by
side, because they answer different questions and the gap between them is the
whole point -- "you have it" versus "a request can reach it".

    python -m blastradius.cli check vulnerable-pkg@1.0.5
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


def cmd_stats(args) -> int:
    client = HydraClient(base_url=args.url)
    print()
    print(rule("graph contents"))
    counts = client.counts_by_label(schema.NODE_LABELS)
    for label, n in counts.items():
        print(f"  {label:22} {n:>8,}")
    print()
    print(rule("edges"))
    for etype in schema.EDGE_TYPES:
        n = client.query(f"MATCH ()-[r:{etype}]->() RETURN count(*) AS n").scalar("n") or 0
        if n:
            tag = DIM("  (materialised inverse)") if etype in schema.INVERSE_OF.values() else ""
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
    counts = client.counts_by_label(schema.NODE_LABELS)
    if not any(counts.values()):
        print(DIM("  empty -- run: python -m blastradius.cli ingest"))
    for label, n in counts.items():
        if n:
            print(f"  {label:22} {n:>8,}")
    print()
    return 0


def cmd_reset(args) -> int:
    """Delete every node this project creates; edges go with them."""
    client = HydraClient(base_url=args.url)
    print()
    for label in schema.NODE_LABELS:
        client.query(f"MATCH (n:{label}) DETACH DELETE n")
        print(f"  cleared {label}")
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


def cmd_serve(args) -> int:
    import uvicorn

    print(f"\n  UI at http://127.0.0.1:{args.port}\n")
    uvicorn.run("blastradius.api.main:app", host="127.0.0.1", port=args.port, log_level="warning")
    return 0


def cmd_ui(args) -> int:
    """Run the Blast Radius Explorer frontend."""
    import uvicorn

    print(f"
  Blast Radius Explorer -> http://127.0.0.1:{args.port}
")
    uvicorn.run("ui.server:app", host="127.0.0.1", port=args.port, log_level="warning")
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
    check.add_argument("package", help="e.g. vulnerable-pkg@1.0.5 or just express")
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

    ing = sub.add_parser("ingest", help="scan the corpus into the graph")
    ing.add_argument("--corpus", default="corpus")
    ing.add_argument("--quiet", action="store_true")
    ing.set_defaults(func=cmd_ingest)

    srv = sub.add_parser("serve", help="run the assessment API + simple UI")
    srv.add_argument("--port", type=int, default=8000)
    srv.set_defaults(func=cmd_serve)

    explorer = sub.add_parser("ui", help="run the Blast Radius Explorer frontend")
    explorer.add_argument("--port", type=int, default=8100)
    explorer.set_defaults(func=cmd_ui)

    rst = sub.add_parser("reset", help="empty the graph, keep the container")
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
