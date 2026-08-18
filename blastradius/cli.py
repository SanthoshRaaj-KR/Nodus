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
            print(f"    {RED('artifact')} {artifact['path']} " + DIM(f"[{artifact['kind']}]"))
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


def _render_path(path) -> str:
    """Best-effort one-line rendering of a returned path structure."""
    if isinstance(path, dict):
        for key in ("vertices", "nodes", "path"):
            if key in path:
                return _render_path(path[key])
        return json.dumps(path)[:200]
    if isinstance(path, list):
        parts = []
        for item in path:
            if isinstance(item, dict):
                parts.append(str(item.get("key") or item.get("name") or item.get("id")))
            else:
                parts.append(str(item))
        return " -> ".join(parts)
    return str(path)


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
        ioc_paths=[".claude/**/*", ".vscode/**/*"],
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

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except HydraError as exc:
        print(RED(f"\n{exc}\n"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
