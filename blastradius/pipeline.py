"""One repository in, a fully populated graph out.

The three commands this replaces -- `osv-scan`, `cli ingest`, `pkg.cli ingest`
-- all have to agree on *which* repository they are talking about, and running
them against different paths gives you a graph whose vulnerabilities describe
somebody else's code. Doing it in one pass makes that impossible to get wrong.

What runs beside what
---------------------

Three of the four stages do not depend on each other, so they run together::

    +-- phase A (concurrent) ------------------------------------------+
    |  osv scan          -> files only, touches neither graph nor ids  |
    |  code graph ingest -> the only graph writer in this phase        |
    |  registry prefetch -> warms data/registry-cache/, network only   |
    +------------------------------------------------------------------+
                                    |
    phase B: package tier ingest  <-+  needs the scan's CSV, the ids the
                                       code graph allocated, and the
                                       registry documents now in cache

The split is drawn along what each stage *writes*, not along what would be
convenient. Exactly one member of phase A writes to the graph and exactly one
writes ``data/ids.sqlite``, so there is no lock to contend and no ordering to
get wrong. The package tier is not in there because it genuinely depends on
all three, and starting it early would mean ingesting advisories the scan had
not finished finding.

The prefetch is the one that pays. The package tier spends most of its time
waiting on the npm registry, and those documents are keyed by package name --
which the lockfiles already name, before any advisory is known. Fetching them
while the scanner and the AST walker are busy turns that wait into a cache
read. `RegistryClient` writes its cache atomically and is already thread-safe,
so the two phases share one client and the second finds what the first left.

Concurrency is defeatable (`parallel=False`). When a stage fails, being able
to run the same work in a straight line is worth more than the seconds.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import schema
from .hydra_client import HydraClient, HydraError
from .ids import IdAllocator
from .ingest.lockfile import find_lockfiles, parse_package_lock
from .ingest.load import ingest_corpus
from .pkg import osvscan
from .pkg.ingest import IngestConfig
from .pkg.ingest import ingest as pkg_ingest
from .pkg.osvscan import ScanRun, Step, render_steps
from .pkg.registry import RegistryClient

__all__ = ["PipelineReport", "run_pipeline", "DEFAULT_CORPUS"]

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = ROOT / "corpus"
DEFAULT_IDS = ROOT / "data" / "ids.sqlite"


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


@dataclass
class PipelineReport:
    """What one end-to-end run produced, and where its time went."""

    repo: str
    parallel: bool = True
    steps: list[Step] = field(default_factory=list)
    scan: ScanRun | None = None
    micro: Any = None
    package: Any = None
    counts: dict[str, int] = field(default_factory=dict)
    affects: int = 0
    elapsed_s: float = 0.0
    started_at: float = 0.0
    #: Stage name -> the exception it raised. A stage that failed does not
    #: abort the others in its phase; it is reported and the run continues,
    #: because a scan that could not reach the network should not also cost
    #: you the code graph.
    failures: dict[str, str] = field(default_factory=dict)

    @property
    def advisory_nodes(self) -> int:
        return self.counts.get(schema.ADVISORY, 0)

    #: Wall clock of phase A, and of each of its top-level members. Recorded
    #: when the phase runs rather than derived from `steps` afterwards: the
    #: scan's own sub-steps are spliced into that list and are *inside* the
    #: scan's own duration, so summing every concurrent row would count the
    #: scan twice and overstate what the overlap won.
    phase_seconds: float = 0.0
    phase_member_seconds: list[float] = field(default_factory=list)

    @property
    def saved_s(self) -> float:
        """Wall clock saved by phase A, versus running its members in turn."""
        if not self.phase_member_seconds:
            return 0.0
        return max(0.0, sum(self.phase_member_seconds) - self.phase_seconds)

    def render(self) -> str:
        lines = [
            f"repo             {self.repo}",
            f"mode             {'concurrent' if self.parallel else 'sequential'}",
        ]
        if self.scan:
            lines += [
                f"scanner          {self.scan.engine}",
                f"findings         {self.scan.findings:,} row(s) -> "
                f"{self.scan.advisories:,} advisory(ies) after alias merge",
            ]
        lines += [
            f"Advisory nodes   {self.advisory_nodes:,}",
            f"AFFECTS edges    {self.affects:,}",
        ]
        if self.failures:
            lines.append("")
            for name, message in self.failures.items():
                lines.append(f"FAILED  {name}: {message}")
        lines.append("")
        lines.append(render_steps(self.steps, self.elapsed_s))
        if self.saved_s > 0.05:
            lines.append("")
            lines.append(
                f"phase A saved {self.saved_s:.1f}s against running its three "
                f"stages in turn."
            )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "repo": self.repo,
            "parallel": self.parallel,
            "started_at": self.started_at,
            "elapsed_s": round(self.elapsed_s, 3),
            "saved_s": round(self.saved_s, 3),
            "advisory_nodes": self.advisory_nodes,
            "affects_edges": self.affects,
            "graph_counts": {k: v for k, v in self.counts.items() if v},
            "scan": self.scan.to_dict() if self.scan else None,
            "failures": self.failures,
            "steps": [
                {
                    "name": s.name.strip(),
                    "seconds": round(s.seconds, 4),
                    "detail": s.detail,
                    "concurrent": s.concurrent,
                }
                for s in self.steps
            ],
        }

    def write_log(self, path: Path | str) -> Path:
        """The table to read and the JSON to diff, side by side."""
        import json

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started_at))
        body = [
            "# Blast Radius pipeline log",
            "",
            f"generated {stamp}",
            "",
            "## Summary",
            "",
            "```",
            self.render(),
            "```",
            "",
        ]
        if self.scan:
            body += ["## Scan detail", "", "```", self.scan.render(), "```", ""]
        if self.counts:
            body += ["## Graph contents", "", "| label | nodes |", "|---|---:|"]
            body += [f"| {k} | {v:,} |" for k, v in self.counts.items() if v]
            body.append("")
        if self.package is not None:
            body += ["## Package tier", "", "```", self.package.render(), "```", ""]
        path.write_text("\n".join(body), encoding="utf-8")
        path.with_suffix(".json").write_text(
            json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
        return path


# --------------------------------------------------------------------------
# Stages
# --------------------------------------------------------------------------

PHASE_A = "phase A (concurrent)"


def _lockfile_package_names(repo: Path) -> list[str]:
    """Every package name the repo's lockfiles resolve.

    This is what the registry prefetch needs, and it is knowable before any
    advisory is: a lockfile names its packages whether or not they turn out to
    be vulnerable. Parsing failures are not raised -- the package tier parses
    the same files again and reports them properly; here a bad lockfile just
    means a colder cache.
    """
    names: set[str] = set()
    for path in find_lockfiles(repo):
        try:
            lock = parse_package_lock(path)
        except Exception:  # noqa: BLE001 - a bad lockfile is data, not a bug
            continue
        for entry in lock.packages.values():
            if entry.name:
                names.add(entry.name)
    return sorted(names)


def run_pipeline(
    repo: Path | str = DEFAULT_CORPUS,
    client: HydraClient | None = None,
    *,
    reset: bool = False,
    skip_micro: bool = False,
    offline: bool = False,
    abbreviated: bool = False,
    typosquat: bool = True,
    engine: str = "auto",
    include_python: bool = False,
    advisory_dir: Path | str | None = osvscan.DEFAULT_ADVISORY_DIR,
    out_dir: Path | str | None = None,
    parallel: bool = True,
    prefetch: bool = True,
    verbose: bool = True,
    on_stage: Callable[[str], None] | None = None,
) -> PipelineReport:
    """Scan ``repo`` and build both graph tiers from it.

    Returns a :class:`PipelineReport` whether or not every stage succeeded;
    check ``report.failures`` before trusting the counts.
    """
    repo = Path(repo)
    if not repo.is_dir():
        raise FileNotFoundError(f"no such directory: {repo}")
    repo = repo.resolve()

    client = client or HydraClient()
    report = PipelineReport(repo=str(repo), parallel=parallel, started_at=time.time())
    wall = time.perf_counter()

    def announce(name: str) -> None:
        if on_stage:
            on_stage(name)
        elif verbose:
            print(f"\n  {name} ...", flush=True)

    def timed(name: str, fn, concurrent: bool = False):
        """Run ``fn``, record the time, keep going if it raises."""
        start = time.perf_counter()
        try:
            value, detail = fn()
        except Exception as exc:  # noqa: BLE001 - a stage failing is reportable
            report.steps.append(
                Step(name, time.perf_counter() - start, f"FAILED: {exc}", concurrent)
            )
            report.failures[name.strip()] = str(exc)
            return None
        report.steps.append(
            Step(name, time.perf_counter() - start, detail, concurrent)
        )
        return value

    # -- reset -------------------------------------------------------------

    if reset:
        announce("reset")

        def do_reset():
            from . import node

            node.wipe(verbose=False)
            node.up(wait=90, verbose=False)
            for leftover in DEFAULT_IDS.parent.glob("ids.sqlite*"):
                leftover.unlink()
            return None, "store dropped, id map cleared, node back up"

        timed("reset", do_reset)

    # -- phase A -----------------------------------------------------------
    #
    # One registry client for the whole run, so the prefetch and the package
    # tier share a cache and one set of statistics.

    registry = RegistryClient(offline=offline)

    def scan_stage():
        run = osvscan.scan_repository(
            repo,
            out_dir=out_dir,
            advisory_dir=advisory_dir,
            engine=engine,
            include_python=include_python,
            # Progress printing from inside a thread interleaves with the
            # other two stages into an unreadable mess; the scan's own step
            # table is folded into this report afterwards instead.
            verbose=verbose and not parallel,
        )
        report.scan = run
        return run, (
            f"{run.findings} finding(s), {run.advisories} advisory(ies) "
            f"via {run.engine}"
        )

    def micro_stage():
        with IdAllocator() as ids:
            result = ingest_corpus(repo, client, ids, verbose=verbose and not parallel)
        report.micro = result
        return result, (
            f"{sum(result.nodes.values()):,} nodes, "
            f"{sum(result.edges.values()):,} edges"
        )

    def prefetch_stage():
        names = _lockfile_package_names(repo)
        if not names:
            return None, "no lockfile packages to warm"
        before = registry.stats["misses"]
        registry.packuments(names, full=not abbreviated, on_error=lambda *_: None)
        fetched = registry.stats["misses"] - before
        return None, f"{len(names):,} package(s) warmed, {fetched:,} fetched"

    tasks: list[tuple[str, Any]] = [("  scan", scan_stage)]
    if not skip_micro:
        tasks.append(("  code graph ingest", micro_stage))
    if prefetch and not offline:
        tasks.append(("  registry prefetch", prefetch_stage))

    if parallel and len(tasks) > 1:
        announce(f"{PHASE_A}: " + ", ".join(name.strip() for name, _ in tasks))
        phase_start = time.perf_counter()
        # Each worker records its own step; the pool only decides when they
        # run. Results are collected in submission order so the table reads
        # the same whichever finishes first.
        with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
            futures = [
                (name, pool.submit(timed, name, fn, True)) for name, fn in tasks
            ]
            for _name, future in futures:
                future.result()
        phase = time.perf_counter() - phase_start
        members = report.steps[-len(tasks):]
        report.phase_seconds = phase
        report.phase_member_seconds = [s.seconds for s in members]
        # The phase itself is the sequential row; its members hang off it and
        # are marked concurrent, so the share column stays honest.
        report.steps.insert(
            len(report.steps) - len(tasks),
            Step(PHASE_A, phase, f"{len(tasks)} stage(s) in parallel"),
        )
    else:
        for name, fn in tasks:
            announce(name.strip())
            timed(name.strip(), fn)

    # -- phase B: the package tier ----------------------------------------

    announce("package tier ingest")

    def macro_stage():
        ids = IdAllocator(str(DEFAULT_IDS))
        try:
            result = pkg_ingest(
                client,
                ids,
                corpus=repo,
                # No findings means no CSV worth reading -- passing an empty
                # one would write zero advisories and log a scan that found
                # nothing as though it had been consulted.
                osv_csv=(
                    report.scan.csv_path
                    if report.scan and report.scan.findings
                    else None
                ),
                registry=registry,
                config=IngestConfig(
                    fetch_full_metadata=not abbreviated,
                    detect_typosquats=typosquat,
                ),
                verbose=verbose,
            )
        finally:
            ids.close()
        report.package = result
        return result, (
            f"{result.versions:,} versions, {result.advisories:,} advisories, "
            f"{result.closure_edges:,} closure edges"
        )

    timed("package tier ingest", macro_stage)

    # -- verify ------------------------------------------------------------

    announce("verify")

    def verify_stage():
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
        report.counts, report.affects = counts, affects
        return None, (
            f"{counts.get(schema.ADVISORY, 0):,} Advisory nodes, "
            f"{affects:,} AFFECTS edges"
        )

    timed("verify", verify_stage)

    # The scan's internal breakdown is kept rather than collapsed: when a run
    # is slow it is usually inside one of these, and "scan: 40s" does not say
    # which half. They are nested under a stage that already counted their
    # time, so they carry the concurrent marker rather than a second share.
    if report.scan:
        index = next(
            (i for i, s in enumerate(report.steps) if s.name.strip() == "scan"), None
        )
        if index is not None:
            report.steps[index + 1 : index + 1] = [
                Step(f"    {s.name}", s.seconds, s.detail, True)
                for s in report.scan.steps
            ]

    report.elapsed_s = time.perf_counter() - wall
    return report
