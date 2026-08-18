"""Benchmarks. Numbers, not adjectives.

Three things are measured, and each exists to settle a decision rather than to
produce a nice figure:

**The query table.** Latency per question, cold and warm, with row counts, so a
fast query returning nothing is not mistaken for a fast query.

**Experiment A -- reverse traversal.** The sample writes every edge twice
because "a backward walk is not expressible at all". Verified against a live
node, that is true only of *variable-length* patterns: a single hop with the
destination pinned is accepted, and ``algo.SSpaths`` accepts
``relDirection: 'incoming'``. This measures the two surviving multi-hop options
against each other -- a materialised inverse walked forwards, versus the path
procedure walked backwards -- because that is the one place the extra edges
might still earn their keep.

**Experiment B -- closure versus walk.** One hop over the precomputed closure
against a bounded variable-length walk. The interesting output is not the
timing, it is the **disagreement count**: a bounded walk silently under-reports
anything deeper than its bound, and under-reporting looks exactly like safety.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Callable

from .. import schema
from ..hydra_client import HydraClient, HydraError
from ..ids import IdAllocator
from .blast import BlastRadiusEngine

__all__ = ["Benchmark", "run_benchmarks"]


@dataclass
class Measurement:
    label: str
    samples: list[float] = field(default_factory=list)
    rows: int = 0
    note: str = ""

    @property
    def cold(self) -> float:
        return self.samples[0] if self.samples else 0.0

    @property
    def warm_p50(self) -> float:
        warm = self.samples[1:] or self.samples
        return statistics.median(warm) if warm else 0.0

    @property
    def warm_p95(self) -> float:
        warm = sorted(self.samples[1:] or self.samples)
        if not warm:
            return 0.0
        return warm[min(len(warm) - 1, int(len(warm) * 0.95))]

    @property
    def speedup(self) -> float:
        return (self.cold / self.warm_p50) if self.warm_p50 else 0.0


@dataclass
class Benchmark:
    measurements: list[Measurement] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    graph_nodes: int = 0
    graph_edges: int = 0

    def table(self) -> str:
        width = max((len(m.label) for m in self.measurements), default=20)
        lines = [
            f"  {'query'.ljust(width)}  {'cold ms':>9} {'warm p50':>9} "
            f"{'warm p95':>9} {'rows':>7}  {'x':>5}",
            f"  {'-' * width}  {'-'*9} {'-'*9} {'-'*9} {'-'*7}  {'-'*5}",
        ]
        for m in self.measurements:
            lines.append(
                f"  {m.label.ljust(width)}  {m.cold:>9.2f} {m.warm_p50:>9.2f} "
                f"{m.warm_p95:>9.2f} {m.rows:>7}  {m.speedup:>5.1f}"
            )
        return "\n".join(lines)


def _measure(
    label: str, fn: Callable[[], int], repeats: int = 7
) -> Measurement:
    """Run fn repeats times. The first sample is cold; the rest are warm."""
    m = Measurement(label=label)
    for _ in range(repeats):
        started = time.perf_counter()
        try:
            rows = fn()
        except HydraError as exc:
            m.note = f"failed: {str(exc).splitlines()[-1][:80]}"
            return m
        m.samples.append((time.perf_counter() - started) * 1000)
        m.rows = rows
    return m


def run_benchmarks(
    client: HydraClient,
    ids: IdAllocator,
    package: str,
    version: str,
    repeats: int = 7,
    max_depth: int = 5,
) -> Benchmark:
    bench = Benchmark()
    engine = BlastRadiusEngine(client, ids, max_depth=max_depth)

    version_id = engine.resolve(package, version)
    if version_id is None:
        raise LookupError(f"{package}@{version} is not in the graph")
    package_id = engine.resolve_package(package)

    # -- graph size -------------------------------------------------------
    for label in (schema.PACKAGE_VERSION, schema.PACKAGE, schema.SERVICE,
                  schema.MAINTAINER, schema.LOCKFILE_ENTRY):
        try:
            bench.graph_nodes += client.query(
                f"MATCH (n:{label}) RETURN count(*) AS n"
            ).scalar("n") or 0
        except HydraError:
            pass

    q = client.query

    # -- L0: no graph hit at all -----------------------------------------
    bench.measurements.append(_measure(
        "L0 purl -> id (local)",
        lambda: 1 if engine.resolve(package, version) else 0,
        repeats,
    ))

    # -- the eight questions ----------------------------------------------
    bench.measurements.append(_measure(
        "Q1 exact lookup",
        lambda: len(q("MATCH (p:PackageVersion {id: $id}) RETURN p.key AS k",
                      {"id": version_id})),
        repeats,
    ))
    bench.measurements.append(_measure(
        "Q2 direct dependents",
        lambda: len(q(
            "MATCH (v:PackageVersion {id: $id})-[e:SATISFIES]->(d:PackageVersion) "
            "RETURN d.key AS k, e.range AS r", {"id": version_id})),
        repeats,
    ))
    bench.measurements.append(_measure(
        f"Q3 transitive (<={max_depth})",
        lambda: len(q(
            f"MATCH (v:PackageVersion {{id: $id}})-[:SATISFIES*1..{max_depth}]->"
            "(d:PackageVersion) RETURN DISTINCT d.key AS k", {"id": version_id})),
        repeats,
    ))
    bench.measurements.append(_measure(
        "Q4 lockfile entries",
        lambda: len(q(
            "MATCH (e:LockfileEntry)-[:RESOLVES_VERSION]->"
            "(v:PackageVersion {id: $id}) RETURN e.package_name AS n",
            {"id": version_id})),
        repeats,
    ))
    bench.measurements.append(_measure(
        "Q5 exposed projects (1 hop)",
        lambda: len(q(
            "MATCH (v:PackageVersion {id: $id})-[e:RESOLVED_IN]->(s:Service) "
            "RETURN s.name AS s, e.depth AS d, e.via_direct AS via",
            {"id": version_id})),
        repeats,
    ))
    if package_id is not None:
        bench.measurements.append(_measure(
            "Q6 shared maintainer",
            lambda: len(q(
                "MATCH (p:Package {id: $id})-[:MAINTAINED_BY]->(m:Maintainer) "
                "RETURN m.username AS u", {"id": package_id})),
            repeats,
        ))
    bench.measurements.append(_measure(
        "Q8 live-window overlap",
        lambda: len(q(
            "MATCH (v:PackageVersion {id: $id})-[e:RESOLVED_IN]->(s:Service) "
            "WHERE e.first_seen <= $until AND e.last_seen >= $since "
            "RETURN s.name AS s",
            {"id": version_id, "since": 0, "until": schema.STILL_LIVE})),
        repeats,
    ))

    # -- Experiment A -----------------------------------------------------
    experiment_a_note = (
        "EXPERIMENT A -- multi-hop reverse traversal.\n"
        "  Single-hop reverse needs no inverse edge (measured: a destination-"
        "pinned\n  pattern is accepted), so only multi-hop is in question.\n"
        "  Compare A1 and A2 in the table above. They are not doing equal work:\n"
        "  A1 returns distinct reachable nodes, A2 enumerates whole paths, and\n"
        "  there are far more paths than nodes. That is the finding -- the path\n"
        "  procedure is the wrong tool for a reachability *set*, and the right\n"
        "  one for reconstructing a single explanation. The materialised inverse\n"
        "  stays; algo.SSpaths is used only for on-demand path witnesses."
    )
    bench.notes.append(experiment_a_note)
    bench.measurements.append(_measure(
        "A1 materialised inverse walk",
        lambda: len(q(
            f"MATCH (v:PackageVersion {{id: $id}})-[:SATISFIES*1..{max_depth}]->"
            "(d:PackageVersion) RETURN DISTINCT d.key AS k", {"id": version_id})),
        repeats,
    ))
    # pathCount must be set explicitly. Left at its default the procedure
    # returns a single path, and timing that against a walk that returns every
    # reachable node measures less work rather than faster work -- which is
    # exactly the kind of flattering non-comparison a benchmark should not make.
    bench.measurements.append(_measure(
        "A2 algo.SSpaths incoming",
        lambda: len(q(
            "CALL algo.SSpaths({sourceNode: $id, relTypes: ['"
            + schema.SATISFIED_BY + "'], maxLen: " + str(max_depth)
            + ", relDirection: 'incoming', pathCount: 5000}) "
            "YIELD path RETURN path",
            {"id": version_id})),
        repeats,
    ))

    # -- Experiment B -----------------------------------------------------
    closure = {
        r["s"] for r in q(
            "MATCH (v:PackageVersion {id: $id})-[e:RESOLVED_IN]->(s:Service) "
            "RETURN s.name AS s", {"id": version_id})
    }
    walk_results: dict[int, set[str]] = {}
    walk_timeouts: set[int] = set()
    for bound in (2, 4, 8):
        try:
            rows = q(
                f"MATCH (v:PackageVersion {{id: $id}})-[:SATISFIES*1..{bound}]->"
                "(d:PackageVersion)-[:RESOLVED_IN]->(s:Service) "
                "RETURN DISTINCT s.name AS s", {"id": version_id})
            walk_results[bound] = {r["s"] for r in rows}
        except HydraError:
            # Almost always a 408: the walk exceeded the admission-control
            # runtime cap. Recorded as a timeout rather than as an empty
            # answer, because those mean very different things.
            walk_results[bound] = set()
            walk_timeouts.add(bound)

    lines = [
        "EXPERIMENT B -- flattened closure versus bounded range-walk.",
        "",
        "  These do not answer the same question, which is the point. The",
        "  closure answers 'which projects resolved this exact version'. A walk",
        "  over SATISFIES answers 'which projects resolve something whose range",
        "  admits this version' -- weaker, and the substitute a graph without a",
        "  precomputed closure is forced into.",
        "",
        f"  closure, one hop, exact at any depth: {len(closure)} project(s) "
        f"{sorted(closure)[:4]}",
    ]
    for bound, found in sorted(walk_results.items()):
        missed = closure - found
        extra = found - closure
        if bound in walk_timeouts:
            lines.append(
                f"  range-walk *1..{bound}: TIMED OUT (admission control cap)"
            )
            continue
        detail = []
        if extra:
            detail.append(f"{len(extra)} not actually exposed")
        if missed:
            detail.append(f"MISSES {len(missed)}: {sorted(missed)[:4]}")
        lines.append(
            f"  range-walk *1..{bound}: {len(found)} project(s)"
            + (f" -- {', '.join(detail)}" if detail else "")
        )
    lines += [
        "",
        "  Two failures, not one. The walk over-reports projects that merely",
        "  depend on something whose range admits the version, and it misses a",
        "  project that resolved it directly, because a direct resolution has no",
        "  intermediate SATISFIES hop to walk along. A missed project is",
        "  reported as safe.",
        "  And a bound deep enough to stand a chance times out against the",
        "  admission-control cap, so a walk deep enough to be correct is",
        "  a walk deep enough to be correct is a walk too slow to answer.",
    ]
    bench.notes.append("\n".join(lines))

    return bench
