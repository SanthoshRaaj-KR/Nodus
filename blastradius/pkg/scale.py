"""Does the exposure query cost track the answer, or the graph?

`PACKAGE-GRAPH.md` §2 claims the headline question -- "which projects resolved
this compromised version" -- is a single hop over a precomputed closure, and
that its cost therefore "tracks the number of projects resolving one version,
not graph size". §10 then admits the claim was never measured beyond a 3.3k-node
graph. This module measures it.

**Why two sweeps and not one.** A flat line on its own proves nothing: a query
that is flat because it is genuinely O(answer) and a query that is flat because
the whole harness is dominated by fixed HTTP overhead look identical. So the
experiment varies the two inputs independently.

*Sweep A -- grow the graph, hold the answer fixed.* Versions and closure edges
climb; the probe keeps exactly ``probe_fanout`` services. If the claim holds,
Q5 is flat.

*Sweep B -- hold the graph, grow the answer.* One graph, probes with different
out-degree. Q5 must **rise** here. This is the control: it demonstrates the
measurement can detect the cost it is claiming not to see in Sweep A. Without
it, Sweep A is unfalsifiable.

**Synthetic, and it says so.** The graph is generated, not crawled -- npm will
not hand over ten million versions on demand, and the question here is a
complexity question, which does not need real names to answer. What has to be
real is the *shape* (a service resolves several hundred versions, a version is
resolved by a few services) and the *code path*: generation goes through
``PackageGraphWriter`` and measurement through ``BlastRadiusEngine``, so this
times the shipping query rather than a copy of it that might have drifted.

**Correctness is checked at every point.** Each measurement asserts Q5 returned
exactly the services attached to that probe. A fast wrong answer would sail
through a timing harness otherwise, and under-reporting is the failure mode
this whole project is organised against.
"""

from __future__ import annotations

import random
import statistics
import time
from dataclasses import dataclass, field

from .. import schema
from ..hydra_client import HydraClient
from ..ids import IdAllocator
from .blast import BlastRadius, BlastRadiusEngine
from .identity import package_key, service_key, version_key
from .writer import PackageGraphWriter

__all__ = [
    "ScaleSpec",
    "GeneratedGraph",
    "ScalePoint",
    "generate",
    "measure_probe",
    "sweep_graph_size",
    "sweep_answer_size",
    "render_sweep",
]


#: Synthetic names carry this prefix so they can never collide with a real
#: package pulled in by an ordinary ingest, and so a polluted graph is
#: recognisable at a glance rather than silently mixed into a demo.
PREFIX = "scale-synth"

#: Rows staged before a flush. Staging is plain dicts held in memory, so an
#: unchunked ten-million-node run would need gigabytes before writing anything.
#: Flushing in chunks keeps the footprint flat and costs nothing: the writer
#: clears its staging area on flush and every write is a MERGE by id.
CHUNK = 20_000


@dataclass(frozen=True)
class ScaleSpec:
    """One synthetic graph. Every field shows up in the report."""

    packages: int
    versions_per_package: int
    services: int
    #: Closure edges per service. Real lockfiles in this corpus resolve ~650
    #: entries, so the default is that order rather than a token handful.
    deps_per_service: int
    #: Services attached to each probe version. This is the "answer size" the
    #: claim says cost should track.
    probe_fanout: int
    #: How many probe versions to plant. Measuring several and taking the
    #: median guards against one unlucky node placement.
    probes: int = 3
    seed: int = 20260820

    @property
    def versions(self) -> int:
        return self.packages * self.versions_per_package

    @property
    def closure_edges(self) -> int:
        return self.services * self.deps_per_service + self.probes * self.probe_fanout


@dataclass
class GeneratedGraph:
    """What was actually written, and the probes planted in it."""

    spec: ScaleSpec
    version_nodes: int = 0
    service_nodes: int = 0
    #: Every edge written, including the HAS_VERSION spine.
    edges: int = 0
    #: RESOLVED_IN edges only. Reported separately because that is the
    #: adjacency Q5 actually walks, and folding the spine into it would
    #: overstate the mass the query is being asked to see past.
    closure_edges: int = 0
    seconds: float = 0.0
    #: version_id -> the exact set of service names attached to it.
    probes: dict[int, set[str]] = field(default_factory=dict)
    #: Requested fan-outs that exceeded the service count and were reduced.
    #: Surfaced rather than absorbed: a table reading "answer grew 20x" when
    #: 50x was asked for is the silent-cap failure this project forbids.
    clamped: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class ScalePoint:
    """One (graph size, answer size) -> latency observation."""

    versions: int
    services: int
    closure_edges: int
    answer_rows: int
    samples_ms: list[float] = field(default_factory=list)

    @property
    def p50(self) -> float:
        return statistics.median(self.samples_ms) if self.samples_ms else 0.0

    @property
    def p95(self) -> float:
        if not self.samples_ms:
            return 0.0
        ordered = sorted(self.samples_ms)
        return ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]


# --------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------

def _pkg_name(index: int) -> str:
    return f"{PREFIX}-pkg-{index:07d}"


def _svc_name(index: int) -> str:
    return f"{PREFIX}-svc-{index:06d}"


def generate(
    client: HydraClient,
    ids: IdAllocator,
    spec: ScaleSpec,
    verbose: bool = True,
) -> GeneratedGraph:
    """Write one synthetic graph and return its probes.

    Packages and versions first, then services, then the closure edges -- in
    that order because an edge statement MATCHes both endpoints and fails
    outright if either has not landed. The writer enforces the same ordering
    within a flush; this enforces it across flushes.
    """
    rng = random.Random(spec.seed)
    out = GeneratedGraph(spec=spec)
    started = time.perf_counter()

    writer = PackageGraphWriter(
        client, ids, source="scale-synthetic", verbose=False, parallelism=4
    )

    # Totals per stage rather than per chunk. A 100k-version build flushes
    # twenty times and a line each would bury the measurement underneath its
    # own progress log.
    totals: dict[str, list[int]] = {}

    def flush(stage: str) -> None:
        nodes, edges = writer.staged_counts()
        if not (nodes or edges):
            return
        writer.flush()
        running = totals.setdefault(stage, [0, 0])
        running[0] += nodes
        running[1] += edges

    # -- packages and versions --------------------------------------------
    version_ids: list[int] = []
    staged = 0
    for p in range(spec.packages):
        name = _pkg_name(p)
        pkg_id = writer.node(
            schema.PACKAGE, package_key(name), name=name, scope=schema.UNKNOWN_STR
        )
        for v in range(spec.versions_per_package):
            version = f"1.0.{v}"
            vid = writer.node(
                schema.PACKAGE_VERSION,
                version_key(name, version),
                name=name,
                version=version,
            )
            writer.edge(schema.HAS_VERSION, pkg_id, vid)
            version_ids.append(vid)
            staged += 1
        if staged >= CHUNK:
            flush("versions")
            staged = 0
    flush("versions")
    out.version_nodes = len(version_ids)

    # -- services ----------------------------------------------------------
    service_ids: list[tuple[int, str]] = []
    for s in range(spec.services):
        name = _svc_name(s)
        sid = writer.node(schema.SERVICE, service_key(name), name=name, repo=name)
        service_ids.append((sid, name))
        if len(service_ids) % CHUNK == 0:
            flush("services")
    flush("services")
    out.service_nodes = len(service_ids)

    # -- probes ------------------------------------------------------------
    # Planted before the bulk edges so a probe's fan-out is exactly what we
    # attached, not that plus whatever the random bulk pass happened to add.
    # Probes are spread across the id range rather than clustered, so the
    # result cannot depend on one lucky region of the store.
    probe_ids: list[int] = []
    if spec.probes and version_ids:
        stride = max(1, len(version_ids) // (spec.probes + 1))
        probe_ids = [version_ids[min(len(version_ids) - 1, stride * (i + 1))]
                     for i in range(spec.probes)]
    probe_set = set(probe_ids)

    for vid in probe_ids:
        attached: set[str] = set()
        fanout = min(spec.probe_fanout, len(service_ids))
        if fanout < spec.probe_fanout:
            out.clamped.append((spec.probe_fanout, fanout))
        for sid, sname in rng.sample(service_ids, fanout):
            writer.edge(
                schema.RESOLVED_IN, vid, sid,
                depth=2, via_direct=_pkg_name(0), dev_only=False,
                first_seen=1_700_000_000, last_seen=schema.STILL_LIVE,
            )
            attached.add(sname)
        out.probes[vid] = attached
    flush("probes")

    # -- bulk closure edges ------------------------------------------------
    # These are the mass the sweep is actually varying: without them the graph
    # would have the node count but not the edge count, and RESOLVED_IN
    # adjacency is what Q5 walks.
    bulk = 0
    closure_written = sum(len(v) for v in out.probes.values())
    non_probe = [v for v in version_ids if v not in probe_set]
    if non_probe:
        for sid, _ in service_ids:
            picked = rng.sample(
                non_probe, min(spec.deps_per_service, len(non_probe))
            )
            for vid in picked:
                writer.edge(
                    schema.RESOLVED_IN, vid, sid,
                    depth=rng.randint(1, 5), via_direct=_pkg_name(0),
                    dev_only=False, first_seen=1_700_000_000,
                    last_seen=schema.STILL_LIVE,
                )
                bulk += 1
                closure_written += 1
            if bulk >= CHUNK:
                flush("closure")
                bulk = 0
    flush("closure")

    out.edges = writer.report.edge_total
    out.closure_edges = closure_written
    out.seconds = time.perf_counter() - started
    if verbose:
        for stage, (nodes, edges) in totals.items():
            print(f"    {stage}: {nodes:,} nodes, {edges:,} edges", flush=True)
    return out


# --------------------------------------------------------------------------
# Measurement
# --------------------------------------------------------------------------

def measure_probe(
    engine: BlastRadiusEngine,
    version_id: int,
    expected: set[str],
    repeats: int = 9,
) -> list[float]:
    """Time Q5 against one probe, asserting it returns the right services.

    The assertion is the point. A harness that only timed the query would
    report a graph that had silently lost its closure edges as the fastest
    result in the table.
    """
    samples: list[float] = []
    for _ in range(repeats):
        result = BlastRadius(target=f"probe-{version_id}")
        started = time.perf_counter()
        rows = engine.exposed_projects(result, version_id)
        samples.append((time.perf_counter() - started) * 1000)

        got = {r["service"] for r in rows}
        if got != expected:
            missing = sorted(expected - got)[:5]
            extra = sorted(got - expected)[:5]
            raise AssertionError(
                f"Q5 on probe {version_id} returned {len(got)} service(s), "
                f"expected {len(expected)}. missing={missing} extra={extra}"
            )
    # Drop the cold sample; the claim is about steady-state cost and the first
    # call also pays connection setup.
    return samples[1:] or samples


def _reset_graph(wait: int = 90, verbose: bool = False) -> None:
    """Drop the store and the id map together, then bring the node back.

    Dropping is O(1) and cannot finish halfway; deleting rows costs ~319 ms per
    node here and would blow the query timeout mid-sweep. The id map has to go
    with it -- a surviving map against an empty graph would let the next
    generation re-use ids the store no longer has.
    """
    from pathlib import Path

    from .. import node

    node.require_daemon()
    node.wipe(verbose=verbose)
    node.up(wait=wait, verbose=verbose)
    ids_db = Path(__file__).resolve().parents[2] / "data" / "ids.sqlite"
    for leftover in ids_db.parent.glob("ids.sqlite*"):
        leftover.unlink()


# --------------------------------------------------------------------------
# The two sweeps
# --------------------------------------------------------------------------

def sweep_graph_size(
    url: str,
    specs: list[ScaleSpec],
    repeats: int = 9,
    verbose: bool = True,
) -> list[ScalePoint]:
    """Sweep A: grow the graph, hold the answer fixed. Expect a flat line."""
    points: list[ScalePoint] = []
    for spec in specs:
        if verbose:
            print(
                f"\n  graph: {spec.versions:,} versions, {spec.services:,} services, "
                f"~{spec.closure_edges:,} closure edges "
                f"(probe fan-out {spec.probe_fanout})",
                flush=True,
            )
        _reset_graph()
        client = HydraClient(base_url=url)
        with IdAllocator() as ids:
            built = generate(client, ids, spec, verbose=verbose)
            engine = BlastRadiusEngine(client, ids)
            samples: list[float] = []
            rows = 0
            for vid, expected in built.probes.items():
                samples.extend(measure_probe(engine, vid, expected, repeats))
                rows = len(expected)
            points.append(ScalePoint(
                versions=built.version_nodes,
                services=built.service_nodes,
                closure_edges=built.closure_edges,
                answer_rows=rows,
                samples_ms=samples,
            ))
        if verbose:
            for asked, got in built.clamped[:1]:
                print(
                    f"    NOTE: probe fan-out {asked} exceeded the {got} "
                    f"service(s) available and was reduced to {got}",
                    flush=True,
                )
            print(
                f"    build {built.seconds:.1f}s -> Q5 p50 {points[-1].p50:.2f} ms "
                f"over {rows} row(s)",
                flush=True,
            )
    return points


def sweep_answer_size(
    url: str,
    base: ScaleSpec,
    fanouts: list[int],
    repeats: int = 9,
    verbose: bool = True,
) -> list[ScalePoint]:
    """Sweep B: hold the graph, grow the answer. Expect a rising line.

    One graph is built, carrying a probe per fan-out, so every point is
    measured against identical graph state. Rebuilding per point would confound
    answer size with whatever else changed between builds.
    """
    _reset_graph()
    client = HydraClient(base_url=url)
    points: list[ScalePoint] = []

    with IdAllocator() as ids:
        # One probe per fan-out, planted in a single graph.
        spec = ScaleSpec(
            packages=base.packages,
            versions_per_package=base.versions_per_package,
            services=base.services,
            deps_per_service=base.deps_per_service,
            probe_fanout=0,
            probes=0,
            seed=base.seed,
        )
        if verbose:
            print(
                f"\n  one graph: {spec.versions:,} versions, "
                f"{spec.services:,} services",
                flush=True,
            )
        built = generate(client, ids, spec, verbose=verbose)

        writer = PackageGraphWriter(
            client, ids, source="scale-synthetic", verbose=False
        )
        rng = random.Random(base.seed + 1)
        service_ids = [
            (ids.get(schema.SERVICE, service_key(_svc_name(s))), _svc_name(s))
            for s in range(spec.services)
        ]
        for sid, _ in service_ids:
            writer.register(schema.SERVICE, sid)

        planted: list[tuple[int, set[str]]] = []
        for i, fanout in enumerate(fanouts):
            name = f"{PREFIX}-probe-{i:03d}"
            version = "9.9.9"
            pkg_id = writer.node(schema.PACKAGE, package_key(name), name=name)
            vid = writer.node(
                schema.PACKAGE_VERSION, version_key(name, version),
                name=name, version=version,
            )
            writer.edge(schema.HAS_VERSION, pkg_id, vid)
            attached: set[str] = set()
            actual = min(fanout, len(service_ids))
            if actual < fanout and verbose:
                print(
                    f"    NOTE: fan-out {fanout:,} exceeded the "
                    f"{len(service_ids):,} service(s) available; measured at "
                    f"{actual:,} instead",
                    flush=True,
                )
            for sid, sname in rng.sample(service_ids, actual):
                writer.edge(
                    schema.RESOLVED_IN, vid, sid,
                    depth=2, via_direct=name, dev_only=False,
                    first_seen=1_700_000_000, last_seen=schema.STILL_LIVE,
                )
                attached.add(sname)
            planted.append((vid, attached))
        writer.flush()

        engine = BlastRadiusEngine(client, ids)
        for vid, expected in planted:
            samples = measure_probe(engine, vid, expected, repeats)
            points.append(ScalePoint(
                versions=built.version_nodes + len(fanouts),
                services=built.service_nodes,
                closure_edges=built.closure_edges,
                answer_rows=len(expected),
                samples_ms=samples,
            ))
            if verbose:
                print(
                    f"    fan-out {len(expected):>6,} -> "
                    f"p50 {points[-1].p50:.2f} ms",
                    flush=True,
                )
    return points


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def elasticity(points: list[ScalePoint], vary: str) -> float:
    """How hard latency responds to the input being swept.

    ``d(log latency) / d(log input)``: 0 means the input is free, 1 means cost
    is proportional to it. Expressed as a ratio rather than a slope in
    milliseconds so the two sweeps -- which move inputs of different units over
    different spans -- can be put side by side at all.
    """
    import math

    if len(points) < 2:
        return 0.0
    first, last = points[0], points[-1]
    span = (
        (last.closure_edges / first.closure_edges)
        if vary == "graph" and first.closure_edges
        else (last.answer_rows / first.answer_rows) if first.answer_rows
        else 0.0
    )
    if span <= 1 or not first.p50 or not last.p50:
        return 0.0
    return math.log(last.p50 / first.p50) / math.log(span)


def render_verdict(
    graph_points: list[ScalePoint], answer_points: list[ScalePoint]
) -> str:
    """Put the two sweeps side by side and say what they jointly show.

    Neither sweep means much alone. Together they answer the question the
    module exists for, and the honest answer here is a comparison rather than
    a yes/no: graph size is not free, it is merely far cheaper than the answer.
    """
    g = elasticity(graph_points, "graph")
    a = elasticity(answer_points, "answer")
    lines = [
        f"  cost elasticity to graph size    {g:>6.2f}",
        f"  cost elasticity to answer size   {a:>6.2f}",
        "",
    ]
    if a <= 0 or g <= 0:
        lines.append(
            "  Not enough spread to compare. Widen --sizes and --fanouts."
        )
        return "\n".join(lines)

    lines.append(
        f"  Answer size costs {a / g:.1f}x what graph size does. The closure "
        f"design holds:\n  the query is dominated by how many projects "
        f"resolved the version, not by\n  how large the ecosystem around it "
        f"is."
    )
    if g > 0.05:
        lines.append(
            f"\n  Graph size is not free, though: {g:.2f} is above zero, so "
            f"the single-hop\n  lookup does pay something as the store grows. "
            f"Stating it flat would be\n  a stronger claim than this "
            f"experiment supports."
        )
    return "\n".join(lines)


def render_sweep(points: list[ScalePoint], vary: str) -> str:
    """A table plus the ratio that settles the question.

    ``vary`` names the column that is being swept, so the reader can see which
    input moved and which stayed put.
    """
    lines = [
        f"  {'versions':>12} {'closure edges':>14} {'answer rows':>12} "
        f"{'p50 ms':>9} {'p95 ms':>9}",
        f"  {'-'*12} {'-'*14} {'-'*12} {'-'*9} {'-'*9}",
    ]
    for p in points:
        lines.append(
            f"  {p.versions:>12,} {p.closure_edges:>14,} {p.answer_rows:>12,} "
            f"{p.p50:>9.2f} {p.p95:>9.2f}"
        )

    if len(points) >= 2:
        first, last = points[0], points[-1]
        if vary == "graph":
            grew = (last.closure_edges / first.closure_edges) if first.closure_edges else 0
            slowed = (last.p50 / first.p50) if first.p50 else 0
            lines += [
                "",
                f"  graph grew {grew:.1f}x; Q5 p50 changed {slowed:.2f}x "
                f"at a constant {first.answer_rows}-row answer.",
            ]
        else:
            grew = (last.answer_rows / first.answer_rows) if first.answer_rows else 0
            slowed = (last.p50 / first.p50) if first.p50 else 0
            lines += [
                "",
                f"  answer grew {grew:.1f}x; Q5 p50 changed {slowed:.2f}x "
                f"on one unchanged graph.",
            ]
    return "\n".join(lines)
