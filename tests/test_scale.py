"""The scale harness, and the guard that makes its numbers mean anything.

The harness exists to settle whether Q5 costs what `PACKAGE-GRAPH.md` claims,
so the thing most worth testing is not the timing -- it is the correctness
assertion inside `measure_probe`. A benchmark that reports a number regardless
of whether the query answered correctly would rate an empty graph as the
fastest configuration available, and "fast because it found nothing" is the
exact failure this project is organised against.

The live tests build deliberately tiny graphs. Their job is to prove the
generator writes what it says it writes and that the probe assertion is wired
to real query output; the actual sweep is a CLI command, not a unit test,
because resetting the store per point is far too destructive to run in a suite.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.pkg import scale  # noqa: E402
from blastradius.pkg.identity import normalize_name  # noqa: E402


def _live_client():
    from blastradius.hydra_client import HydraClient, HydraError

    client = HydraClient()
    try:
        return client if client.ready() else None
    except HydraError:
        return None


#: The live tests here DROP THE STORE. There is no other way to measure against
#: a graph of a known size, but it means a plain `pytest tests/` would silently
#: destroy whatever the developer had ingested and leave synthetic rows in its
#: place -- and because these sort after `test_exposure.py`, the damage would
#: land *after* the tests that would have caught it, so the suite would still
#: come out green. Opt in explicitly:
#:
#:     BLASTRADIUS_DESTRUCTIVE_TESTS=1 python -m pytest tests/test_scale.py
#:
#: Rebuild afterwards with `python -m blastradius.cli pipeline --reset`.
DESTRUCTIVE = os.environ.get("BLASTRADIUS_DESTRUCTIVE_TESTS") == "1"

live = pytest.mark.skipif(
    _live_client() is None or not DESTRUCTIVE,
    reason=(
        "needs HydraDB and BLASTRADIUS_DESTRUCTIVE_TESTS=1 (these tests drop "
        "the store)"
    ),
)


# -- the spec arithmetic ----------------------------------------------------


def test_spec_reports_what_it_will_build():
    """The report quotes these before building, so they have to be right."""
    spec = scale.ScaleSpec(
        packages=100, versions_per_package=4, services=10,
        deps_per_service=50, probe_fanout=3, probes=2,
    )
    assert spec.versions == 400
    # bulk edges plus the probe edges, which are planted separately
    assert spec.closure_edges == 10 * 50 + 2 * 3


def test_synthetic_names_are_valid_package_names():
    """A name the registry would reject would fail at key construction.

    Not cosmetic: `package_key` normalises through npm's own rules, so an
    invalid generated name aborts the run partway through a sweep rather than
    at the start.
    """
    for i in (0, 1, 999_999):
        assert normalize_name(scale._pkg_name(i)) == scale._pkg_name(i)
    assert scale.PREFIX in scale._pkg_name(0)
    assert scale.PREFIX in scale._svc_name(0)


# -- percentile handling ----------------------------------------------------


def test_point_percentiles():
    p = scale.ScalePoint(
        versions=1, services=1, closure_edges=1, answer_rows=1,
        samples_ms=[5.0, 1.0, 3.0, 2.0, 4.0],
    )
    assert p.p50 == 3.0
    assert p.p95 == 5.0


def test_empty_point_does_not_divide_by_zero():
    """A point with no samples renders as zero rather than raising.

    It happens when a probe is skipped, and a crash in the reporting layer
    would throw away the measurements that did succeed.
    """
    p = scale.ScalePoint(versions=0, services=0, closure_edges=0, answer_rows=0)
    assert p.p50 == 0.0
    assert p.p95 == 0.0
    assert scale.render_sweep([p], "graph")


def test_render_states_which_input_moved():
    """The conclusion line is the output; it must name the right ratio."""
    points = [
        scale.ScalePoint(versions=100, services=5, closure_edges=1_000,
                         answer_rows=3, samples_ms=[2.0]),
        scale.ScalePoint(versions=1_000, services=5, closure_edges=10_000,
                         answer_rows=3, samples_ms=[2.0]),
    ]
    graph = scale.render_sweep(points, "graph")
    assert "graph grew 10.0x" in graph
    assert "1.00x" in graph

    answers = [
        scale.ScalePoint(versions=100, services=5, closure_edges=1_000,
                         answer_rows=2, samples_ms=[2.0]),
        scale.ScalePoint(versions=100, services=5, closure_edges=1_000,
                         answer_rows=20, samples_ms=[8.0]),
    ]
    assert "answer grew 10.0x" in scale.render_sweep(answers, "answer")


# -- elasticity, which is what the verdict is read off ----------------------


def _pts(pairs, vary):
    """(input, latency) -> points varying either graph or answer size."""
    return [
        scale.ScalePoint(
            versions=1_000,
            services=10,
            closure_edges=size if vary == "graph" else 1_000,
            answer_rows=5 if vary == "graph" else size,
            samples_ms=[ms],
        )
        for size, ms in pairs
    ]


def test_elasticity_of_a_free_input_is_zero():
    """Latency unchanged across a 100x sweep means the input costs nothing."""
    pts = _pts([(1_000, 2.0), (100_000, 2.0)], "graph")
    assert scale.elasticity(pts, "graph") == pytest.approx(0.0)


def test_elasticity_of_a_proportional_input_is_one():
    """Latency tracking the input exactly is the other anchor of the scale."""
    pts = _pts([(10, 1.0), (1_000, 100.0)], "answer")
    assert scale.elasticity(pts, "answer") == pytest.approx(1.0)


def test_elasticity_is_degenerate_without_spread():
    """One point, or no growth, cannot support a conclusion."""
    assert scale.elasticity([], "graph") == 0.0
    assert scale.elasticity(_pts([(10, 1.0)], "graph"), "graph") == 0.0
    assert scale.elasticity(_pts([(10, 1.0), (10, 2.0)], "answer"), "answer") == 0.0


def test_verdict_refuses_to_conclude_without_data():
    """Better to say the sweep was too narrow than to publish a ratio of zeros."""
    text = scale.render_verdict([], [])
    assert "Not enough spread" in text


def test_verdict_states_the_comparison_and_the_caveat():
    """The finding is the ratio; the caveat is that graph size is not free."""
    graph = _pts([(2_000, 1.0), (200_000, 1.89)], "graph")
    answer = _pts([(1, 1.62), (1_000, 61.46)], "answer")
    text = scale.render_verdict(graph, answer)
    assert "Answer size costs" in text
    # graph elasticity is clearly above zero here, so the caveat must appear
    assert "not free" in text


def test_verdict_omits_the_caveat_when_graph_size_really_is_free():
    """A genuinely flat line should not be talked down."""
    graph = _pts([(2_000, 2.00), (200_000, 2.01)], "graph")
    answer = _pts([(1, 1.0), (1_000, 60.0)], "answer")
    text = scale.render_verdict(graph, answer)
    assert "Answer size costs" in text
    assert "not free" not in text


# -- the live half ----------------------------------------------------------


@live
def test_generate_writes_exactly_what_the_spec_asked_for():
    """Node and edge counts are the spec's arithmetic, not an approximation."""
    from blastradius.hydra_client import HydraClient
    from blastradius.ids import IdAllocator

    scale._reset_graph(verbose=False)
    client = HydraClient()
    spec = scale.ScaleSpec(
        packages=8, versions_per_package=2, services=4,
        deps_per_service=3, probe_fanout=2, probes=2,
    )
    with IdAllocator() as ids:
        built = scale.generate(client, ids, spec, verbose=False)

    assert built.version_nodes == spec.versions == 16
    assert built.service_nodes == 4
    assert len(built.probes) == 2
    for attached in built.probes.values():
        assert len(attached) == 2


@live
def test_probe_assertion_rejects_a_wrong_answer():
    """The guard that makes the timing trustworthy.

    Three ways to be wrong, because they fail differently: a completely
    unrelated expectation, a strict subset (the under-report that looks like
    safety), and a node that is not in the graph at all.
    """
    from blastradius.hydra_client import HydraClient
    from blastradius.ids import IdAllocator
    from blastradius.pkg.blast import BlastRadiusEngine

    scale._reset_graph(verbose=False)
    client = HydraClient()
    spec = scale.ScaleSpec(
        packages=6, versions_per_package=2, services=5,
        deps_per_service=2, probe_fanout=3, probes=1,
    )
    with IdAllocator() as ids:
        built = scale.generate(client, ids, spec, verbose=False)
        engine = BlastRadiusEngine(client, ids)
        version_id, expected = next(iter(built.probes.items()))

        # The truthful expectation passes and yields one sample per repeat
        # beyond the discarded cold one.
        samples = scale.measure_probe(engine, version_id, expected, repeats=3)
        assert len(samples) == 2
        assert all(s > 0 for s in samples)

        with pytest.raises(AssertionError):
            scale.measure_probe(engine, version_id, {"nonexistent"}, repeats=2)

        subset = set(sorted(expected)[:1])
        with pytest.raises(AssertionError):
            scale.measure_probe(engine, version_id, subset, repeats=2)

        with pytest.raises(AssertionError):
            scale.measure_probe(engine, 987_654_321, {"anything"}, repeats=2)


@live
def test_closure_edges_are_counted_apart_from_the_spine():
    """The reported closure count must exclude HAS_VERSION.

    The sweep table labels that column "closure edges" and the conclusion is
    read off it. Folding the version spine in would overstate the mass Q5 is
    being asked to see past, making the flat line look more impressive than
    the experiment earned.
    """
    from blastradius.hydra_client import HydraClient
    from blastradius.ids import IdAllocator

    scale._reset_graph(verbose=False)
    client = HydraClient()
    spec = scale.ScaleSpec(
        packages=10, versions_per_package=2, services=5,
        deps_per_service=4, probe_fanout=2, probes=2,
    )
    with IdAllocator() as ids:
        built = scale.generate(client, ids, spec, verbose=False)

    # 5 services x 4 deps, plus 2 probes x 2 attached services.
    assert built.closure_edges == 5 * 4 + 2 * 2
    # The spine adds one HAS_VERSION per version on top of that.
    assert built.edges == built.closure_edges + spec.versions
    assert built.closure_edges < built.edges


@live
def test_clamped_fanout_is_reported_not_absorbed():
    """Asking for more services than exist must leave a trace.

    A run that quietly measured 5 rows when 500 were requested would publish a
    conclusion about an answer size that never existed.
    """
    from blastradius.hydra_client import HydraClient
    from blastradius.ids import IdAllocator

    scale._reset_graph(verbose=False)
    client = HydraClient()
    spec = scale.ScaleSpec(
        packages=6, versions_per_package=2, services=3,
        deps_per_service=2, probe_fanout=500, probes=1,
    )
    with IdAllocator() as ids:
        built = scale.generate(client, ids, spec, verbose=False)

    assert built.clamped, "a reduced fan-out must be recorded"
    asked, got = built.clamped[0]
    assert asked == 500
    assert got == 3
    assert all(len(v) == 3 for v in built.probes.values())


@live
def test_generation_is_deterministic_for_a_seed():
    """Two runs of one seed must plant identical probes.

    A sweep compares points built in separate runs, so a generator that
    reshuffled between them would attribute its own randomness to graph size.
    """
    from blastradius.hydra_client import HydraClient
    from blastradius.ids import IdAllocator

    spec = scale.ScaleSpec(
        packages=6, versions_per_package=2, services=6,
        deps_per_service=2, probe_fanout=3, probes=2, seed=1234,
    )
    seen = []
    for _ in range(2):
        scale._reset_graph(verbose=False)
        client = HydraClient()
        with IdAllocator() as ids:
            built = scale.generate(client, ids, spec, verbose=False)
            seen.append({k: sorted(v) for k, v in sorted(built.probes.items())})
    assert seen[0] == seen[1]
