"""The heat model: severity x distance, and the guarantees that hang off it.

These are pure-function tests over `propagate`. The graph reads that feed it
are covered by the live-graph tests in test_oracle.py; what matters here is the
grading itself, because it is the thing the whole UI is drawn from and it is
silent when wrong -- a bad ramp still renders, just in the wrong colour.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.query.exposure import (  # noqa: E402
    DECAY,
    FLOOR,
    SEVERITY_BASE,
    UNRATED_BASE,
    ExposureModel,
    Heat,
    Seed,
    propagate,
    severity_base,
    severity_word,
)


def seed(node_id, severity="high", label=None, advisory="CVE-0"):
    return Seed(
        node_id=node_id,
        label=label or f"pkg{node_id}@1.0.0",
        severity=severity,
        advisory=advisory,
        base=severity_base(severity),
    )


# -- the ramp ---------------------------------------------------------------


@pytest.mark.parametrize(
    "label, expected",
    [
        ("critical", 1.00),
        ("CRITICAL", 1.00),
        ("  High  ", 0.85),
        ("moderate", 0.65),
        ("medium", 0.65),
        ("low", 0.45),
    ],
)
def test_severity_base_known_words(label, expected):
    assert severity_base(label) == expected


def test_unrated_sits_between_low_and_moderate():
    """An advisory nobody rated is still an advisory.

    Folding it to 0 would draw a published finding green, and folding it to
    critical would invent a severity the feed never published.
    """
    assert SEVERITY_BASE["low"] < UNRATED_BASE < SEVERITY_BASE["moderate"]
    for value in (None, "", "  ", "banana", {"type": "null"}, 7):
        assert severity_base(value) == UNRATED_BASE


def test_severity_word_normalises_hydra_nulls():
    assert severity_word({"type": "null"}) == "unknown"
    assert severity_word("") == "unknown"
    assert severity_word("  HIGH ") == "high"


# -- the walk ---------------------------------------------------------------


def test_no_seeds_is_a_clean_graph_not_an_empty_one():
    """Nothing vulnerable must produce heat nowhere, so the UI draws all green."""
    model = propagate([], [(1, 2), (2, 3)])
    assert model.heat == {}
    assert model.worst() is None
    assert model.payload() == {}


def test_exposure_travels_against_the_edges():
    """Edges point importer -> imported; exposure flows the other way.

    Getting this backwards is a silent failure: the walk still runs, still
    marks nodes, and marks precisely the wrong ones -- everything the
    vulnerable package depends on rather than everything that depends on it.
    """
    # app -> lib -> vuln
    model = propagate([seed(3, "critical")], [(1, 2), (2, 3)])
    assert set(model.heat) == {1, 2, 3}
    assert model.heat[3].hops == 0
    assert model.heat[2].hops == 1
    assert model.heat[1].hops == 2
    # and nothing the vulnerable node depends on is implicated
    downstream = propagate([seed(1, "critical")], [(1, 2), (2, 3)])
    assert set(downstream.heat) == {1}


def test_heat_decays_one_step_per_hop():
    model = propagate([seed(4, "critical")], [(1, 2), (2, 3), (3, 4)])
    assert model.heat[4].heat == pytest.approx(1.0)
    assert model.heat[3].heat == pytest.approx(1.0 - DECAY)
    assert model.heat[2].heat == pytest.approx(1.0 - 2 * DECAY)
    assert model.heat[1].heat == pytest.approx(1.0 - 3 * DECAY)


def test_the_radius_stops_at_the_floor():
    """Without a floor the blast radius is the whole graph, which says nothing."""
    chain = [(i, i + 1) for i in range(40)]
    model = propagate([seed(40, "low")], chain)
    assert all(h.heat >= FLOOR for h in model.heat.values())
    assert len(model.heat) < 41


def test_worst_seed_wins_when_two_radii_overlap():
    """A node reached by both a low and a critical finding shows the critical.

    Plain first-visit BFS gets this wrong whenever the queue happens to pop
    the milder seed first, and the result is a genuinely critical exposure
    drawn in yellow.
    """
    edges = [(1, 2), (1, 3)]
    low_first = propagate([seed(2, "low", advisory="CVE-LOW"),
                           seed(3, "critical", advisory="CVE-CRIT")], edges)
    crit_first = propagate([seed(3, "critical", advisory="CVE-CRIT"),
                            seed(2, "low", advisory="CVE-LOW")], edges)
    for model in (low_first, crit_first):
        assert model.heat[1].severity == "critical"
        assert model.heat[1].advisory == "CVE-CRIT"
        assert model.heat[1].heat == pytest.approx(1.0 - DECAY)


def test_severity_outranks_distance_but_does_not_ignore_it():
    """The whole reason the ramp takes two inputs.

    A critical two hops away must still read hotter than a low one at the
    source -- otherwise distance alone decides and severity is decoration.
    But a critical *far* enough away must eventually fall below a near low
    one, or severity alone decides and the radius is decoration.
    """
    near_low = severity_base("low")
    far_critical = severity_base("critical") - 2 * DECAY
    assert far_critical > near_low

    very_far_critical = severity_base("critical") - 6 * DECAY
    assert very_far_critical < near_low


def test_cycles_terminate():
    """A dependency cycle must not hang the walk."""
    model = propagate([seed(1, "high")], [(1, 2), (2, 3), (3, 1)])
    assert set(model.heat) == {1, 2, 3}


def test_payload_is_json_shaped_and_keyed_by_string_id():
    model = propagate([seed(2, "high", label="tar@7.4.3", advisory="CVE-1")], [(1, 2)])
    payload = model.payload()
    assert set(payload) == {"1", "2"}
    assert payload["2"] == {
        "heat": pytest.approx(0.85),
        "hops": 0,
        "severity": "high",
        "source": "tar@7.4.3",
        "advisory": "CVE-1",
    }


def test_offer_keeps_the_hotter_claim():
    model = ExposureModel()
    hot = Heat(heat=0.9, hops=0, severity="critical", source="a", advisory="A")
    cool = Heat(heat=0.3, hops=3, severity="low", source="b", advisory="B")
    assert model.offer(1, cool) is True
    assert model.offer(1, hot) is True
    assert model.offer(1, cool) is False
    assert model.heat[1].severity == "critical"


# --------------------------------------------------------------------------
# Live-graph guards on the defect this module was written to fix
# --------------------------------------------------------------------------


def _live_client():
    from blastradius.hydra_client import HydraClient, HydraError

    client = HydraClient()
    try:
        return client if client.ready() else None
    except HydraError:
        return None


live = pytest.mark.skipif(_live_client() is None, reason="HydraDB is not reachable")


@live
def test_advisories_reach_the_dependency_tree():
    """The join that was empty, asserted.

    Two ingest tiers used to key `PackageVersion` differently -- plain
    `vite@6.3.6` from the lockfile loader, `pkg:npm/vite@6.3.6` from the
    package tier -- so every package version existed twice. Advisories landed
    on one copy, the dependency tree and the code-graph bridge on the other,
    and no query could cross between them. Nothing errored; the product simply
    reported no vulnerabilities anywhere.
    """
    client = _live_client()
    advisories = client.query("MATCH (a:Advisory) RETURN count(*) AS n").rows[0]["n"]
    if not advisories:
        pytest.skip("nothing ingested; run: python -m blastradius.cli pipeline --reset")

    reached = client.query(
        "MATCH (a:Advisory)-[:AFFECTS]->(v:PackageVersion)-[:PRESENT_IN]->(s:Service) "
        "RETURN count(*) AS n"
    ).rows[0]["n"]
    assert reached > 0, (
        "no advisory reaches a project through the dependency tree -- the "
        "advisory tier and the lockfile tier are keying PackageVersion "
        "differently again"
    )


@live
def test_advisories_reach_the_code_graph():
    """The second half of the same join: a CVE must be able to reach a file."""
    client = _live_client()
    if not client.query("MATCH (e:ExternalImport) RETURN count(*) AS n").rows[0]["n"]:
        pytest.skip("no code graph ingested")

    reached = client.query(
        "MATCH (a:Advisory)-[:AFFECTS]->(v:PackageVersion)"
        "<-[:RESOLVES_TO]-(e:ExternalImport) RETURN count(*) AS n"
    ).rows[0]["n"]
    assert reached > 0, (
        "no advisory reaches an imported package -- the ExternalImport bridge "
        "and the AFFECTS edges are landing on different PackageVersion nodes"
    )


@live
def test_no_package_version_is_keyed_two_ways():
    """The id map itself must hold one key per package version."""
    import sqlite3

    from blastradius.ids import DEFAULT_DB

    if not DEFAULT_DB.exists():
        pytest.skip("no id map")
    with sqlite3.connect(DEFAULT_DB) as conn:
        bare = conn.execute(
            "SELECT count(*) FROM ids "
            "WHERE kind = 'PackageVersion' AND key NOT LIKE 'pkg:%'"
        ).fetchone()[0]
        services = [
            row[0] for row in conn.execute("SELECT key FROM ids WHERE kind = 'Service'")
        ]
    assert bare == 0, (
        f"{bare} PackageVersion ids are keyed by a bare name@version rather "
        f"than a purl; every one of them is a duplicate node"
    )
    assert all(key.startswith("svc:") for key in services), (
        f"Service keys disagree between the tiers: {services}"
    )


@live
def test_the_model_grades_the_live_graph():
    """End to end: real advisories produce heat on real nodes, graded by hop."""
    from blastradius.query.exposure import full_exposure

    client = _live_client()
    model = full_exposure(client)
    if not model.seeds:
        pytest.skip("no advisories in the graph")

    assert model.heat, "advisories exist but nothing carries heat"
    # Seeds sit at hop 0; a radius that never leaves its seeds is not a radius.
    hops = {h.hops for h in model.heat.values()}
    assert 0 in hops
    assert max(hops) >= 1, "no advisory propagated past the package it names"
    assert all(0 < h.heat <= 1.0 for h in model.heat.values())


@live
def test_package_view_grades_its_columns():
    """The six-column view must grade, and must not overclaim.

    It is the landing view, so its colours are the first thing anyone reads.
    Two things have to hold at once: the confirmed chain cools as it moves
    right, and the two columns that are explicitly *not* findings stay off the
    ramp entirely. Colouring `RANGE ADMITS` warm would assert the range-only
    guess the whole evidence model exists to replace.
    """
    from blastradius.ids import DEFAULT_DB, IdAllocator
    from blastradius.pkg.graphview import package_graph

    client = _live_client()
    if not DEFAULT_DB.exists():
        pytest.skip("no id map")
    with IdAllocator(DEFAULT_DB) as ids:
        graph = package_graph(client, ids, "vite", "6.3.6")
    if not graph.get("exists"):
        pytest.skip("vite@6.3.6 not ingested")

    by_kind: dict = {}
    for node in graph["nodes"]:
        by_kind.setdefault(node["kind"], []).append(node)

    # every node carries the channel, so the renderer never falls back to 0
    for node in graph["nodes"]:
        assert "heat" in node and "hops" in node and "vuln" in node, node["id"]

    for kind in ("possible", "related"):
        for node in by_kind.get(kind, []):
            assert node["heat"] == 0.0, f"{kind} must stay off the ramp"
            assert node["vuln"] is False

    subject = by_kind.get("compromised") or by_kind.get("subject")
    assert subject, "no target node"
    assert subject[0]["heat"] > 0, "the version the advisories name is not graded"

    # confirmed chain: target (0 hops) -> lockfile (1) -> project (2)
    chain = [subject[0]]
    for kind in ("resolution", "exposed"):
        if by_kind.get(kind):
            chain.append(by_kind[kind][0])
    heats = [n["heat"] for n in chain]
    assert heats == sorted(heats, reverse=True), f"chain does not cool outward: {heats}"


@live
def test_package_view_declares_all_six_columns():
    """An empty column is an answer, so the payload must still declare it."""
    from blastradius.ids import DEFAULT_DB, IdAllocator
    from blastradius.pkg.graphview import COLUMNS, package_graph

    client = _live_client()
    if not DEFAULT_DB.exists():
        pytest.skip("no id map")
    with IdAllocator(DEFAULT_DB) as ids:
        graph = package_graph(client, ids, "axios", "1.12.0")
    if not graph.get("exists"):
        pytest.skip("axios@1.12.0 not ingested")

    assert graph["cols"] == COLUMNS
    # axios is the case that exposed this: nothing's range admits it, so
    # column 2 is empty and used to be dropped from the drawing entirely.
    assert not [n for n in graph["nodes"] if n["layer"] == 2]
    assert len(graph["cols"]) == 6
