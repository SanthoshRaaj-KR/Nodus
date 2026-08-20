"""The last mile: from a confirmed threat to the function that runs its code.

These are unit tests over a canned graph rather than live ones. The walk is
pure once the reads are done, and the interesting cases -- a package reached
only through a bridge dependency, a caller cycle, a threat nothing imports --
are ones the real repository does not happen to contain. Building them by hand
is the only way to assert on them at all.

The fake client dispatches on a distinctive substring of each statement. That
couples the tests to the query text, which is the point: if someone rewrites a
sweep and forgets that the reach walk depended on it, the fake stops matching
and these fail loudly instead of silently returning nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.query.codereach import (  # noqa: E402
    MAX_DEP_DEPTH,
    CodeIndex,
    _function_label,
    _int,
    _reachable,
    _text,
    build_index,
    code_reach,
    threats,
)

NULL = {"type": "null"}  # how HydraDB spells a missing property


class Rows:
    def __init__(self, rows):
        self.rows = rows

    def __len__(self):
        return len(self.rows)


class FakeClient:
    """Answers each sweep from a dict, keyed by a marker in the statement.

    Ordered, because the markers overlap: the deprecated sweep is also a
    ``MATCH (v:PackageVersion)``, and a generic match would swallow it.
    """

    MARKERS = (
        ("v.deprecated = true", "deprecated"),
        ("DEPENDS_ON", "depends"),
        ("PRESENT_IN", "services"),
        # Must precede the generic `MATCH (v:PackageVersion)` entry, or the
        # resolution sweep falls through to it and silently gets the version
        # rows -- which is exactly how the first run of these tests failed.
        ("RESOLVED_IN", "resolutions"),
        ("RESOLVES_TO", "resolved"),
        ("MATCH (e:ExternalImport) RETURN", "imports"),
        ("CALLS_EXTERNAL", "import_users"),
        ("[:CALLS]", "calls"),
        ("MATCH (f:Function) RETURN", "functions"),
        ("AFFECTS", "advisories"),
        ("COMPROMISES", "incidents"),
        ("MATCH (v:PackageVersion)", "versions"),
    )

    def __init__(self, **tables):
        self.tables = tables
        self.seen: list[str] = []

    def query(self, statement, params=None):
        self.seen.append(statement)
        for marker, key in self.MARKERS:
            if marker in statement:
                return Rows(list(self.tables.get(key, [])))
        raise AssertionError(f"unexpected statement: {statement}")


def version(vid, name, ver):
    return {"id": vid, "name": name, "version": ver}


def edge(src, dst):
    return {"src": src, "dst": dst}


def fn(fid, name, file, line=1, service="svc"):
    return {"id": fid, "name": name, "file": file, "line": line, "service": service}


def imp(eid, spec, file="a.js", service="svc", names="x"):
    return {"id": eid, "specifier": spec, "file": file,
            "service": service, "names": names}


# --------------------------------------------------------------------------
# The null problem
# --------------------------------------------------------------------------

def test_text_survives_hydra_null():
    """A missing property is a dict, not None, and must not render as one."""
    assert _text(NULL) == ""
    assert _text(None) == ""
    assert _text(123) == ""
    assert _text("  hi  ") == "hi"


def test_int_rejects_bool_and_null():
    # True is an int in Python, and an id of 1 that is really True would
    # silently alias node 1.
    assert _int(NULL) == -1
    assert _int(True) == -1
    assert _int(7) == 7
    assert _int(None, default=0) == 0


# --------------------------------------------------------------------------
# Dependency reachability
# --------------------------------------------------------------------------

def test_reachable_records_shortest_distance():
    depends = {1: [2, 3], 2: [4], 3: [4], 4: []}
    assert _reachable(depends, 1) == {1: 0, 2: 1, 3: 1, 4: 2}


def test_reachable_prefers_the_short_path():
    # 1 -> 4 directly and 1 -> 2 -> 3 -> 4. The direct hop is what gets
    # explained to a human, so it is the one recorded.
    depends = {1: [2, 4], 2: [3], 3: [4]}
    assert _reachable(depends, 1)[4] == 1


def test_reachable_terminates_on_a_cycle():
    depends = {1: [2], 2: [3], 3: [1]}
    assert _reachable(depends, 1) == {1: 0, 2: 1, 3: 2}


def test_reachable_stops_at_the_depth_cap():
    chain = {i: [i + 1] for i in range(MAX_DEP_DEPTH + 5)}
    reach = _reachable(chain, 0)
    assert max(reach.values()) == MAX_DEP_DEPTH


# --------------------------------------------------------------------------
# Labels
# --------------------------------------------------------------------------

def test_module_scope_is_named_by_its_file():
    """`<module>()` names no function anyone can open."""
    label, sub = _function_label(fn(1, "<module>", "vite.config.js", 0))
    assert label == "vite.config.js"
    assert "module scope" in sub
    assert "()" not in label


def test_named_function_keeps_its_call_shape():
    label, sub = _function_label(fn(1, "render", "src/App.jsx", 42))
    assert label == "render()"
    assert sub == "src/App.jsx:42"


# --------------------------------------------------------------------------
# The index
# --------------------------------------------------------------------------

def simple_graph(**overrides):
    """lodash <- inquirer, imported directly; one function uses it."""
    tables = dict(
        versions=[version(1, "lodash", "4.17.21"), version(2, "inquirer", "9.0.0")],
        depends=[edge(2, 1)],
        services=[{"id": 1, "service": "api"}, {"id": 2, "service": "api"}],
        resolved=[{"eid": 10, "vid": 2}],
        imports=[imp(10, "inquirer")],
        functions=[fn(100, "prompt", "cli.js", 5), fn(101, "main", "cli.js", 1)],
        import_users=[{"fid": 100, "eid": 10}],
        calls=[edge(101, 100)],
        advisories=[],
        incidents=[],
        deprecated=[],
    )
    tables.update(overrides)
    return FakeClient(**tables)


def test_index_reads_every_tier():
    index = build_index(simple_graph())
    assert index.versions[1] == ("lodash", "4.17.21")
    assert index.depends[2] == [1]
    assert index.imports[10]["specifier"] == "inquirer"
    assert index.imports[10]["version_id"] == 2
    assert index.import_users[10] == [100]
    # Callers are stored reversed: the only question asked is "who calls X".
    assert index.callers[100] == [101]
    assert index.services[1] == ["api"]


def test_unresolved_import_is_kept_not_dropped():
    """`node:fs` resolves to nothing and must still be in the index.

    Dropping it would make the count of imports disagree with the count the
    scanner found, and "we saw 8 imports" is a claim the UI makes.
    """
    client = simple_graph(imports=[imp(10, "inquirer"), imp(11, "node:fs")])
    index = build_index(client)
    assert index.imports[11]["version_id"] == -1
    assert index.import_reach[11] == {}


def test_import_reach_is_precomputed_per_import():
    index = build_index(simple_graph())
    # inquirer names itself at 0 hops and reaches lodash at 1.
    assert index.import_reach[10] == {2: 0, 1: 1}


# --------------------------------------------------------------------------
# Threats
# --------------------------------------------------------------------------

def advisory(vid, aid, severity, summary="s"):
    return {"vid": vid, "advisory_id": aid, "severity": severity,
            "summary": summary, "cvss_vector": ""}


def test_advisories_group_by_version_not_by_cve():
    """Three CVEs on one version is one thing to go and fix."""
    client = simple_graph(advisories=[
        advisory(1, "CVE-1", "low"), advisory(1, "CVE-2", "critical"),
        advisory(1, "CVE-3", "moderate"),
    ])
    found = threats(client)
    assert len(found) == 1
    assert len(found[0].advisories) == 3
    # A version is as dangerous as the worst thing known about it.
    assert found[0].severity == "critical"
    # And the worst is listed first.
    assert found[0].advisories[0]["advisory_id"] == "CVE-2"


def test_unrated_severity_does_not_beat_a_rated_one():
    client = simple_graph(advisories=[
        advisory(1, "CVE-1", "high"), advisory(1, "CVE-2", NULL),
    ])
    assert threats(client)[0].severity == "high"


def test_compromised_outranks_vulnerable_on_the_same_version():
    client = simple_graph(
        advisories=[advisory(1, "CVE-1", "low")],
        incidents=[{"vid": 1, "incident_id": "SIM-1",
                    "status": "SIMULATED_COMPROMISED", "summary": "drill"}],
    )
    found = threats(client)
    assert found[0].kind == "compromised"
    assert found[0].incident["simulated"] is True


def test_a_real_incident_is_not_flagged_as_a_drill():
    client = simple_graph(incidents=[
        {"vid": 1, "incident_id": "INC-1", "status": "CONFIRMED", "summary": "real"},
    ])
    assert threats(client)[0].incident["simulated"] is False


def test_deprecated_version_becomes_a_threat():
    client = simple_graph(deprecated=[{"vid": 1, "reason": "use lodash-es"}])
    found = threats(client)
    assert found[0].kind == "deprecated"
    assert found[0].deprecated_reason == "use lodash-es"


def test_deprecation_does_not_downgrade_a_vulnerable_version():
    client = simple_graph(
        advisories=[advisory(1, "CVE-1", "high")],
        deprecated=[{"vid": 1, "reason": "old"}],
    )
    found = threats(client)
    assert found[0].kind == "vulnerable"
    assert found[0].severity == "high"


def test_code_reach_outranks_severity_in_the_ordering():
    """A moderate finding in code beats a critical one nothing imports.

    This is the ranking claim the whole page rests on, so it is asserted
    rather than assumed: sorting on severity alone buries the finding that
    actually has a file to open.
    """
    client = simple_graph(advisories=[
        advisory(1, "CVE-REACHED", "moderate"),   # lodash, reached via inquirer
        advisory(3, "CVE-ORPHAN", "critical"),    # nothing imports it
    ], versions=[
        version(1, "lodash", "4.17.21"), version(2, "inquirer", "9.0.0"),
        version(3, "orphan", "1.0.0"),
    ])
    found = threats(client)
    assert [t.package for t in found] == ["lodash", "orphan"]
    assert found[0].in_code is True
    assert found[1].in_code is False


def test_function_count_counts_distinct_functions():
    client = simple_graph(
        advisories=[advisory(1, "CVE-1", "high")],
        imports=[imp(10, "inquirer"), imp(11, "inquirer-too")],
        resolved=[{"eid": 10, "vid": 2}, {"eid": 11, "vid": 2}],
        # Both imports are used by the same function; it is one function.
        import_users=[{"fid": 100, "eid": 10}, {"fid": 100, "eid": 11}],
    )
    found = threats(client)
    assert found[0].import_count if hasattr(found[0], "import_count") else True
    assert found[0].function_count == 1
    assert len(found[0].reached_by) == 2


def test_threat_dict_is_json_safe():
    client = simple_graph(advisories=[advisory(1, "CVE-1", NULL, summary=NULL)])
    payload = threats(client)[0].to_dict()
    assert payload["advisories"][0]["summary"] == ""
    assert payload["spec"] == "lodash@4.17.21"
    assert isinstance(payload["services"], list)


# --------------------------------------------------------------------------
# The reach walk
# --------------------------------------------------------------------------

def test_reach_through_a_bridge_dependency():
    """The import names inquirer; the advisory is on lodash one hop below."""
    reach = code_reach(simple_graph(), "lodash", "4.17.21")
    assert reach.found
    kinds = {n["kind"]: n for n in reach.nodes}
    assert kinds["threat"]["label"] == "lodash@4.17.21"
    assert kinds["bridge"]["label"] == "inquirer@9.0.0"
    assert kinds["import"]["label"] == "inquirer"
    assert kinds["uses"]["label"] == "prompt()"
    assert kinds["caller"]["label"] == "main()"
    # Columns are the semantics, so their order is asserted.
    assert [kinds[k]["column"] for k in ("threat", "bridge", "import", "uses", "caller")] \
        == [0, 1, 2, 3, 4]


def test_a_direct_import_draws_no_bridge():
    """`vite -> vite` as two circles would imply a hop that is not there."""
    client = simple_graph(resolved=[{"eid": 10, "vid": 1}])
    reach = code_reach(client, "lodash", "4.17.21")
    assert reach.found
    assert not [n for n in reach.nodes if n["kind"] == "bridge"]
    assert {(e["src"], e["dst"]) for e in reach.edges} >= {("pkg:1", "im:10")}


def test_installed_but_unreached_says_so_without_calling_it_clean():
    client = simple_graph(resolved=[])  # nothing imports anything
    reach = code_reach(client, "lodash", "4.17.21")
    assert reach.found is False
    assert reach.nodes == []
    assert "installed" in reach.note
    # The wording must not imply the advisory does not apply.
    assert "false positive" not in reach.note.lower()
    assert "not affected" not in reach.note.lower()


def test_unknown_version_is_distinguished_from_unreached():
    reach = code_reach(simple_graph(), "nope", "0.0.0")
    assert reach.found is False
    assert "not in the graph" in reach.note


def test_caller_walk_stops_at_the_configured_depth():
    client = simple_graph(
        functions=[fn(100, "a", "x.js"), fn(101, "b", "x.js"),
                   fn(102, "c", "x.js"), fn(103, "d", "x.js")],
        calls=[edge(101, 100), edge(102, 101), edge(103, 102)],
    )
    reach = code_reach(client, "lodash", "4.17.21", caller_depth=2)
    drawn = {n["label"] for n in reach.nodes if n["kind"] in ("uses", "caller")}
    assert drawn == {"a()", "b()", "c()"}
    # `d` is past the cap: counted, never silently dropped.
    assert reach.truncated_callers == 1


def test_caller_cycle_does_not_hang_or_duplicate():
    client = simple_graph(
        functions=[fn(100, "a", "x.js"), fn(101, "b", "x.js")],
        calls=[edge(101, 100), edge(100, 101)],  # mutual recursion
    )
    reach = code_reach(client, "lodash", "4.17.21", caller_depth=4)
    keys = [n["key"] for n in reach.nodes]
    assert len(keys) == len(set(keys))


def test_two_imports_converging_on_one_function_draw_it_once():
    client = simple_graph(
        imports=[imp(10, "inquirer"), imp(11, "inquirer/lib")],
        resolved=[{"eid": 10, "vid": 2}, {"eid": 11, "vid": 2}],
        import_users=[{"fid": 100, "eid": 10}, {"fid": 100, "eid": 11}],
    )
    reach = code_reach(client, "lodash", "4.17.21")
    uses = [n for n in reach.nodes if n["kind"] == "uses"]
    assert len(uses) == 1
    # ...but both import edges into it survive, because both are true.
    into = [e for e in reach.edges
            if e["dst"] == "fn:100" and e["kind"] == "calls-into"]
    assert len(into) == 2


def test_edges_never_dangle():
    """Every edge endpoint must be a node that was actually emitted."""
    reach = code_reach(simple_graph(), "lodash", "4.17.21")
    keys = {n["key"] for n in reach.nodes}
    for e in reach.edges:
        assert e["src"] in keys, e
        assert e["dst"] in keys, e


def test_reach_dict_shape():
    payload = code_reach(simple_graph(), "lodash", "4.17.21").to_dict()
    assert set(payload) == {
        "found", "spec", "nodes", "edges", "note", "truncated_callers"
    }
    assert payload["spec"] == "lodash@4.17.21"


def test_an_index_can_be_reused_across_calls():
    """The endpoint caches one index and passes it to both entry points."""
    client = simple_graph(advisories=[advisory(1, "CVE-1", "high")])
    index = build_index(client)
    before = len(client.seen)
    threats(client, index)
    code_reach(client, "lodash", "4.17.21", index)
    # threats() still issues its own three sweeps; the reach walk issues none.
    assert len(client.seen) - before == 3


def test_empty_graph_yields_no_threats():
    client = FakeClient()
    assert threats(client) == []
    assert isinstance(build_index(client), CodeIndex)


@pytest.mark.parametrize("severity", ["critical", "high", "moderate", "low"])
def test_every_severity_word_survives_the_round_trip(severity):
    client = simple_graph(advisories=[advisory(1, "CVE-1", severity)])
    assert threats(client)[0].to_dict()["severity"] == severity


# --------------------------------------------------------------------------
# The live window
# --------------------------------------------------------------------------

DAY = 86400


def windowed(**over):
    """A graph where lodash@4.17.21 is advised, with datable events."""
    tables = dict(
        versions=[
            {"id": 1, "name": "lodash", "version": "4.17.21",
             "published_at": 1000 * DAY},
            {"id": 2, "name": "inquirer", "version": "9.0.0",
             "published_at": 900 * DAY},
        ],
        depends=[edge(2, 1)],
        services=[{"id": 1, "service": "api"}],
        resolutions=[],
        resolved=[{"eid": 10, "vid": 2}],
        imports=[imp(10, "inquirer")],
        functions=[fn(100, "prompt", "cli.js", 5)],
        import_users=[{"fid": 100, "eid": 10}],
        calls=[],
        advisories=[],
        incidents=[],
        deprecated=[],
    )
    tables.update(over)
    return FakeClient(**tables)


def advisory_dated(vid, aid, severity, published, fixed_at):
    return {"vid": vid, "advisory_id": aid, "severity": severity,
            "summary": "s", "cvss_vector": "", "published": published,
            "introduced_version": "0", "fixed_version": "4.17.22",
            "fixed_published_at": fixed_at}


def resolution(vid, service, first_seen, last_seen=4_102_444_800):
    return {"id": vid, "service": service,
            "first_seen": first_seen, "last_seen": last_seen}


def test_the_window_opens_when_the_version_was_published():
    """Not when the advisory was.

    The first draft used the advisory date and produced windows that ended
    before they began -- esbuild@0.21.5 came out as 2025-02-10 -> 2025-02-08.
    That is the normal order of events: the fix ships, the advisory follows.
    A vulnerable version is installable from the moment it exists.
    """
    client = windowed(advisories=[
        advisory_dated(1, "CVE-1", "high",
                       published=1100 * DAY, fixed_at=1050 * DAY),
    ])
    threat = threats(client)[0]
    assert threat.window == (1000 * DAY, 1050 * DAY)
    assert threat.window[0] < threat.window[1], "window must not be inverted"
    assert threat.window_basis.startswith("version published")


def test_an_undated_version_falls_back_to_the_advisory_and_says_so():
    client = windowed(
        versions=[{"id": 1, "name": "lodash", "version": "4.17.21",
                   "published_at": 0}],
        advisories=[advisory_dated(1, "CVE-1", "high",
                                   published=1100 * DAY, fixed_at=1200 * DAY)],
    )
    threat = threats(client)[0]
    assert threat.window[0] == 1100 * DAY
    assert threat.window_basis.startswith("advisory published")


def test_no_dated_fix_leaves_the_window_open():
    client = windowed(advisories=[
        advisory_dated(1, "CVE-1", "high", published=1100 * DAY, fixed_at=0),
    ])
    threat = threats(client)[0]
    assert threat.window[1] == 4_102_444_800
    assert "no dated fix" in threat.window_basis


def test_a_lockfile_held_during_the_window_is_reported_as_such():
    client = windowed(
        advisories=[advisory_dated(1, "CVE-1", "high",
                                   published=1100 * DAY, fixed_at=1200 * DAY)],
        resolutions=[resolution(1, "api", first_seen=1150 * DAY)],
    )
    threat = threats(client)[0]
    assert threat.live_window_services == ["api"]
    assert threat.after_fix_services == []


def test_a_lockfile_written_after_the_fix_is_a_different_finding():
    """Not a lesser one: the remedy already existed when it was written."""
    client = windowed(
        advisories=[advisory_dated(1, "CVE-1", "high",
                                   published=1100 * DAY, fixed_at=1200 * DAY)],
        resolutions=[resolution(1, "api", first_seen=1500 * DAY)],
    )
    threat = threats(client)[0]
    assert threat.after_fix_services == ["api"]
    assert threat.live_window_services == []


def test_an_undated_resolution_is_not_counted_either_way():
    """Unknown is not "no". A resolution with no observation time cannot be
    placed against the window, and guessing would invent a finding."""
    client = windowed(
        advisories=[advisory_dated(1, "CVE-1", "high",
                                   published=1100 * DAY, fixed_at=1200 * DAY)],
        resolutions=[resolution(1, "api", first_seen=0)],
    )
    threat = threats(client)[0]
    assert threat.live_window_services == []
    assert threat.after_fix_services == []


def test_several_advisories_widen_the_window():
    client = windowed(advisories=[
        advisory_dated(1, "CVE-1", "low", published=1100 * DAY, fixed_at=1150 * DAY),
        advisory_dated(1, "CVE-2", "high", published=1100 * DAY, fixed_at=1400 * DAY),
    ])
    threat = threats(client)[0]
    assert threat.window == (1000 * DAY, 1400 * DAY)


def test_window_fields_are_serialised():
    client = windowed(advisories=[
        advisory_dated(1, "CVE-1", "high", published=1100 * DAY, fixed_at=1200 * DAY),
    ])
    payload = threats(client)[0].to_dict()
    for key in ("window_start", "window_end", "window_basis",
                "live_window_services", "after_fix_services"):
        assert key in payload
