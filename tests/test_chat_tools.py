"""The facts the chatbot is allowed to state, asserted without a model.

Two halves. The pure ones -- version arithmetic, capping, sentinel handling --
run anywhere and cover the logic most likely to produce a confidently wrong
answer. The live ones run only when HydraDB is up and something is ingested,
and they pin the two properties the whole feature rests on: workspaces do not
leak into each other, and an unbuilt code graph is never reported as safety.

None of this needs an API key. That is deliberate -- the correctness of a
supply-chain assistant lives in the tool layer, and a test suite that could
only run with a credential would not be run.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.chat import tools as T  # noqa: E402
from blastradius.chat.workspaces import Workspace, WorkspaceRegistry  # noqa: E402

NULL = {"type": "null"}  # how HydraDB spells a missing property


# --------------------------------------------------------------------------
# pure logic -- no graph, no key
# --------------------------------------------------------------------------


def test_null_sentinel_becomes_a_plain_default():
    """`{"type":"null"}` reaching the model gets described as a value.

    A model shown that object under `fixed_version` will cheerfully report it
    as the fix.
    """
    assert T._clean(NULL) == ""
    assert T._clean(NULL, -1) == -1
    assert T._clean(None) == ""
    assert T._clean("4.17.21") == "4.17.21"
    assert T._clean(0, "x") == 0


def test_split_spec_keeps_scoped_names_intact():
    assert T.split_spec("lodash@4.17.21") == ("lodash", "4.17.21")
    assert T.split_spec("@babel/core@7.1.0") == ("@babel/core", "7.1.0")
    assert T.split_spec("lodash") == ("lodash", "")
    assert T.split_spec("") == ("", "")


def test_cap_reports_what_it_left_out():
    kept, omitted = T._cap([1, 2, 3, 4, 5], 3)
    assert (kept, omitted) == ([1, 2, 3], 2)
    assert T._cap([1, 2], 5) == ([1, 2], 0)


def test_joined_fixed_versions_are_split():
    """OSV fixes arrive joined: uuid ships as one `"11.1.1; 12.0.1; 13.0.1"`.

    Left alone that string becomes the target of a generated
    `npm install uuid@11.1.1; 12.0.1; 13.0.1` -- wrong, and with the
    semicolons, a shell command nobody asked for.
    """
    assert T._split_versions(["11.1.1; 12.0.1; 13.0.1"]) == ["11.1.1", "12.0.1", "13.0.1"]
    assert T._split_versions(["1.0.0, 2.0.0"]) == ["1.0.0", "2.0.0"]
    assert T._split_versions([]) == []
    assert T._split_versions(None) == []


def test_fixed_versions_sort_semantically_not_alphabetically():
    assert T._split_versions(["10.0.0", "9.0.0", "2.0.0"]) == ["2.0.0", "9.0.0", "10.0.0"]


def test_unparseable_versions_sort_last_and_survive():
    out = T._split_versions(["not-a-version", "1.0.0"])
    assert out[0] == "1.0.0"
    assert "not-a-version" in out


# -- the downgrade bug, pinned ---------------------------------------------


def test_recommended_fix_never_downgrades():
    """The bug this function exists for.

    OSV lists a fixed version per affected *branch*, so one advisory on
    `vite@5.4.21` reports 0.1.24, 2.14.1, 6.4.3, 7.3.5 and 8.0.16 together.
    Taking the lowest -- the obvious "smallest upgrade" reading -- recommends
    a five-major downgrade onto a branch that was never patched.
    """
    assert T.recommended_fix(
        "5.4.21", ["0.1.24", "2.14.1", "6.4.3", "7.3.5", "8.0.16"]
    ) == "6.4.3"


def test_recommended_fix_takes_the_smallest_real_upgrade():
    assert T.recommended_fix("8.3.2", ["11.1.1", "12.0.1", "13.0.1"]) == "11.1.1"
    assert T.recommended_fix("4.17.21", ["4.17.21", "4.17.23", "4.18.0"]) == "4.17.23"


def test_recommended_fix_is_empty_when_nothing_moves_forward():
    """A real answer: the installed branch has no published patch.

    Empty is what makes `remediation_plan` say so instead of inventing a bump.
    """
    assert T.recommended_fix("9.0.0", ["1.2.3", "2.0.0"]) == ""
    assert T.recommended_fix("1.0.0", []) == ""


def test_recommended_fix_excludes_the_installed_version_itself():
    assert T.recommended_fix("4.17.21", ["4.17.21"]) == ""


# -- path rendering --------------------------------------------------------


def test_path_properties_are_unwrapped_from_their_type_tags():
    """`algo.MSpaths` returns whole nodes, and their properties arrive tagged."""
    node = {"id": 7, "labels": ["PackageVersion"],
            "properties": {"name": {"String": "fastify"},
                           "version": {"String": "4.29.1"}}}
    assert T._prop(node, "name") == "fastify"
    assert T._prop(node, "missing") == ""
    assert T._node_label(node) == "fastify@4.29.1"


def test_a_service_node_is_labelled_by_its_name():
    node = {"id": 3, "labels": ["Service"], "properties": {"name": {"String": "orm-backend"}}}
    assert T._node_label(node) == "orm-backend"


def test_dependency_chains_read_as_names_not_node_ids():
    """The regression this guards.

    Reading tagged properties like a flat dict yields nothing, so every label
    fell through to the node id and the one answer a human most wants to read
    -- why is this package here at all -- came out as
    `200000488 -> 200000474 -> 100000014`.
    """
    path = {"nodes": [
        {"id": 1, "labels": ["PackageVersion"],
         "properties": {"name": {"String": "uuid"}, "version": {"String": "8.3.2"}}},
        {"id": 2, "labels": ["PackageVersion"],
         "properties": {"name": {"String": "sequelize"}, "version": {"String": "6.37.8"}}},
        {"id": 3, "labels": ["Service"], "properties": {"name": {"String": "orm-backend"}}},
    ]}
    assert T._render_path(path) == "uuid@8.3.2 -> sequelize@6.37.8 -> orm-backend"


def test_render_path_survives_an_unexpected_shape():
    """A changed engine shape must shorten the answer, not fail the question."""
    assert T._render_path({"nodes": []}) == ""
    assert T._render_path(None) == "None"
    assert isinstance(T._render_path({"nodes": [{"id": 9, "labels": []}]}), str)


# --------------------------------------------------------------------------
# live graph
# --------------------------------------------------------------------------


def _live():
    from blastradius.hydra_client import HydraClient, HydraError

    try:
        client = HydraClient()
        return client if client.ready() else None
    except HydraError:
        return None


live = pytest.mark.skipif(_live() is None, reason="HydraDB is not reachable")


def _scopes():
    """Every registered chatbot as a Scope, or an empty list."""
    from blastradius.hydra_client import HydraClient
    from blastradius.ids import IdAllocator

    client, ids = HydraClient(), IdAllocator()
    return [
        T.Scope(client=client, ids=ids, workspace=w)
        for w in WorkspaceRegistry().list()
        if w.service_ids
    ]


@live
def test_workspace_packages_stay_inside_the_owned_services():
    scopes = _scopes()
    if not scopes:
        pytest.skip("no chatbots registered; run: python -m blastradius.chat.cli add <repo>")
    for scope in scopes:
        rows = T.workspace_packages(scope)
        if not rows:
            continue
        stray = {r["service"] for r in rows if not scope.owns(r["service"])}
        assert not stray, f"{scope.workspace.label} saw foreign services: {stray}"


@live
def test_two_chatbots_do_not_share_findings():
    """The requirement, asserted directly.

    Each chatbot may only report threats on versions its own services resolve.
    A finding that belongs to another repository's services must not appear.
    """
    scopes = _scopes()
    if len(scopes) < 2:
        pytest.skip("needs two registered chatbots to compare")
    for scope in scopes:
        for threat in T._scoped_threats(scope):
            for name in threat["services"]:
                assert scope.owns(name), (
                    f"{scope.workspace.label} reported a finding against "
                    f"{name!r}, which it does not own"
                )


@live
def test_a_foreign_service_is_refused_by_name():
    scopes = _scopes()
    if len(scopes) < 2:
        pytest.skip("needs two registered chatbots")
    first, second = scopes[0], scopes[1]
    foreign = next((n for n in first.service_names if not second.owns(n)), None)
    if foreign is None:
        pytest.skip("the two chatbots share every service name")
    answer = T.service_profile(second, foreign)
    assert answer["found"] is False
    assert "not part of" in answer["note"]


@live
def test_resolve_package_never_offers_another_repositorys_version():
    scopes = _scopes()
    if len(scopes) < 2:
        pytest.skip("needs two registered chatbots")
    for scope in scopes:
        held = {f"{r['name']}@{r['version']}" for r in T.workspace_packages(scope)}
        for match in T.resolve_package(scope, "a")["matches"]:
            assert match["spec"] in held


@live
def test_missing_package_says_so_rather_than_returning_empty():
    scopes = _scopes()
    if not scopes:
        pytest.skip("no chatbots registered")
    answer = T.resolve_package(scopes[0], "definitely-not-a-real-package-xyzzy")
    assert answer["matches"] == []
    assert answer["note"], "an empty match list must carry an explanation"
    assert scopes[0].workspace.label in answer["note"]


@live
def test_unbuilt_code_graph_is_unknown_not_safe():
    """The most dangerous mistake available to this feature.

    With no parsed source, every reachability answer is empty -- which is
    indistinguishable from a genuine all-clear, and wrong in the most
    flattering possible direction.
    """
    scopes = [s for s in _scopes() if not T.has_code_graph(s)]
    if not scopes:
        pytest.skip("every registered chatbot has a code graph")
    scope = scopes[0]
    threats = T._scoped_threats(scope)
    if not threats:
        pytest.skip("nothing to ask about")

    reach = T.code_reach(scope, threats[0]["spec"])
    assert reach["reaches_code"] is None, "must be unknown, never False"
    assert "unknown, not clear" in reach["note"]

    listing = T.list_threats(scope)
    assert listing["code_graph_ingested"] is False
    assert "not false" in listing["note"]

    plan = T.remediation_plan(scope, threats[0]["spec"])
    assert "UNKNOWN reach" in plan["priority"]


@live
def test_remediation_recommends_a_forward_fix_and_the_right_mechanism():
    """Direct dependencies get a bump; transitive ones need an override."""
    for scope in _scopes():
        for threat in T._scoped_threats(scope):
            plan = T.remediation_plan(scope, threat["spec"])
            target = plan.get("recommended_fix")
            if not target:
                continue
            installed = T.split_spec(plan["spec"])[1]
            assert target != installed
            assert target in plan["fixed_versions"]
            joined = " ".join(plan["steps"])
            if plan["transitive_services"] and not plan["direct_services"]:
                assert "overrides" in joined
            if plan["direct_services"]:
                assert "npm install" in joined
            return
    pytest.skip("no threat with a published forward fix")


@live
def test_every_tool_returns_something_serialisable_and_small():
    """A tool result is the one input nobody reviews before the model sees it."""
    import json

    scopes = _scopes()
    if not scopes:
        pytest.skip("no chatbots registered")
    scope = scopes[0]
    threats = T._scoped_threats(scope)
    spec = threats[0]["spec"] if threats else "lodash@4.17.21"
    service = scope.service_names[0]

    results = {
        "fleet_overview": T.fleet_overview(scope),
        "list_threats": T.list_threats(scope),
        "resolve_package": T.resolve_package(scope, "a"),
        "threat_detail": T.threat_detail(scope, spec),
        "impacted_services": T.impacted_services(scope, spec),
        "code_reach": T.code_reach(scope, spec),
        "remediation_plan": T.remediation_plan(scope, spec),
        "service_profile": T.service_profile(scope, service),
        "search_advisories": T.search_advisories(scope, ""),
        "dependency_path": T.dependency_path(scope, spec),
    }
    for name, payload in results.items():
        text = json.dumps(payload, default=str)
        assert isinstance(payload, dict), name
        assert len(text) < 24_000, f"{name} returned {len(text)} chars"
        assert "'type': 'null'" not in text, f"{name} leaked a HydraDB sentinel"


@live
def test_threat_detail_on_an_unknown_spec_offers_alternatives():
    scopes = _scopes()
    if not scopes:
        pytest.skip("no chatbots registered")
    answer = T.threat_detail(scopes[0], "not-a-package@9.9.9")
    assert answer["found"] is False
    assert "not that it is unused" in answer["note"]


@live
def test_caches_are_keyed_so_a_second_read_is_much_cheaper():
    """The briefing is only affordable because these are cached per epoch."""
    import time

    scopes = _scopes()
    if not scopes:
        pytest.skip("no chatbots registered")
    scope = scopes[0]
    T.clear_caches()

    started = time.perf_counter()
    T.fleet_overview(scope)
    cold = time.perf_counter() - started

    started = time.perf_counter()
    T.fleet_overview(scope)
    warm = time.perf_counter() - started

    assert warm < max(cold, 0.05), f"cold {cold*1000:.0f}ms, warm {warm*1000:.0f}ms"
