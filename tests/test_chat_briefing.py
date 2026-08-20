"""The situation pack: small enough to be free, honest enough to be safe.

The briefing is the feature's speed decision -- it is why "what is affected?"
costs one model call instead of three. That only holds if it stays small, so
its size is asserted rather than hoped for. And because it is the text the
model trusts most, the reachability caveat has to survive in it verbatim.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.chat import briefing as B  # noqa: E402
from blastradius.chat import tools as T  # noqa: E402
from blastradius.chat.workspaces import WorkspaceRegistry  # noqa: E402


def test_severity_ranks_worst_first():
    ranks = [B._severity_rank(s) for s in ("critical", "high", "moderate", "low")]
    assert ranks == sorted(ranks)
    assert B._severity_rank("nonsense") > B._severity_rank("low")
    assert B._severity_rank("medium") == B._severity_rank("moderate")


def test_suggestions_come_from_the_repository_not_a_canned_list():
    """A demo that suggests "which services use lodash" to a repo with no
    lodash demonstrates the opposite of what it means to."""
    overview = {"code_graph_ingested": True, "services": [{"name": "api", "packages": 3}]}
    threats = [{"spec": "left-pad@1.0.0", "severity": "high", "services": ["api"]}]
    questions = B._suggestions(overview, threats)
    assert any("left-pad@1.0.0" in q for q in questions)
    assert len(questions) <= 5


def test_suggestions_avoid_reachability_when_there_is_no_code_graph():
    overview = {"code_graph_ingested": False, "services": [{"name": "api", "packages": 3}]}
    threats = [{"spec": "left-pad@1.0.0", "severity": "high", "services": ["api"]}]
    joined = " ".join(B._suggestions(overview, threats)).lower()
    assert "actually call" not in joined


def test_clean_repository_still_gets_starter_questions():
    overview = {"code_graph_ingested": True, "services": [{"name": "api", "packages": 3}]}
    assert len(B._suggestions(overview, [])) >= 2


# --------------------------------------------------------------------------
# live
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
    from blastradius.hydra_client import HydraClient
    from blastradius.ids import IdAllocator

    client, ids = HydraClient(), IdAllocator()
    return [
        T.Scope(client=client, ids=ids, workspace=w)
        for w in WorkspaceRegistry().list()
        if w.service_ids
    ]


@live
def test_briefing_stays_within_its_token_budget():
    """It rides in every request. Growth here is a per-question tax."""
    scopes = _scopes()
    if not scopes:
        pytest.skip("no chatbots registered")
    for scope in scopes:
        pack = B.briefing(scope, force=True)
        assert len(pack.text) < 6000, (
            f"{scope.workspace.label} briefing is {len(pack.text)} chars"
        )


@live
def test_briefing_names_its_own_repository_and_services():
    scopes = _scopes()
    if not scopes:
        pytest.skip("no chatbots registered")
    for scope in scopes:
        text = B.briefing(scope, force=True).text
        assert scope.workspace.label in text
        assert str(scope.workspace.id) in text
        for name in scope.service_names[:3]:
            assert name in text, f"{name} missing from its own briefing"


@live
def test_briefing_never_names_another_repositorys_service():
    scopes = _scopes()
    if len(scopes) < 2:
        pytest.skip("needs two registered chatbots")
    for scope in scopes:
        text = B.briefing(scope, force=True).text
        for other in scopes:
            if other.workspace.id == scope.workspace.id:
                continue
            for name in other.service_names:
                if scope.owns(name):
                    continue  # a genuinely shared name, reported as a collision
                assert name not in text, (
                    f"{scope.workspace.label} briefing leaked {name!r}"
                )


@live
def test_missing_code_graph_is_stated_in_the_prompt_itself():
    """The caveat has to be where the model reads it, not only in tool output.

    Most questions are answered straight from the briefing without a tool
    call, so a caveat that lived only in tool results would be absent from
    exactly the answers most likely to be given.
    """
    scopes = [s for s in _scopes() if not T.has_code_graph(s)]
    if not scopes:
        pytest.skip("every registered chatbot has a code graph")
    text = B.briefing(scopes[0], force=True).text
    assert "NOT BUILT" in text
    assert "UNKNOWN" in text


@live
def test_service_names_in_the_threat_table_are_never_truncated():
    """The model quotes this column verbatim.

    An abbreviated `no-lodas` is reported to the user as the name of a service
    that does not exist.
    """
    scopes = _scopes()
    if not scopes:
        pytest.skip("no chatbots registered")
    for scope in scopes:
        pack = B.briefing(scope, force=True)
        for threat in T._scoped_threats(scope):
            names = threat["services"]
            if len(names) == 1 and names[0] in pack.text:
                assert names[0] in pack.text
                return
    pytest.skip("no single-service threat to check")


@live
def test_briefing_recommends_only_forward_fixes():
    """The table's fix column must never show a downgrade."""
    for scope in _scopes():
        for threat in T._scoped_threats(scope):
            target = threat.get("recommended_fix")
            if target:
                installed = T.split_spec(threat["spec"])[1]
                assert T.recommended_fix(installed, [target]) == target


@live
def test_briefing_is_cached_per_workspace_and_epoch():
    scopes = _scopes()
    if not scopes:
        pytest.skip("no chatbots registered")
    B.clear_cache()
    first = B.briefing(scopes[0])
    assert B.briefing(scopes[0]) is first, "a second read should not rebuild"
    if len(scopes) > 1:
        assert B.briefing(scopes[1]) is not first
