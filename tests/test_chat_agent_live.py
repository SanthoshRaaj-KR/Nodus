"""The model in the loop, asserted on facts rather than on wording.

Skipped unless `OPENAI_API_KEY` is set, so the suite stays runnable without a
credential. When it does run it costs real tokens, which is why it asks a
small fixed set of questions rather than sweeping.

What is asserted here is deliberately narrow. Checking that an answer *reads*
well is checking the model, not the integration, and it fails randomly. What
matters is grounding: does the answer name things that are genuinely in this
repository, does it stay inside its own workspace, and does it refuse to call
an unscanned code graph "safe". Those are properties of the wiring, and they
either hold or they are a bug worth failing over.
"""

from __future__ import annotations

import asyncio
import os
import uuid
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.chat import agent as agent_mod  # noqa: E402
from blastradius.chat import briefing as B  # noqa: E402
from blastradius.chat import tools as T  # noqa: E402
from blastradius.chat.config import config  # noqa: E402
from blastradius.chat.workspaces import WorkspaceRegistry  # noqa: E402


def _live_graph():
    from blastradius.hydra_client import HydraClient, HydraError

    try:
        client = HydraClient()
        return client if client.ready() else None
    except HydraError:
        return None


def _scopes():
    from blastradius.hydra_client import HydraClient
    from blastradius.ids import IdAllocator

    client, ids = HydraClient(), IdAllocator()
    return [
        T.Scope(client=client, ids=ids, workspace=w)
        for w in WorkspaceRegistry().list()
        if w.service_ids
    ]


needs_key = pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY", "").strip()
    and not config().ready,
    reason="OPENAI_API_KEY is not set",
)
needs_graph = pytest.mark.skipif(
    _live_graph() is None, reason="HydraDB is not reachable"
)
live = pytest.mark.usefixtures()


@pytest.fixture(scope="module")
def scope():
    scopes = _scopes()
    if not scopes:
        pytest.skip("no chatbots registered")
    # Prefer one with findings -- an empty repository exercises none of the
    # interesting paths.
    with_threats = [s for s in scopes if T._scoped_threats(s)]
    return (with_threats or scopes)[0]


def _ask(scope, question, session="pytest"):
    """One question, in a session unique to this run.

    History is persisted in SQLite, so a fixed session id would let the
    previous run's conversation decide what this one asserts -- a test that
    passes only on a second invocation is worse than one that fails.
    """
    unique = f"{session}-{uuid.uuid4().hex[:8]}"
    return asyncio.run(agent_mod.answer(scope, question, session_id=unique))


# --------------------------------------------------------------------------
# construction -- no tokens spent
# --------------------------------------------------------------------------


@needs_graph
def test_agent_builds_with_every_tool_bound(scope):
    agent = agent_mod.build_agent(scope)
    names = {t.name for t in agent.tools}
    assert {
        "resolve_package", "list_threats", "threat_detail", "impacted_services",
        "code_reach", "dependency_path", "remediation_plan", "attack_frontier",
        "service_profile", "search_advisories", "fleet_overview",
    } <= names
    assert agent.model == config().model


@needs_graph
def test_the_prompt_carries_this_repositorys_briefing(scope):
    agent = agent_mod.build_agent(scope)
    assert B.briefing(scope).text in agent.instructions
    assert "Never invent" in agent.instructions


@needs_graph
def test_sessions_are_namespaced_per_workspace():
    """Two tabs on two chatbots must not share history even on one session id.

    The client id comes from the browser, so collisions are the default rather
    than the exception.
    """
    first = agent_mod.session_for(1, "shared")
    second = agent_mod.session_for(2, "shared")
    assert first.session_id != second.session_id
    assert first.session_id.startswith("w1:")
    assert second.session_id.startswith("w2:")


# --------------------------------------------------------------------------
# live calls
# --------------------------------------------------------------------------


@needs_key
@needs_graph
def test_the_model_answers_and_names_real_things(scope):
    result = _ask(scope, "What is affected in this repository, and how bad is it?")
    assert not result["error"], result["error"]
    answer = result["answer"]
    assert answer.strip(), "empty answer"

    threats = T._scoped_threats(scope)
    if threats:
        packages = {T.split_spec(t["spec"])[0] for t in threats}
        assert any(p in answer for p in packages), (
            f"answer named none of {packages}: {answer[:400]}"
        )


@needs_key
@needs_graph
def test_the_common_question_needs_no_tool_call(scope):
    """The whole point of the briefing.

    If this starts failing, the pack has stopped carrying enough and every
    question has quietly become two model calls.
    """
    result = _ask(scope, "How many services are in this repository?", session="nb")
    assert not result["error"]
    assert result["tools_called"] == [], (
        f"expected a briefing-only answer, got {result['tools_called']}"
    )


@needs_key
@needs_graph
def test_a_drilldown_actually_reaches_for_a_tool(scope):
    threats = T._scoped_threats(scope)
    if not threats:
        pytest.skip("nothing to drill into")
    spec = threats[0]["spec"]
    result = _ask(scope, f"How exactly do I fix {spec}? Give me the command.",
                  session="fix")
    assert not result["error"]
    assert result["tools_called"], "a remediation question should consult a tool"


@needs_key
@needs_graph
def test_the_recommended_fix_is_never_a_downgrade(scope):
    """The bug that would matter most in production.

    Advisories list a fix per affected branch, so the lowest is often below
    what is installed. An assistant that tells somebody to downgrade onto an
    unpatched branch has done real harm.
    """
    from blastradius.pkg.semver import try_parse

    threats = [t for t in T._scoped_threats(scope) if t.get("recommended_fix")]
    if not threats:
        pytest.skip("no threat with a published forward fix")
    threat = threats[0]
    installed = try_parse(T.split_spec(threat["spec"])[1])

    result = _ask(scope, f"What version should I upgrade {threat['spec']} to?",
                  session="upgrade")
    assert not result["error"]

    # Any version the answer names must be an upgrade, not a rollback.
    import re
    for candidate in re.findall(r"\b\d+\.\d+\.\d+\b", result["answer"]):
        parsed = try_parse(candidate)
        if parsed is None or installed is None:
            continue
        if candidate == threat["spec"].rsplit("@", 1)[-1]:
            continue  # naming the installed version is fine
        assert parsed > installed, (
            f"answer suggested {candidate}, below the installed {installed}: "
            f"{result['answer'][:400]}"
        )


@needs_key
@needs_graph
def test_it_refuses_a_package_this_repository_does_not_have(scope):
    """Grounding, at the point where a model most wants to be helpful."""
    result = _ask(
        scope,
        "What is our exposure to the package quixotic-nonexistent-pkg-42?",
        session="ground",
    )
    assert not result["error"]
    lowered = result["answer"].lower()
    assert any(
        phrase in lowered
        for phrase in ("not", "no ", "isn't", "does not", "cannot find", "n't find")
    ), f"expected a refusal, got: {result['answer'][:300]}"


@needs_key
@needs_graph
def test_an_unbuilt_code_graph_is_never_called_safe():
    """The most damaging answer available to this feature.

    Empty reachability data looks exactly like a clean bill of health, and
    reporting it as one tells somebody to ignore a live vulnerability.
    """
    scopes = [s for s in _scopes() if not T.has_code_graph(s) and T._scoped_threats(s)]
    if not scopes:
        pytest.skip("no chatbot with findings and no code graph")
    target = scopes[0]
    spec = T._scoped_threats(target)[0]["spec"]

    result = _ask(target, f"Can our code actually reach {spec}? Is it safe to ignore?",
                  session="reach")
    assert not result["error"]
    lowered = result["answer"].lower()
    assert any(
        word in lowered
        for word in ("unknown", "not been built", "not built", "has not been scanned",
                     "no source", "cannot determine", "can't determine")
    ), f"must not imply safety: {result['answer'][:400]}"


@needs_key
@needs_graph
def test_one_chatbot_will_not_answer_for_anothers_service():
    """The isolation requirement, end to end through the model."""
    scopes = _scopes()
    if len(scopes) < 2:
        pytest.skip("needs two registered chatbots")
    first, second = scopes[0], scopes[1]
    foreign = next((n for n in first.service_names if not second.owns(n)), None)
    if foreign is None:
        pytest.skip("the chatbots share every service name")

    result = _ask(second, f"What is wrong with the service called {foreign}?",
                  session="isolation")
    assert not result["error"]
    lowered = result["answer"].lower()
    assert any(
        phrase in lowered
        for phrase in ("not part of", "not in this", "no service", "does not",
                       "isn't part", "another repository", "not found")
    ), f"chatbot #{second.workspace.id} should refuse {foreign!r}: {result['answer'][:400]}"


@needs_key
@needs_graph
def test_answers_arrive_promptly(scope):
    """Speed is a stated requirement, so it gets an assertion.

    Generous on purpose -- this is a smoke test against a hang or a runaway
    tool loop, not a benchmark. The CLI prints the real numbers.
    """
    started = time.perf_counter()
    result = _ask(scope, "Summarise the risk here in one sentence.", session="speed")
    elapsed = time.perf_counter() - started
    assert not result["error"]
    assert elapsed < 45, f"took {elapsed:.1f}s"
