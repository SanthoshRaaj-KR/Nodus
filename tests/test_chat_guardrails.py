"""Staying on subject, and inside the facts.

The prompt-only version of this leaked: told in prose to stay on topic, the
agent answered `1+1` with `2` and wrote a poem on request, while correctly
refusing questions about heads of state. That is the characteristic shape of
prompt-only scoping -- it holds against a different *domain* and gives way to
anything that reads as a small favour.

Two properties matter here and they pull against each other. Refusing what is
off subject is the easy one. Not refusing a terse follow-up -- "how bad?",
"the second one" -- is the one that breaks a guardrail in practice, so it gets
at least as many tests.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.chat import guardrails as G  # noqa: E402
from blastradius.chat import tools as T  # noqa: E402
from blastradius.chat.workspaces import WorkspaceRegistry  # noqa: E402


# --------------------------------------------------------------------------
# layer 1 -- the free deterministic pass
# --------------------------------------------------------------------------


@pytest.mark.parametrize("message", [
    "what's 1+1?",
    "1+1",
    "what is 12 * 7",
    "write me a poem about the sea",
    "write a song about docker",
    "tell me a joke",
    "compose an essay on the industrial revolution",
    "translate this to French",
])
def test_obviously_off_topic_is_refused_for_free(message):
    verdict = G.obvious_off_topic(message)
    assert not verdict.allowed, message
    assert verdict.reason


@pytest.mark.parametrize("message", [
    "what is vulnerable?",
    "how do I fix uuid@8.3.2?",
    "which services are affected",
    "can our code reach lodash",
    "what should I patch first",
    "is this package installed anywhere",
    "who maintains fastify",
    "show me the dependency chain",
])
def test_real_questions_pass_layer_one(message):
    assert G.obvious_off_topic(message).allowed, message


@pytest.mark.parametrize("message", [
    "how bad?",
    "why?",
    "the second one",
    "and the other one",
    "explain that",
    "yes",
    "what about it",
    "",
])
def test_terse_followups_are_never_refused_by_pattern(message):
    """The failure mode that makes a guardrail worse than none.

    A follow-up carries no vocabulary of its own, so layer 1 must not try to
    judge it -- the model has the conversation and can.
    """
    assert G.obvious_off_topic(message).allowed, message


def test_arithmetic_patterns_cannot_fire_on_version_numbers():
    """A dot is not an operator, so `4.17.20` must never read as a sum."""
    for message in ("4.17.20", "lodash@4.17.20", "upgrade 1.2.3 to 4.5.6"):
        assert G.obvious_off_topic(message).allowed, message


def test_a_domain_word_always_beats_an_off_topic_pattern():
    """Layer 1 defers whenever the message could plausibly be real.

    "write me a poem" is refused; "write me a poem about our CVEs" is somebody
    being odd about a real subject, and the model can decline that itself.
    """
    assert G.obvious_off_topic("write me a poem about our vulnerabilities").allowed
    assert G.obvious_off_topic("what is 1+1 for the lodash advisory").allowed


def test_domain_signal_detects_vocabulary_and_specs():
    assert G.has_domain_signal("what packages are vulnerable")
    assert G.has_domain_signal("tell me about lodash@4.17.20")
    assert G.has_domain_signal("@scope/pkg@1.0.0")
    assert not G.has_domain_signal("how bad?")
    assert not G.has_domain_signal("what is the capital of Peru")


# --------------------------------------------------------------------------
# layer 3 -- grounding
# --------------------------------------------------------------------------


def test_spec_pattern_finds_names_and_scoped_names():
    found = dict(G._SPEC.findall("use lodash@4.17.20 and @babel/core@7.1.0 today"))
    assert found["lodash"] == "4.17.20"
    assert found["@babel/core"] == "7.1.0"


def _live():
    from blastradius.hydra_client import HydraClient, HydraError

    try:
        client = HydraClient()
        return client if client.ready() else None
    except HydraError:
        return None


live = pytest.mark.skipif(_live() is None, reason="HydraDB is not reachable")


@pytest.fixture
def scope():
    from blastradius.hydra_client import HydraClient
    from blastradius.ids import IdAllocator

    workspaces = [w for w in WorkspaceRegistry().list() if w.service_ids]
    if not workspaces:
        pytest.skip("no chatbots registered")
    with_threats = None
    client, ids = HydraClient(), IdAllocator()
    for workspace in workspaces:
        candidate = T.Scope(client=client, ids=ids, workspace=workspace)
        if T._scoped_threats(candidate):
            with_threats = candidate
            break
    return with_threats or T.Scope(client=client, ids=ids, workspace=workspaces[0])


@live
def test_an_invented_package_is_caught(scope):
    """The check that does not depend on the model behaving.

    An invented package in a vulnerability report is the failure worth
    catching by code, because the reader has no way to catch it themselves.
    """
    flagged = G.ungrounded_specs(
        "You are exposed to evil-corp-sdk@6.6.6, patch it now.", scope
    )
    assert "evil-corp-sdk@6.6.6" in flagged


@live
def test_an_invented_version_of_a_real_package_is_caught(scope):
    threats = T._scoped_threats(scope)
    if not threats:
        pytest.skip("nothing installed to fake a version of")
    name = T.split_spec(threats[0]["spec"])[0]
    flagged = G.ungrounded_specs(f"{name}@99.99.99 is affected here.", scope)
    assert f"{name}@99.99.99".lower() in flagged


@live
def test_installed_versions_are_not_flagged(scope):
    packages = T.workspace_packages(scope)
    if not packages:
        pytest.skip("nothing installed")
    row = packages[0]
    spec = f"{row['name']}@{row['version']}"
    assert G.ungrounded_specs(f"You have {spec} installed.", scope) == []


@live
def test_a_recommended_fix_is_not_flagged_as_invented(scope):
    """The false positive that would make this check useless.

    A correct answer names versions that are deliberately *not* installed --
    that is what an upgrade is. Flagging them would fire on every remediation.
    """
    threats = [t for t in T._scoped_threats(scope) if t.get("recommended_fix")]
    if not threats:
        pytest.skip("no threat with a published forward fix")
    threat = threats[0]
    name = T.split_spec(threat["spec"])[0]
    text = f"Upgrade to {name}@{threat['recommended_fix']} to clear the advisory."
    assert G.ungrounded_specs(text, scope) == []


@live
def test_sentence_punctuation_is_not_read_as_part_of_the_version(scope):
    """`left-pad@1.0.0.` at the end of a sentence must not become a new spec."""
    packages = T.workspace_packages(scope)
    if not packages:
        pytest.skip("nothing installed")
    row = packages[0]
    for ending in (".", ",", ";", ")"):
        text = f"It resolves {row['name']}@{row['version']}{ending}"
        assert G.ungrounded_specs(text, scope) == [], ending


@live
def test_an_answer_with_no_specs_is_grounded(scope):
    assert G.ungrounded_specs("Nothing is wrong with this repository.", scope) == []
    assert G.ungrounded_specs("", scope) == []


# --------------------------------------------------------------------------
# wiring
# --------------------------------------------------------------------------


@live
def test_the_agent_carries_a_guardrail_when_enabled(scope):
    from blastradius.chat import agent as agent_mod
    from blastradius.chat.config import config

    agent = agent_mod.build_agent(scope, config())
    assert agent.input_guardrails, "guardrails are on by default"


@live
def test_guardrails_can_be_turned_off_for_debugging(scope, monkeypatch):
    from blastradius.chat import agent as agent_mod
    from blastradius.chat.config import config

    monkeypatch.setenv("CHAT_GUARDRAILS", "0")
    config.cache_clear()
    try:
        assert agent_mod.build_agent(scope, config()).input_guardrails == []
    finally:
        config.cache_clear()


def test_the_refusal_names_what_it_can_do_instead():
    """A bare "no" teaches nobody where the edge is."""
    assert "supply chain" in G.OFF_TOPIC_REFUSAL
    assert G.OFF_TOPIC_REFUSAL.count("-") >= 5  # the list of what it can answer
