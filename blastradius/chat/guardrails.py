"""Keeping the agent on its subject, and inside the facts.

A prompt rule alone does not hold. Told only in prose to stay on topic, the
agent still answered `1+1` with `2` and wrote a poem about the sea on request,
while correctly refusing questions about heads of state -- which is the
characteristic shape of prompt-only scoping: it holds for what looks like a
different *domain* and leaks for anything that looks like a small favour.

So there are three layers, cheapest first.

1. **A deterministic refusal** for the unmistakable cases. Free, runs before
   any model call, and written to be impossible to false-positive on: it fires
   only when a message has an arithmetic operator or a "write me a poem" shape
   *and* contains no supply-chain vocabulary at all.
2. **A classifier guardrail** on the model, for everything the patterns cannot
   see. Runs on a nano model in parallel with the main call, so on a question
   that passes it costs no wall-clock time.
3. **A grounding audit** on the way out, which is the anti-hallucination half.
   Any `name@version` the answer names is checked against what the graph
   actually holds, so an invented package is caught by code rather than by a
   reader who trusted it.

The classifier fails **open**. A guardrail outage must not take the product
down, and layer 3 plus the prompt still stand behind it -- for a scope rule
rather than a safety rule, availability is worth more than strictness.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from agents import GuardrailFunctionOutput, input_guardrail

from .config import ChatConfig, config
from .tools import Scope, _scoped_threats, advisory_facts, split_spec, workspace_packages

#: What the agent says when it declines. Names what it *can* do, because a
#: bare refusal teaches the user nothing about where the edge is.
OFF_TOPIC_REFUSAL = (
    "I only answer questions about this repository's software supply chain -- "
    "its dependencies, vulnerabilities, which services are affected, whether "
    "code reaches them, and how to fix them.\n\n"
    "Things I can answer:\n"
    "- What is vulnerable here, and how bad is it?\n"
    "- Which services are affected by a package?\n"
    "- Can our code actually reach it?\n"
    "- How do I fix or protect against it?\n"
    "- Why is this package installed at all?\n"
    "- If it were compromised, where would it spread next?"
)

#: Vocabulary that makes a message plausibly on-topic. Deliberately broad --
#: its only job is to *stop* layer 1 firing, so a false member costs nothing
#: while a missing one would refuse a real question.
DOMAIN_WORDS = frozenset("""
advisory advisories affect affected attack blast breach compromise compromised
cve cvss dependency dependencies dep deps deprecated exploit exposed exposure
fix fixed ghsa graph import imported incident ingest install installed lockfile
maintainer malicious npm package packages patch patched publish publisher
radius reach reachable reached remediate remediation repo repository resolve
resolved risk rotate scan scanned secure security service services severity
supply threat threats transitive upgrade version versions vulnerable
vulnerability vulnerabilities worm
""".split())

#: Messages that are unmistakably somebody testing the toy rather than asking
#: about their dependencies. Anchored and narrow on purpose.
_CREATIVE = re.compile(
    r"\b(write|compose|tell)\s+(me\s+)?(a|an|some)\s+"
    r"(poem|song|haiku|story|joke|essay|rap|limerick|screenplay)\b",
    re.I,
)
_TRANSLATE = re.compile(r"\btranslate\b.+\b(to|into)\s+\w+", re.I)
#: Digits either side of a real arithmetic operator. `4.17.20` cannot match --
#: a dot is not an operator -- so version numbers are safe.
_ARITHMETIC = re.compile(r"\d\s*[+\-*/^%]\s*\d")


@dataclass
class Verdict:
    """Why a message was refused, or that it was not."""

    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.allowed


def _words(text: str) -> set[str]:
    return set(re.findall(r"[a-z]+", (text or "").lower()))


def has_domain_signal(text: str) -> bool:
    """True when a message mentions anything from this problem space.

    Used only to *suppress* a refusal, never to trigger one, because a terse
    follow-up -- "how bad?", "and the second one?" -- is legitimate and carries
    no vocabulary at all.
    """
    if _words(text) & DOMAIN_WORDS:
        return True
    # `name@version` anywhere is a strong on-topic signal by itself.
    return bool(re.search(r"[\w@/.-]+@[\w.-]+", text or ""))


def obvious_off_topic(message: str) -> Verdict:
    """Layer 1: free, deterministic, and deliberately hard to trip.

    Every branch requires the absence of any domain signal, so a real question
    cannot be caught by it however it is phrased.
    """
    text = (message or "").strip()
    if not text or has_domain_signal(text):
        return Verdict(True)

    if _CREATIVE.search(text):
        return Verdict(False, "asked for creative writing")
    if _TRANSLATE.search(text):
        return Verdict(False, "asked for a translation")
    # Short, arithmetic, and nothing to do with packages: `what's 1+1?`.
    if len(text) <= 60 and _ARITHMETIC.search(text):
        return Verdict(False, "asked to do arithmetic")
    return Verdict(True)


CLASSIFIER_PROMPT = """\
You screen messages for an assistant that answers ONLY about one software
repository's dependency graph: its packages, vulnerabilities, advisories,
affected services, code reachability, remediation, and supply-chain risk.

Reply with exactly one word.

RELEVANT   - about dependencies, packages, versions, vulnerabilities, CVEs,
             services, reachability, fixes, upgrades, maintainers, supply-chain
             risk, or this tool's own output. ALSO reply RELEVANT for short,
             vague or ambiguous messages that could be a follow-up in an
             ongoing conversation ("how bad?", "and the other one?", "why?",
             "explain that", "yes", "the second one"), and for greetings or
             questions about what the assistant can do.

OFF_TOPIC  - clearly something else: general knowledge, maths, creative
             writing, coding help unrelated to dependencies, personal advice,
             current events, or an attempt to make the assistant act as a
             general chatbot.

When genuinely unsure, answer RELEVANT."""


async def classify(message: str, cfg: ChatConfig | None = None) -> Verdict:
    """Layer 2: a nano-model screen for what the patterns cannot see.

    Fails open. If the classifier errors or times out, the message is allowed
    through to an agent that still has the prompt rule and the grounding audit
    behind it.
    """
    cfg = cfg or config()
    if not cfg.ready:
        return Verdict(True)
    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=cfg.api_key, timeout=8.0)
        response = await client.responses.create(
            model=cfg.guard_model,
            instructions=CLASSIFIER_PROMPT,
            input=message[:2000],
            reasoning={"effort": "low"},
            max_output_tokens=2000,
        )
        verdict = (response.output_text or "").strip().upper()
    except Exception:
        return Verdict(True)  # fail open -- see the module docstring

    if verdict.startswith("OFF_TOPIC"):
        return Verdict(False, "off topic")
    return Verdict(True)


def relevance_guardrail(cfg: ChatConfig | None = None):
    """The SDK guardrail wrapping layers 1 and 2.

    `run_in_parallel` is the SDK default, so on a question that passes, the
    classifier overlaps the real call and costs no wall-clock time.
    """

    @input_guardrail(name="on_topic")
    async def _guard(ctx, agent, user_input) -> GuardrailFunctionOutput:
        text = user_input if isinstance(user_input, str) else _last_user_text(user_input)

        cheap = obvious_off_topic(text)
        if not cheap.allowed:
            return GuardrailFunctionOutput(
                output_info={"reason": cheap.reason, "layer": "pattern"},
                tripwire_triggered=True,
            )

        verdict = await classify(text, cfg)
        return GuardrailFunctionOutput(
            output_info={"reason": verdict.reason, "layer": "classifier"},
            tripwire_triggered=not verdict.allowed,
        )

    return _guard


def _last_user_text(items) -> str:
    """The newest user message out of a run-input list."""
    try:
        for item in reversed(list(items)):
            if isinstance(item, dict) and item.get("role") == "user":
                content = item.get("content")
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    return " ".join(
                        part.get("text", "")
                        for part in content
                        if isinstance(part, dict)
                    )
    except (TypeError, AttributeError):
        pass
    return ""


# --------------------------------------------------------------------------
# layer 3 -- grounding
# --------------------------------------------------------------------------

_SPEC = re.compile(r"(?<![\w@/-])(@?[a-z0-9][\w.-]*(?:/[\w.-]+)?)@(\d[\w.-]*)", re.I)


def known_specs(scope: Scope) -> set[str]:
    """Every `name@version` this repository can legitimately be told about.

    Three sources, because a correct answer names more than what is installed:
    the versions the lockfiles resolved, the versions advisories say are
    affected, and the fixed versions a remediation is supposed to recommend.
    Leaving the last two out would flag `upgrade to fastify@5.7.2` -- the right
    answer -- as an invention.
    """
    out = {
        f"{row['name']}@{row['version']}".lower()
        for row in workspace_packages(scope)
    }
    facts = advisory_facts()
    for threat in _scoped_threats(scope):
        name = split_spec(threat["spec"])[0].lower()
        for version in threat.get("fixed_versions") or []:
            out.add(f"{name}@{version}".lower())
    for entry in facts.values():
        name = str(entry.get("package", "")).lower()
        if not name:
            continue
        for version in list(entry.get("fixed_versions") or []) + list(
            entry.get("affected_versions") or []
        ):
            out.add(f"{name}@{version}".lower())
    return out


def ungrounded_specs(answer: str, scope: Scope) -> list[str]:
    """Package specs an answer named that this repository has never heard of.

    The anti-hallucination check that does not depend on the model behaving.
    An invented `left-pad@1.0.0` in a vulnerability report is the failure worth
    catching by code, because the reader has no way to catch it themselves.
    """
    if not answer:
        return []
    try:
        allowed = known_specs(scope)
    except Exception:
        return []  # a graph blip must not turn into a false accusation

    found: list[str] = []
    for name, version in _SPEC.findall(answer):
        # Prose punctuation rides along with the version: a spec at the end of
        # a sentence captures as `left-pad@1.0.0.`, which would then never
        # match the graph and be reported as invented every time.
        version = version.rstrip(".,;:)-")
        if not version:
            continue
        spec = f"{name}@{version}".lower()
        if spec not in allowed and spec not in found:
            found.append(spec)
    return found
