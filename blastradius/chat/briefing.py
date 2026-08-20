"""The situation pack: what the chatbot already knows before you ask.

This is the speed decision in the whole feature. Most of what anyone asks a
supply-chain assistant -- *what is affected*, *how bad is it*, *what should I
patch first*, *which services* -- is answerable from a few hundred facts that
change only when the graph does. Making the model fetch them turns every such
question into at least two sequential model calls plus a graph read, and the
first token cannot arrive until all of that is finished.

So they are computed once per `(workspace, read_epoch)` and put in the system
prompt instead. Those questions then cost **one** model call and begin
streaming immediately; only genuine drill-downs spend a tool round trip.

It is rendered as text rather than JSON on purpose. The same content costs
noticeably fewer tokens without braces and quoting, models read a small table
at least as reliably as an object, and -- because the block is stable between
questions -- it sits at the front of the prompt where OpenAI's automatic
prefix caching can hit it on every follow-up in a conversation.

The cap matters as much as the content. A briefing that grows with the repo
would eventually crowd out the conversation, so the threat table is capped and
says how many rows it left out, and the tools exist to ask for the rest.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any

from . import tools
from .tools import Scope

#: Threat rows carried in the prompt. Twelve covers every repository in this
#: corpus whole, and past that the ranking has already put the interesting
#: ones first -- `list_threats` fetches the tail on request.
MAX_ROWS = 12

#: Services named in the prompt before it switches to a count.
MAX_SERVICES = 20

_lock = RLock()
_cache: dict[tuple[Any, int], "Briefing"] = {}


@dataclass
class Briefing:
    """One workspace's situation, rendered once and reused."""

    workspace_id: int
    text: str
    #: Starter questions derived from what is actually in this repository, so
    #: the UI never suggests "which services use lodash" to a repo without it.
    suggestions: list[str]
    threat_count: int
    code_graph: bool

    def to_dict(self) -> dict:
        return {
            "workspace_id": self.workspace_id,
            "text": self.text,
            "suggestions": self.suggestions,
            "threat_count": self.threat_count,
            "code_graph_ingested": self.code_graph,
            "chars": len(self.text),
        }


def _severity_rank(label: str) -> int:
    order = {"critical": 0, "high": 1, "moderate": 2, "medium": 2, "low": 3}
    return order.get((label or "").lower(), 4)


def build(scope: Scope) -> Briefing:
    """Compute the pack. Callers should prefer :func:`briefing`, which caches."""
    workspace = scope.workspace
    overview = tools.fleet_overview(scope)
    threats = tools._scoped_threats(scope)
    threats = sorted(
        threats,
        key=lambda t: (
            not t["in_code"],
            _severity_rank(t.get("severity", "")),
            -len(t.get("services") or []),
            t["spec"],
        ),
    )
    shown = threats[:MAX_ROWS]
    omitted = max(0, len(threats) - len(shown))

    services = overview["services"]
    if len(services) <= MAX_SERVICES:
        service_line = ", ".join(
            f"{s['name']} ({s['packages']} pkgs)" for s in services
        )
    else:
        head = ", ".join(s["name"] for s in services[:MAX_SERVICES])
        service_line = f"{head}, and {len(services) - MAX_SERVICES} more"

    lines: list[str] = []
    lines.append(f"REPOSITORY: {workspace.label}   (chatbot #{workspace.id}, {workspace.repo_path})")
    lines.append(
        f"SERVICES ({overview['service_count']}): {service_line or 'none'}"
    )
    lines.append(
        f"DEPENDENCIES: {overview['distinct_versions']} resolved versions across "
        f"{overview['distinct_packages']} packages; "
        f"{overview['direct_dependencies']} declared directly."
    )

    if overview["code_graph_ingested"]:
        lines.append(
            "CODE GRAPH: built. Reachability answers are real -- "
            "'not reached' means no parsed source imports it."
        )
    else:
        lines.append(
            "CODE GRAPH: NOT BUILT for this repository. Reachability is UNKNOWN, "
            "not clear. Never tell the user something is unreachable or safe to "
            "deprioritise on reachability grounds; say the code graph has not "
            "been built and offer the command in `code_reach`."
        )

    counts = overview["threats"]
    lines.append("")
    lines.append(
        f"CONFIRMED THREATS: {counts['total']} "
        f"({counts['reaching_code']} reach application code)"
        + (f"   by severity: {_fmt_counts(counts['by_severity'])}" if counts["by_severity"] else "")
    )

    if shown:
        lines.append("")
        # `kind` is carried because it is the only column that separates a
        # known CVE from a tampered artifact, and those are different
        # incidents. Without it, "which one is the compromised package" costs
        # a `list_threats` round trip to answer from a table already in the
        # prompt -- and a model that guesses instead names the wrong one.
        lines.append("  spec                          kind         sev       reach  fix             services")
        lines.append("  ----------------------------  -----------  --------  -----  --------------  --------")
        for threat in shown:
            reach = "yes" if threat["in_code"] else (
                "?" if not overview["code_graph_ingested"] else "no"
            )
            # The recommendation, not the first published fix: OSV lists a
            # fix per affected branch, and the lowest is often a downgrade.
            fix = threat.get("recommended_fix") or (
                "no forward fix" if threat.get("fixed_versions") else "none published"
            )
            # Service names are never abbreviated: the model quotes this column
            # back to the user verbatim, and a truncated "no-lodas" would be
            # reported as the name of a service that does not exist.
            names = threat.get("services") or []
            who = ", ".join(names) if len(names) <= 2 else f"{len(names)} services"
            lines.append(
                f"  {threat['spec'][:28]:<28}  {threat.get('kind','')[:11]:<11}  "
                f"{threat.get('severity','')[:8]:<8}  "
                f"{reach:<5}  {fix[:14]:<14}  {who}"
            )
        if omitted:
            lines.append(f"  ... and {omitted} more -- call list_threats for the rest.")
    else:
        lines.append("  Nothing is filed against any version this repository resolves.")

    text = "\n".join(lines)
    return Briefing(
        workspace_id=workspace.id,
        text=text,
        suggestions=_suggestions(overview, shown),
        threat_count=len(threats),
        code_graph=overview["code_graph_ingested"],
    )


def _fmt_counts(counts: dict[str, int]) -> str:
    return ", ".join(
        f"{n} {label}"
        for label, n in sorted(counts.items(), key=lambda kv: _severity_rank(kv[0]))
    )


def _suggestions(overview: dict, threats: list[dict]) -> list[str]:
    """Starter questions this repository can actually answer.

    Generated from its own contents rather than hardcoded, because a canned
    "which services use lodash?" against a repo with no lodash demonstrates
    the opposite of what a demo wants to show.
    """
    out: list[str] = ["What is affected, and how bad is it?"]
    if threats:
        worst = threats[0]
        out.append(f"How do I fix {worst['spec']}?")
        # Offered only where there is a tampered artifact to ask it about, on
        # the same rule as the rest of this function: a starter question the
        # repository cannot answer demonstrates the opposite of what it should.
        compromised = next(
            (t for t in threats if (t.get("kind") or "") == "compromised"), None
        )
        if compromised is not None:
            out.append(f"Who published {compromised['spec']}?")
        out.append(f"Which services are exposed to {worst['spec']}?")
        if overview["code_graph_ingested"]:
            out.append(f"Does our code actually call {worst['spec']}?")
        else:
            out.append("What can I safely deprioritise?")
        out.append(f"If {worst['spec']} were compromised, where would it spread next?")
    else:
        out.append("What does this repository depend on?")
        services = overview.get("services") or []
        if services:
            out.append(f"What is in {services[0]['name']}?")
    return out[:5]


def briefing(scope: Scope, force: bool = False) -> Briefing:
    """The cached pack for one workspace, rebuilt only when the graph moves."""
    epoch = tools._read_epoch(scope.client)
    key = (epoch, scope.workspace.id)
    with _lock:
        if not force and epoch is not None and key in _cache:
            return _cache[key]
    built = build(scope)
    with _lock:
        if epoch is not None:
            _cache[key] = built
    return built


def clear_cache() -> None:
    with _lock:
        _cache.clear()
