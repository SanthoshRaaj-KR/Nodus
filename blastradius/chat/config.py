"""Where the chat agent gets its key, its model and its limits.

One module reads the environment so that nothing else has to. Every knob has
a default that works, except the key -- there is no sensible default for a
credential, and a chat endpoint that silently runs without one would fail at
the worst possible moment rather than at startup.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

#: Repository root -- three levels up from this file (chat/ -> blastradius/ -> root).
ROOT = Path(__file__).resolve().parent.parent.parent

#: Mini-class models only, by project rule. This is a *guard*, not a registry:
#: it rejects a model whose name says it is a full-size model, rather than
#: enumerating the ones that exist. A hardcoded list would reject every model
#: released after this file was written, which for a field that exists to be
#: swapped is exactly the wrong failure.
_FORBIDDEN_MARKERS = ("-pro", "-opus", "-max")

DEFAULT_MODEL = "gpt-5.4-mini"

#: The scope classifier runs on every question, so it goes on the smallest
#: model available rather than the answering one. It decides one word.
DEFAULT_GUARD_MODEL = "gpt-5.4-nano"

#: Reasoning effort. Low is the default because time-to-first-token dominates
#: how fast this feels, and the questions here are lookups over facts already
#: computed by the tools rather than problems the model has to think through.
DEFAULT_EFFORT = "low"


def load_env(path: Path | None = None) -> None:
    """Read `.env` into the process environment, if python-dotenv is present.

    Called for its side effect at import time by anything that needs config.
    Nothing in this repository loaded `.env` before -- `.env.example` existed
    and documented `HYDRA_*`, but every process still expected them exported
    by hand. Loading it here fixes that for the whole server, not just chat.

    Never overrides a variable already set: an explicit `HYDRA_HTTP=... uvicorn`
    on the command line has to beat a stale line in a file nobody remembered.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover -- optional, documented in requirements
        return
    load_dotenv(path or (ROOT / ".env"), override=False)


@dataclass(frozen=True)
class ChatConfig:
    """Everything the agent needs to run, resolved once."""

    api_key: str
    model: str
    reasoning_effort: str
    max_turns: int
    #: Where conversation history lives. One file, many sessions -- see
    #: `agent.session_for`. Under data/ because data/ is already gitignored
    #: and already holds the other thing keyed to a graph build (ids.sqlite).
    session_db: Path
    #: Model for the relevance guardrail. Separate from `model` because it
    #: answers a one-word classification and should never cost what an
    #: answer costs.
    guard_model: str
    #: Whether the guardrails run at all. Off is for debugging what the
    #: agent would say unscreened, never for production.
    guardrails: bool
    #: Ceiling on a single tool result, in characters. Tool payloads are the
    #: one input a user cannot see and cannot bound, and an unbounded one both
    #: slows generation and pushes the briefing out of the prompt cache.
    max_tool_chars: int

    @property
    def ready(self) -> bool:
        """True when there is a key to make requests with."""
        return bool(self.api_key)

    @property
    def model_allowed(self) -> bool:
        """False when the configured model is not a mini-class model.

        Checked rather than assumed because the model is deliberately a
        settable field -- see `_FORBIDDEN_MARKERS`.
        """
        lowered = self.model.lower()
        if any(marker in lowered for marker in _FORBIDDEN_MARKERS):
            return False
        return "mini" in lowered or "nano" in lowered or "haiku" in lowered

    def redacted(self) -> dict:
        """Safe to put in an HTTP response. Never returns the key itself."""
        return {
            "model": self.model,
            "reasoning_effort": self.reasoning_effort,
            "max_turns": self.max_turns,
            "key_present": self.ready,
            "model_allowed": self.model_allowed,
            "guard_model": self.guard_model,
            "guardrails": self.guardrails,
        }


def _int_env(name: str, default: int) -> int:
    """An int from the environment, falling back rather than crashing.

    A typo'd number in `.env` should not take the server down at import time;
    it should take the default and let `/api/chat/health` report what is
    actually in force.
    """
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


@lru_cache(maxsize=1)
def config() -> ChatConfig:
    """The process-wide config, read once.

    Cached because it is consulted per request and per tool call. Call
    `config.cache_clear()` after changing the environment -- the tests do.
    """
    load_env()
    return ChatConfig(
        api_key=os.environ.get("OPENAI_API_KEY", "").strip(),
        model=os.environ.get("CHAT_MODEL", "").strip() or DEFAULT_MODEL,
        reasoning_effort=(
            os.environ.get("CHAT_REASONING_EFFORT", "").strip() or DEFAULT_EFFORT
        ),
        max_turns=_int_env("CHAT_MAX_TURNS", 6),
        session_db=Path(
            os.environ.get("CHAT_SESSION_DB", "").strip()
            or (ROOT / "data" / "chat-sessions.sqlite")
        ),
        max_tool_chars=_int_env("CHAT_MAX_TOOL_CHARS", 6000),
        guard_model=(
            os.environ.get("CHAT_GUARD_MODEL", "").strip() or DEFAULT_GUARD_MODEL
        ),
        guardrails=(
            os.environ.get("CHAT_GUARDRAILS", "1").strip().lower()
            not in ("0", "false", "no", "off")
        ),
    )
