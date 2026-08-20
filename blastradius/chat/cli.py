"""Terminal surface for the chat agent.

    python -m blastradius.chat.cli list
    python -m blastradius.chat.cli add corpus/fleet --label "Corpus fleet"
    python -m blastradius.chat.cli ask 1 "what is affected?"
    python -m blastradius.chat.cli repl 2
    python -m blastradius.chat.cli brief 1

Here because a browser is a poor place to find out that a question is slow or
an answer is wrong. `ask` prints the tools the model actually reached for and
what the round trip cost, which is the thing worth watching while tuning.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

from blastradius.hydra_client import HydraClient, HydraError
from blastradius.ids import IdAllocator

from . import agent as agent_mod
from . import briefing as briefing_mod
from . import tools as T
from .config import config
from .tools import Scope
from .workspaces import WorkspaceRegistry

RULE = "-" * 72

# Model output is full of characters cp1252 cannot encode -- arrows, curly
# quotes, the em dashes it likes in prose. On a Windows console that is not a
# stray glyph but a UnicodeEncodeError mid-stream, which kills the answer
# halfway through and looks like the agent crashed.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover -- already utf-8
        pass


def _scope(ref: str) -> Scope:
    registry = WorkspaceRegistry()
    workspace = registry.get(ref)
    if workspace is None:
        known = registry.list()
        print(f"no chatbot {ref!r}.", file=sys.stderr)
        if known:
            print("registered:", file=sys.stderr)
            for w in known:
                print(f"  #{w.id:<3} {w.slug:<24} {w.label}", file=sys.stderr)
        else:
            print("none registered -- try `add <repo path>`.", file=sys.stderr)
        raise SystemExit(2)
    return Scope(client=HydraClient(), ids=IdAllocator(), workspace=workspace)


def cmd_list(args) -> int:
    workspaces = WorkspaceRegistry().list()
    if not workspaces:
        print("No chatbots registered. Add one:")
        print("  python -m blastradius.chat.cli add corpus/fleet")
        return 0
    print(f"{'id':<4} {'slug':<24} {'svcs':>5}  {'url':<10} repo")
    print(RULE)
    for w in workspaces:
        print(f"{w.id:<4} {w.slug:<24} {len(w.service_ids):>5}  {w.url:<10} {w.repo_path}")
        if w.collisions:
            print(f"     name clash with another chatbot: {', '.join(w.collisions)}")
    return 0


def cmd_add(args) -> int:
    """Register a chatbot over the services a path's lockfiles name."""
    from .router import _discover_services

    path = str(Path(args.path))
    try:
        names = args.services or _discover_services(path)
    except Exception as exc:  # the router raises HTTPException; unwrap it here
        print(f"could not read {path}: {getattr(exc, 'detail', exc)}", file=sys.stderr)
        return 2

    if not names:
        print(f"no package-lock.json under {path}, and no --services given.",
              file=sys.stderr)
        return 2

    workspace = WorkspaceRegistry().register(
        label=args.label or Path(path).name,
        repo_path=path,
        service_names=names,
        slug=args.slug or "",
    )
    print(f"chatbot #{workspace.id} ({workspace.slug}) -> {workspace.url}")
    print(f"  repo      {workspace.repo_path}")
    print(f"  services  {len(workspace.service_ids)} of {len(names)} found in the graph")
    if len(workspace.service_ids) < len(names):
        missing = len(names) - len(workspace.service_ids)
        print(f"            {missing} not in the graph yet -- ingest the repo, "
              f"then `refresh {workspace.id}`")
    if workspace.collisions:
        print(f"  WARNING   these names are already claimed by another chatbot: "
              f"{', '.join(workspace.collisions)}")
        print("            they share graph nodes, so both will report the same "
              "exposure for them.")
    return 0


def cmd_remove(args) -> int:
    print("removed" if WorkspaceRegistry().remove(args.ref) else "no such chatbot")
    return 0


def cmd_refresh(args) -> int:
    workspace = WorkspaceRegistry().refresh_ids(args.ref)
    if workspace is None:
        print("no such chatbot", file=sys.stderr)
        return 2
    T.clear_caches()
    briefing_mod.clear_cache()
    print(f"#{workspace.id} now sees {len(workspace.service_ids)} service(s)")
    return 0


def cmd_brief(args) -> int:
    """Print the situation pack verbatim -- what the model is told before you ask."""
    scope = _scope(args.ref)
    started = time.perf_counter()
    try:
        pack = briefing_mod.briefing(scope, force=args.force)
    except HydraError as exc:
        print(f"graph unreachable: {exc}", file=sys.stderr)
        return 3
    elapsed = (time.perf_counter() - started) * 1000
    print(RULE)
    print(pack.text)
    print(RULE)
    print(f"{len(pack.text)} chars (~{len(pack.text)//4} tokens) in {elapsed:.0f}ms")
    print("\nsuggested:")
    for question in pack.suggestions:
        print(f"  - {question}")
    return 0


def _check_key() -> bool:
    cfg = config()
    if not cfg.ready:
        print("OPENAI_API_KEY is not set. Put it in .env at the repository root.",
              file=sys.stderr)
        return False
    if not cfg.model_allowed:
        print(f"CHAT_MODEL={cfg.model!r} is not a mini-class model.", file=sys.stderr)
        return False
    return True


async def _ask(scope: Scope, question: str, session: str, show_tools: bool) -> None:
    started = time.perf_counter()
    first = None
    tools_used: list[str] = []

    async for event in agent_mod.stream_answer(scope, question, session):
        if event["type"] == "token":
            if first is None:
                first = time.perf_counter() - started
            sys.stdout.write(event["text"])
            sys.stdout.flush()
        elif event["type"] == "tool":
            tools_used.append(event["name"])
            if show_tools:
                arg = ", ".join(f"{k}={v!r}" for k, v in (event["arguments"] or {}).items())
                sys.stdout.write(f"\n  [{event['name']}({arg})]\n")
                sys.stdout.flush()
        elif event["type"] == "error":
            print(f"\n\nERROR: {event['message']}", file=sys.stderr)

    total = time.perf_counter() - started
    print()
    print(RULE)
    print(
        f"first token {first*1000:.0f}ms" if first else "no tokens",
        f"| total {total:.1f}s",
        f"| tools: {', '.join(tools_used) if tools_used else 'none (answered from the briefing)'}",
    )


def cmd_ask(args) -> int:
    if not _check_key():
        return 2
    scope = _scope(args.ref)
    asyncio.run(_ask(scope, " ".join(args.question), args.session, not args.quiet))
    return 0


def cmd_repl(args) -> int:
    if not _check_key():
        return 2
    scope = _scope(args.ref)
    pack = briefing_mod.briefing(scope)
    print(RULE)
    print(f"chatbot #{scope.workspace.id} -- {scope.workspace.label}")
    print(f"{len(scope.service_ids)} service(s), {pack.threat_count} confirmed threat(s)")
    print("try:", *[f"\n  {q}" for q in pack.suggestions])
    print(f"\n{RULE}\nblank line or ctrl-c to quit\n")

    while True:
        try:
            question = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not question:
            return 0
        asyncio.run(_ask(scope, question, args.session, not args.quiet))
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m blastradius.chat.cli",
        description="Ask a repository's dependency graph questions in English.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ls = sub.add_parser("list", help="every registered chatbot")
    ls.set_defaults(func=cmd_list)

    add = sub.add_parser("add", help="register a chatbot for one repository")
    add.add_argument("path", help="repository path, as ingested")
    add.add_argument("--label", default="", help="human name for the chatbot")
    add.add_argument("--slug", default="", help="url token, e.g. /chat/<slug>")
    add.add_argument("--services", nargs="*", default=None,
                     help="service names to own (default: discover from lockfiles)")
    add.set_defaults(func=cmd_add)

    rm = sub.add_parser("remove", help="forget a chatbot (the graph is untouched)")
    rm.add_argument("ref")
    rm.set_defaults(func=cmd_remove)

    rf = sub.add_parser("refresh", help="re-resolve service ids after a rebuild")
    rf.add_argument("ref")
    rf.set_defaults(func=cmd_refresh)

    br = sub.add_parser("brief", help="print the situation pack the model is given")
    br.add_argument("ref")
    br.add_argument("--force", action="store_true", help="rebuild rather than cache")
    br.set_defaults(func=cmd_brief)

    ask = sub.add_parser("ask", help="ask one question and stream the answer")
    ask.add_argument("ref")
    ask.add_argument("question", nargs="+")
    ask.add_argument("--session", default="cli")
    ask.add_argument("--quiet", action="store_true", help="hide tool calls")
    ask.set_defaults(func=cmd_ask)

    repl = sub.add_parser("repl", help="interactive session against one chatbot")
    repl.add_argument("ref")
    repl.add_argument("--session", default="cli")
    repl.add_argument("--quiet", action="store_true")
    repl.set_defaults(func=cmd_repl)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
