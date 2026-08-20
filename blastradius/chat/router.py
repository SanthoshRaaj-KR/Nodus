"""The HTTP surface: one chatbot per repository, mounted at `/api/chat`.

Routes are keyed by workspace, not global -- `/api/chat/1/ask` and
`/api/chat/2/ask` are different chatbots over different service sets, and
there is deliberately no unscoped "ask the graph" endpoint for a caller to
reach for by accident.

Answers stream as Server-Sent Events, for the same reason `ui/server.py`
already prefers SSE: everything here travels server-to-browser, EventSource
reconnects on its own, and a socket would add a second protocol to carry
one-way traffic. `?stream=false` returns the whole answer as JSON instead,
which is what the CLI and the tests use.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from blastradius.hydra_client import HydraClient, HydraError
from blastradius.ids import IdAllocator

from . import agent as agent_mod
from . import briefing as briefing_mod
from . import tools as T
from .config import config
from .tools import Scope
from .workspaces import WorkspaceRegistry, Workspace

router = APIRouter(prefix="/api/chat", tags=["chat"])

#: Built lazily so importing this module never opens a socket or a database --
#: `ui/server.py` imports it at startup, and the tests import it with no node
#: running at all.
_client: HydraClient | None = None
_ids: IdAllocator | None = None
_registry: WorkspaceRegistry | None = None


def wire(
    client: HydraClient | None = None,
    ids: IdAllocator | None = None,
    registry: WorkspaceRegistry | None = None,
) -> None:
    """Hand the router the connections the host server already holds.

    `ui/server.py` keeps one `HydraClient` and one `IdAllocator` open for the
    process -- the id map is consulted per request and reopening a sqlite file
    per keystroke is the one avoidable round trip -- so the chat routes borrow
    those rather than opening a second pair.
    """
    global _client, _ids, _registry
    if client is not None:
        _client = client
    if ids is not None:
        _ids = ids
    if registry is not None:
        _registry = registry


def registry() -> WorkspaceRegistry:
    global _registry
    if _registry is None:
        _registry = WorkspaceRegistry(ids=_ids)
    return _registry


#: Slug the bottom-right popup always asks. Unlike the CLI's per-repository
#: workspaces, the three console pages have no concept of "which repo" -- one
#: graph is one fleet -- so the popup gets one workspace that owns every
#: service currently in the graph, provisioned on first use.
DEFAULT_REF = "default"


def _ensure_default_workspace() -> Workspace:
    """Auto-register (or refresh) the workspace the popup talks to.

    Re-registering is cheap and idempotent -- `WorkspaceRegistry.register`
    replaces the existing entry for the same `repo_path` rather than stacking
    a duplicate -- so this just re-derives the service list from the graph on
    every call and lets `register` decide whether anything actually changed.
    """
    global _client
    if _client is None:
        _client = HydraClient()
    try:
        rows = _client.query(
            "MATCH (s:Service) RETURN s.name AS name ORDER BY name"
        ).rows
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    names = [str(r["name"]) for r in rows if r.get("name")]
    return registry().register(
        label="All services",
        repo_path=".",
        service_names=names,
        slug=DEFAULT_REF,
    )


def _scope(ref: str) -> Scope:
    """Resolve `/api/chat/<ref>` to one workspace, or 404 with what does exist."""
    global _client, _ids
    if _client is None:
        _client = HydraClient()
    if _ids is None:
        _ids = IdAllocator()

    workspace = registry().get(ref)
    if workspace is None and ref == DEFAULT_REF:
        workspace = _ensure_default_workspace()
    if workspace is None:
        available = [w.summary() for w in registry().list()]
        raise HTTPException(
            status_code=404,
            detail=(
                f"No chatbot {ref!r}. "
                + (
                    "Registered: "
                    + ", ".join(f"#{w['id']} {w['label']}" for w in available)
                    if available
                    else "None registered yet -- POST /api/chat/workspaces with a repo path."
                )
            ),
        )
    return Scope(client=_client, ids=_ids, workspace=workspace)


# --------------------------------------------------------------------------
# workspaces -- the chatbots themselves
# --------------------------------------------------------------------------


@router.get("/workspaces")
def list_workspaces() -> dict:
    """Every chatbot, for the picker at `/chat`."""
    return {"workspaces": [w.summary() for w in registry().list()]}


@router.post("/workspaces")
def create_workspace(payload: dict) -> dict:
    """Register a chatbot for a repository already in the graph.

    Services can be named explicitly, or discovered from the lockfiles on disk
    at `repo_path`. Discovery is the common case: the caller has just ingested
    a checkout and wants a chatbot over exactly what that ingest wrote.

    This does **not** run an ingest. Registering is cheap and reversible;
    ingesting drops and rebuilds graph state, and conflating the two would
    make "add a chatbot" a destructive operation.
    """
    repo_path = str(payload.get("repo_path") or "").strip()
    if not repo_path:
        raise HTTPException(status_code=400, detail="repo_path is required")

    label = str(payload.get("label") or "").strip()
    slug = str(payload.get("slug") or "").strip()
    names = [str(n) for n in (payload.get("service_names") or [])]

    if not names:
        names = _discover_services(repo_path)
    if not names:
        raise HTTPException(
            status_code=400,
            detail=(
                f"No package-lock.json found under {repo_path!r}, and no "
                "service_names were given, so there is nothing for this "
                "chatbot to answer about."
            ),
        )

    workspace = registry().register(
        label=label or Path(repo_path).name,
        repo_path=repo_path,
        service_names=names,
        slug=slug,
    )
    summary = workspace.summary()
    if workspace.collisions:
        # Reported, never silently merged. Two repositories sharing a service
        # name share one graph node, and no filter downstream can separate
        # their exposure again.
        summary["warning"] = (
            "These service names are already claimed by another chatbot: "
            + ", ".join(workspace.collisions)
            + ". They resolve to the same graph nodes, so both chatbots will "
            "report the same exposure for them. Rename the service in one "
            "repository to separate them."
        )
    if not workspace.service_ids:
        summary["warning"] = (
            "None of these services are in the graph yet. Ingest the "
            f"repository first: python -m blastradius.cli ingest --corpus {repo_path}"
        )
    return summary


def _discover_services(repo_path: str) -> list[str]:
    """Service names a scan of this path would write, read from disk.

    Uses the ingest's own discovery and its own naming rule -- the root
    workspace entry of each lockfile, falling back to the folder name -- so a
    workspace registered from a path names exactly what an ingest of that path
    would create.
    """
    from blastradius.ingest.load import discover_services
    from blastradius.ingest.lockfile import parse_package_lock

    root = Path(repo_path).expanduser()
    if not root.exists():
        raise HTTPException(status_code=400, detail=f"no such path: {repo_path}")

    names: list[str] = []
    for project in discover_services(root):
        try:
            lock = parse_package_lock(project / "package-lock.json", repo=project.name)
            names.append(lock.services.get("", project.name))
        except (OSError, ValueError, KeyError):
            names.append(project.name)
    return sorted({n for n in names if n})


@router.delete("/workspaces/{ref}")
def delete_workspace(ref: str) -> dict:
    """Forget a chatbot. The graph keeps its services -- a workspace is a view."""
    return {"removed": registry().remove(ref), "ref": ref}


@router.post("/workspaces/{ref}/refresh")
def refresh_workspace(ref: str) -> dict:
    """Re-resolve service ids after a graph rebuild, and drop cached answers."""
    workspace = registry().refresh_ids(ref)
    if workspace is None:
        raise HTTPException(status_code=404, detail=f"no chatbot {ref!r}")
    T.clear_caches()
    briefing_mod.clear_cache()
    return workspace.summary()


# --------------------------------------------------------------------------
# per-chatbot
# --------------------------------------------------------------------------


@router.get("/{ref}/health")
def health(ref: str) -> dict:
    """Is this chatbot able to answer, and if not, precisely what is missing."""
    cfg = config()
    scope = _scope(ref)
    problems: list[str] = []
    if not cfg.ready:
        problems.append(
            "OPENAI_API_KEY is not set. Put it in .env at the repository root."
        )
    if not cfg.model_allowed:
        problems.append(
            f"CHAT_MODEL={cfg.model!r} is not a mini-class model, which this "
            "project restricts itself to."
        )
    if not scope.workspace.service_ids:
        problems.append(
            "This chatbot owns no graph services. Ingest the repository, then "
            f"POST /api/chat/workspaces/{ref}/refresh."
        )
    graph_ok = True
    try:
        T._read_epoch(scope.client)
    except HydraError as exc:
        graph_ok = False
        problems.append(f"HydraDB is unreachable: {exc}")

    return {
        "ok": not problems,
        "workspace": scope.workspace.summary(),
        "graph_reachable": graph_ok,
        "config": cfg.redacted(),
        "problems": problems,
    }


@router.get("/{ref}/briefing")
def get_briefing(ref: str) -> dict:
    """The situation pack and the starter questions, for the UI header."""
    scope = _scope(ref)
    try:
        pack = briefing_mod.briefing(scope)
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    return {**pack.to_dict(), "workspace": scope.workspace.summary()}


@router.post("/{ref}/warm")
def warm(ref: str) -> dict:
    """Pre-build the caches so the first question does not pay for them.

    Cold, a briefing costs a whole-graph index build plus one sweep per owned
    service -- about 2.4s on the twelve-service corpus. Warm, it is ~16ms. The
    page calls this on load, so that cost lands while somebody is still
    reading the screen rather than after they have hit send.
    """
    scope = _scope(ref)
    try:
        pack = briefing_mod.briefing(scope)
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    return {"warm": True, "workspace": scope.workspace.id, "threats": pack.threat_count}


@router.delete("/{ref}/session/{session_id}")
async def clear_session(ref: str, session_id: str) -> dict:
    """Forget one conversation, leaving the repository's data untouched."""
    scope = _scope(ref)
    session = agent_mod.session_for(scope.workspace.id, session_id)
    await session.clear_session()
    return {"cleared": True, "workspace": scope.workspace.id, "session": session_id}


@router.post("/{ref}/ask")
async def ask(ref: str, request: Request, stream: bool = True) -> Any:
    """Ask one chatbot one question.

    Streams SSE by default. `?stream=false` returns `{answer, tools_called}`
    in one JSON body, which is what the CLI and the tests consume.
    """
    scope = _scope(ref)
    cfg = config()

    try:
        payload = await request.json()
    except (json.JSONDecodeError, ValueError):
        payload = {}
    message = str(payload.get("message") or "").strip()
    session_id = str(payload.get("session_id") or "default").strip() or "default"

    if not message:
        raise HTTPException(status_code=400, detail="message is required")
    if not cfg.ready:
        raise HTTPException(
            status_code=503,
            detail="OPENAI_API_KEY is not set. Add it to .env at the repository root.",
        )
    if not cfg.model_allowed:
        raise HTTPException(
            status_code=503,
            detail=f"CHAT_MODEL={cfg.model!r} is not a mini-class model.",
        )

    if not stream:
        result = await agent_mod.answer(scope, message, session_id, cfg)
        return JSONResponse(result)

    async def events():
        try:
            async for event in agent_mod.stream_answer(scope, message, session_id, cfg):
                yield f"data: {json.dumps(event, default=str)}\n\n"
                # Hand the loop back between frames so a long answer cannot
                # starve the other requests this server is serving.
                await asyncio.sleep(0)
        except Exception as exc:  # never leave the browser on an open stream
            yield f'data: {json.dumps({"type": "error", "message": str(exc)})}\n\n'

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            # nginx buffers event-streams by default, which turns token
            # streaming back into one delivery at the end.
            "X-Accel-Buffering": "no",
        },
    )
