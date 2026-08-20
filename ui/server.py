"""The `ui` frontend server -- Blast Radius Explorer.

Deliberately separate from `blastradius.api`. That one is the machine-facing
assessment API a CI job would call; this one is the human-facing explorer, and
keeping them apart means the demo UI can be restarted, re-skinned or thrown
away without touching the thing other tools depend on.

It talks to HydraDB directly rather than proxying the other server, so it has
one fewer moving part to fail on stage.

    python -m uvicorn ui.server:app --port 8100
    python -m blastradius.cli ui          # same thing, shorter
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from queue import Empty

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from blastradius import schema
from blastradius.hydra_client import HydraClient, HydraError
from blastradius.ids import IdAllocator
from blastradius.pkg import graphview as pkgview
from blastradius.pkg import incident as pkgincident
from blastradius.query import blast, codereach, graphview
from blastradius.query.advisory import Advisory

from .live import state as livestate

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
ADVISORIES = HERE.parent / "advisories"

app = FastAPI(title="Blast Radius Explorer", version="1.0.0")
client = HydraClient()

#: purl -> integer id, shared with the CLI. Held open for the process
#: because every package-view request resolves a target through it, and
#: reopening a sqlite file per keystroke is the one avoidable round trip.
ids = IdAllocator()


@app.get("/api/health")
def health():
    try:
        counts = client.counts_by_label(schema.ALL_NODE_LABELS)
        return {"ok": True, "counts": counts, "empty": not any(counts.values())}
    except HydraError as exc:
        return JSONResponse(status_code=503, content={"ok": False, "error": str(exc)})


#: mode -> (read_epoch it was built from, payload). Building a view costs six
#: unpinned edge sweeps at 500-770ms each; the result only changes when data
#: does, so it is cached against the server's own write epoch.
_graph_cache: dict[str, tuple[int | None, dict]] = {}


def _read_epoch() -> int | None:
    """The node's current read snapshot, or None if it did not report one.

    Any query carries it back, so this is one cheap pinned lookup rather than
    a scan. Returning None disables caching rather than risking a stale answer
    -- for a tool that reports exposure, serving yesterday's graph is worse
    than being slow.
    """
    try:
        return client.query("MATCH (n {id: 0}) RETURN n.id AS id").read_epoch
    except HydraError:
        return None


@app.get("/api/graph")
def graph(mode: str = "micro"):
    """The whole layered graph for the code view.

    Returned in full rather than filtered by query: the blast-radius
    highlighting is a reverse BFS the browser can do in microseconds, and
    round-tripping on every keystroke would make the search feel broken.

    Only `micro` is served here. The macro view used to be the other half of
    this endpoint -- a whole-graph sweep of every service and package by
    resolved depth -- and it now comes from /api/pkg/graph instead, which
    answers against one exact version rather than shipping the graph out and
    letting the browser guess by name. `mode=macro` is rejected rather than
    redirected: the two return different shapes, so a caller still asking for
    it wants the sweep, and quietly handing back something else would look
    like the sweep had gone wrong.
    """
    if mode != "micro":
        raise HTTPException(
            status_code=400,
            detail="mode must be 'micro'; the macro view is served by /api/pkg/graph",
        )

    epoch = _read_epoch()
    cached = _graph_cache.get(mode)
    if cached and epoch is not None and cached[0] == epoch:
        return cached[1]

    try:
        payload = graphview.micro_graph(client)
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None

    if epoch is not None:
        _graph_cache[mode] = (epoch, payload)
    return payload


def _advisory_files() -> list[Path]:
    """Every advisory on disk: hand-written samples plus scanned ones.

    ``advisories/generated/`` is written by `blastradius.cli osv-scan` from a
    real repository scan, and it is searched recursively so a regenerated set
    replaces itself wholesale without disturbing the samples beside it.
    Scanned advisories sort first: they describe the repository in the graph,
    while the samples describe a scenario.
    """
    generated = sorted((ADVISORIES / "generated").glob("*.json"))
    handwritten = sorted(ADVISORIES.glob("*.json"))
    return generated + handwritten


@app.get("/api/advisories")
def advisories():
    """Advisory files on disk become the one-click chips in the header."""
    out = []
    for path in _advisory_files():
        raw = json.loads(path.read_text(encoding="utf-8"))
        advisory = Advisory.from_dict(raw)

        # The chip drives the same search box a human types into, so it has to
        # name a version that is actually in this graph. Taking the advisory's
        # first affected version instead would produce a chip that highlights
        # nothing whenever the corpus holds a different one -- which looks
        # exactly like "you are not affected".
        query = advisory.package
        try:
            held = blast.held_versions(client, advisory.package)
            matching = [h["version"] for h in held if advisory.matches(h["version"])]
            if matching:
                query = f"{advisory.package}@{matching[0]}"
        except HydraError:
            pass  # node down; the package name alone still filters usefully

        out.append(
            {
                "advisory_id": advisory.advisory_id,
                "package": advisory.package,
                "severity": advisory.severity,
                "query": query,
                "range": advisory.affected_range,
                "file": path.name,
                # Where the chip came from, so a demo can say "this is your
                # repo" rather than "this is our sample".
                "source": raw.get("source", "sample"),
                "scanned_repo": raw.get("scanned_repo", ""),
                # What the advisory actually says. Without these a reader gets
                # an identifier and a severity word, which names a finding
                # without explaining it -- "CVE-2020-28500, moderate" tells you
                # nothing about what breaks or how to fix it. The scan already
                # wrote all of this to disk; withholding it was the bug.
                "summary": raw.get("summary", ""),
                "cvss_vector": raw.get("cvss_vector", ""),
                "affected_versions": list(raw.get("affected_versions") or []),
                "fixed_versions": list(raw.get("fixed_versions") or []),
                "aliases": list(raw.get("aliases") or []),
                "references": list(raw.get("references") or []),
                "published_at": raw.get("published_at") or 0,
            }
        )
    return out


@app.get("/api/assess")
def assess(package: str, version: str = "", range: str = ""):
    """Severity verdict for the queried package, for the footer strip."""
    advisory = Advisory(
        advisory_id="EXPLORER",
        package=package,
        affected_versions=[version] if version and not range else [],
        affected_range=range or ("" if version else "*"),
    )
    try:
        result = blast.assess(client, advisory)
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    return {
        "package": package,
        "affected_keys": result.affected_keys,
        "total_ms": result.total_ms,
        "findings": [
            {
                "service": f.service,
                "tier": f.tier,
                "min_depth": f.min_depth,
                "dev_only": f.dev_only,
                "routes": f.routes,
                "functions": f.functions,
                "artifacts": f.artifacts,
            }
            for f in sorted(result.findings, key=lambda f: (f.rank, f.service))
        ],
    }


# -- macro view: package blast radius ---------------------------------------
#
# The supply-chain half of the Explorer. Where /api/graph returns a whole-graph
# sweep for the browser to highlight, these return an answer already computed
# against HydraDB: which projects resolved one exact version, and with what
# evidence. The difference is the point -- see blastradius/pkg/graphview.py.
#
# The routes keep their /api/pkg prefix. "Macro" is the tab a human clicks;
# what the endpoint does is answer a question about one package version, and
# naming it after the placement in the UI would make it the wrong name the
# first time the view moves.


def _split_spec(spec: str) -> tuple[str, str]:
    """`lodash@4.17.21` -> ("lodash", "4.17.21"). Scoped names keep their @."""
    trimmed = spec.strip()
    at = trimmed.rfind("@")
    if at <= 0:
        raise HTTPException(
            status_code=400,
            detail=f"expected name@version, got {spec!r}",
        )
    return trimmed[:at], trimmed[at + 1 :]


@app.get("/api/pkg/graph")
def pkg_graph(spec: str):
    name, version = _split_spec(spec)
    try:
        return pkgview.package_graph(client, ids, name, version)
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None


@app.get("/api/pkg/project")
def pkg_project():
    """The whole project: every exposed package and the chain that reaches it.

    This is the default package view. ``/api/pkg/graph`` answers "tell me about
    this one version", which is the right question only once you already know
    which version to ask about; after a scan, the question is "what is wrong
    with this repo", and that one needs the tree.

    Cached against the read epoch like the code view, and for the same reason:
    the exposure model is several unpinned whole-graph sweeps plus a BFS, which
    is far too slow to redo per click and changes only when the data does.
    """
    epoch = _read_epoch()
    cached = _graph_cache.get("pkg-project")
    if cached and epoch is not None and cached[0] == epoch:
        return cached[1]

    try:
        payload = pkgview.project_graph(client, ids)
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None

    if epoch is not None:
        _graph_cache["pkg-project"] = (epoch, payload)
    return payload


@app.get("/api/pkg/targets")
def pkg_targets(limit: int = 6):
    """Versions worth marking, so the demo is one click rather than typing."""
    try:
        return pkgview.suggested_targets(client, limit=limit)
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None


@app.post("/api/pkg/incident")
def pkg_mark(spec: str, window_hours: int = 6):
    """Mark one exact version as compromised.

    Synthetic throughout: this writes an Incident node in our own database
    pointing at an ordinary, healthy public package. Nothing is downloaded,
    nothing is executed, and no package is modified. The edge lands on the
    PackageVersion and never on the Package, which is what keeps 4.17.20
    untouched when 4.17.21 is marked.
    """
    name, version = _split_spec(spec)
    try:
        incident = pkgincident.create_incident(
            client, ids, name, version,
            incident_id=pkgincident.incident_id_for(name, version),
            window_hours=window_hours,
            verbose=False,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    return {
        "marked": True,
        "spec": f"{name}@{version}",
        "incident_id": incident.incident_id,
        "live_from": incident.live_from,
        "live_until": incident.live_until,
        "synthetic": True,
    }


@app.delete("/api/pkg/incident")
def pkg_unmark(spec: str):
    """Retract the simulated compromise, so the same target can be re-run."""
    name, version = _split_spec(spec)
    try:
        removed = pkgincident.clear_incident(client, ids, name, version)
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    return {"marked": False, "spec": f"{name}@{version}", "removed": removed}


# ==========================================================================
# Live: point the console at a repository, then watch npm in real time
# ==========================================================================

def _sse(payload: dict) -> str:
    """One Server-Sent Event frame.

    SSE rather than a WebSocket because every message here travels
    server-to-browser. A socket would add a second protocol, a reconnect
    handshake and a keep-alive of its own to carry traffic that only ever goes
    one way; EventSource reconnects on its own and survives a server restart
    without the page knowing.
    """
    return f"data: {json.dumps(payload, default=str)}\n\n"


@app.get("/api/graph/full")
def graph_full(
    satisfied_by: bool = False,
    lockfile_entries: bool = False,
    max_nodes: int = 20_000,
):
    """Every node and edge, for the circle view.

    Cached against `read_epoch` like the micro view: the build is a handful of
    whole-graph sweeps, and the result changes only when a write lands, so an
    ingest invalidates it without anyone having to remember to.
    """
    from blastradius.pkg.fullgraph import GraphSpec, build_full_graph

    key = f"full:{satisfied_by}:{lockfile_entries}:{max_nodes}"
    epoch = _read_epoch()
    cached = _graph_cache.get(key)
    if cached and epoch is not None and cached[0] == epoch:
        return cached[1]

    try:
        payload = build_full_graph(
            client,
            GraphSpec(
                include_satisfied_by=satisfied_by,
                include_lockfile_entries=lockfile_entries,
                max_nodes=max_nodes,
            ),
        )
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None

    if epoch is not None:
        _graph_cache[key] = (epoch, payload)
    return payload


@app.get("/api/graph/node/{node_id}")
def graph_node(node_id: int):
    """One node's full detail, for the click panel.

    Fetched on demand rather than shipped with the graph: the payload already
    carries 2,600 nodes, and the long-form fields nobody reads until they click
    would roughly double it.
    """
    from blastradius.pkg.fullgraph import NODE_FIELDS

    kind = ids.key_for(node_id)
    label = kind[0] if kind else None
    if label is None:
        raise HTTPException(status_code=404, detail=f"unknown node id {node_id}")

    fields = NODE_FIELDS.get(label, ("name",))
    projection = ", ".join(f"n.{f} AS {f}" for f in fields)
    try:
        rows = client.query(
            f"MATCH (n:{label} {{id: $id}}) RETURN n.id AS id, {projection}",
            {"id": node_id},
        )
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    if not len(rows):
        raise HTTPException(status_code=404, detail=f"no {label} with id {node_id}")

    return {
        "id": node_id,
        "label": label,
        "key": kind[1] if kind else "",
        "meta": {k: v for k, v in dict(rows.rows[0]).items() if v not in ("", None)},
    }


# -- the Explorer: confirmed threats, and how far into the code they reach ---
#
# One index serves both routes. Building it costs a sweep of every
# PackageVersion (~800ms here), which is fine once and absurd per click, so it
# is cached on the same read epoch /api/graph uses: a fresh ingest bumps the
# epoch and the next request rebuilds, and nothing else can serve a stale
# answer.

_reach_cache: tuple[int | None, codereach.CodeIndex | None] = (None, None)


def _code_index() -> codereach.CodeIndex:
    global _reach_cache

    epoch = _read_epoch()
    cached_epoch, cached_index = _reach_cache
    if cached_index is not None and epoch is not None and cached_epoch == epoch:
        return cached_index

    try:
        index = codereach.build_index(client)
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None

    if epoch is not None:
        _reach_cache = (epoch, index)
    return index


@app.get("/api/explorer/threats")
def explorer_threats():
    """Every confirmed threat, ranked by whether code here can reach it.

    Confirmed, not suspected: published advisories, incidents somebody wrote
    down, and registry deprecations. The heuristic publish-time leads live on
    the live console and top out at INVESTIGATE, and mixing the two would put
    a guess and a CVE in one list under one heading.
    """
    index = _code_index()
    try:
        found = codereach.threats(client, index)
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None

    rows = [t.to_dict() for t in found]
    return {
        "threats": rows,
        "counts": {
            "total": len(rows),
            "in_code": sum(1 for r in rows if r["in_code"]),
            "compromised": sum(1 for r in rows if r["kind"] == "compromised"),
            "vulnerable": sum(1 for r in rows if r["kind"] == "vulnerable"),
            "deprecated": sum(1 for r in rows if r["kind"] == "deprecated"),
        },
        # The denominator matters as much as the count: "2 of 13 reach code"
        # is a different morning from "13 findings".
        "scanned": {
            "versions": len(index.versions),
            "imports": len(index.imports),
            "functions": len(index.functions),
        },
    }


@app.get("/api/explorer/reach")
def explorer_reach(spec: str):
    """The path from one threatened version to the functions that run it."""
    name, version = _split_spec(spec)
    index = _code_index()
    try:
        reach = codereach.code_reach(client, name, version, index)
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    return reach.to_dict()


@app.post("/api/repo/inspect")
def repo_inspect(path: str):
    """What a scan would find here, without committing to running one.

    Separate from the ingest so a mistyped path costs nothing. The pipeline
    takes tens of seconds and drops the store on the way in; discovering the
    directory was wrong *after* that is the expensive order to find out.
    """
    try:
        resolved = livestate.resolve_repo(path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return livestate.describe_repo(resolved)


@app.post("/api/repo/ingest")
def repo_ingest(path: str, reset: bool = True):
    """Run the full pipeline against any checkout, on a thread.

    `reset` defaults to true because the graph describes one fleet: ingesting
    a second repository on top of a first leaves both in the graph with no way
    to tell whose exposure is whose.
    """
    try:
        job = livestate.start_ingest(path, reset=reset)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    return job.to_dict()


@app.get("/api/repo/status")
def repo_status():
    return {
        "running": livestate.job_running,
        "job": livestate.job.to_dict() if livestate.job else None,
    }


@app.post("/api/live/watch/start")
def watch_start():
    return livestate.start_watcher()


@app.post("/api/live/watch/stop")
def watch_stop():
    return livestate.stop_watcher()


@app.get("/api/live/status")
def live_status():
    return livestate.snapshot()


@app.get("/api/live/alerts")
def live_alerts(limit: int = 100, kind: str = ""):
    alerts = [a.to_dict() for a in livestate.watcher.alerts]
    if kind:
        alerts = [a for a in alerts if a["kind"] == kind]
    return {"alerts": alerts[-limit:], "total": len(livestate.watcher.alerts)}


@app.get("/api/live/bursts")
def live_bursts(window_seconds: int = 900):
    return {"bursts": livestate.watcher.correlated_bursts(window_seconds)}


@app.post("/api/simulate/run")
def simulate_run(spec: str):
    """Treat one package version as compromised and answer everything.

    The incident is synthetic and points at an ordinary, healthy public
    package: nothing is downloaded, nothing is executed, and no package is
    modified. It is a node in our own database, and `clear` removes it.
    """
    try:
        return livestate.start_simulation(spec)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None


@app.post("/api/simulate/clear")
def simulate_clear(spec: str):
    try:
        return {"removed": livestate.clear_simulation(spec)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


@app.get("/api/live/stream")
async def live_stream(request: Request):
    """One stream carrying alerts, ingest progress and simulation stages.

    A single channel rather than one per producer, so ordering survives: an
    alert that lands mid-ingest really did land then, and two sockets would
    leave that to whichever arrived first.
    """
    import asyncio

    q = livestate.bus.subscribe()

    async def events():
        try:
            # A late subscriber is not a new one -- send the current state
            # first so a browser opened halfway through an ingest does not
            # show an empty console until the next event happens to fire.
            yield _sse({"type": "snapshot", **livestate.snapshot()})
            last_beat = time.monotonic()
            while True:
                if await request.is_disconnected():
                    break
                try:
                    yield _sse(q.get_nowait())
                    continue
                except Empty:
                    pass
                # The registry goes quiet for stretches, and a proxy that sees
                # no bytes will close an idle connection as dead.
                if time.monotonic() - last_beat > 15:
                    last_beat = time.monotonic()
                    yield _sse({"type": "heartbeat", "at": int(time.time())})
                await asyncio.sleep(0.2)
        finally:
            livestate.bus.unsubscribe(q)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # nginx buffers by default, which turns a live stream into a
            # batch delivered whenever the buffer happens to fill.
            "X-Accel-Buffering": "no",
        },
    )


app.mount("/static", StaticFiles(directory=STATIC), name="static")


def _console_file() -> Path:
    """The console, preferring the built bundle over the standalone build.

    Built from ui/web (React + Vite) into static/app, which the /static mount
    above already serves -- so there is no second runtime in production, only
    a build step. Falls back to the standalone vanilla console when nobody has
    run `npm run build`, because a 404 looks like a broken route rather than a
    missing build.
    """
    bundled = STATIC / "app" / "index.html"
    return bundled if bundled.exists() else STATIC / "console.html"


@app.get("/")
def index() -> FileResponse:
    """The console is the front door.

    There used to be two UIs on this server answering the same questions
    differently -- the original Explorer at / and the redesigned console at
    /console -- which meant whichever one you happened to open decided what
    you learned. The console supersedes it, so it gets the root, and the
    Explorer stays reachable at /explorer rather than being deleted: it is
    still the only view of the micro/code graph that does not depend on the
    bundle being built.
    """
    return FileResponse(_console_file())


@app.get("/console")
def console() -> FileResponse:
    """Kept so existing links and bookmarks do not break."""
    return FileResponse(_console_file())


@app.get("/explorer")
def explorer() -> FileResponse:
    """Confirmed threats, and how far each one reaches into this code.

    Two questions, in order: what is definitely wrong with what we installed,
    and which of those can actually be reached from a line of source here. The
    second is what the package graph is for -- 1,703 resolved versions and 8
    external imports means almost nothing in the tree is named by this code,
    and a list that cannot say which is which is the flat scan this project
    exists to beat.

    Served no-store for the same reason /graph is: FileResponse sends a
    Last-Modified that browsers honour from memory cache within a session, so
    an edited page keeps rendering the previous build until a hard reload.
    """
    return FileResponse(
        STATIC / "index.html",
        headers={"Cache-Control": "no-store, must-revalidate"},
    )


@app.get("/graph")
def graph_page() -> FileResponse:
    """The live graph: every node as a circle, lit up as alerts arrive.

    Served no-store. FileResponse sends a Last-Modified that browsers happily
    honour from memory cache within a session, so an edited page keeps
    rendering the previous build until a hard reload -- which looks exactly
    like the edit not working. This is a local dev console; the byte cost of
    re-sending 40KB is not worth that confusion.
    """
    return FileResponse(
        STATIC / "graph.html",
        headers={"Cache-Control": "no-store, must-revalidate"},
    )
