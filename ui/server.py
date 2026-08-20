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
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from blastradius import schema
from blastradius.hydra_client import HydraClient, HydraError
from blastradius.ids import IdAllocator
from blastradius.pkg import graphview as pkgview
from blastradius.pkg import incident as pkgincident
from blastradius.query import blast, graphview
from blastradius.query.advisory import Advisory

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


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


#: The redesigned console. Built from ui/web (React + Vite) into static/app,
#: which the /static mount above already serves -- so there is no second
#: runtime in production, only a build step. Falls back to the standalone
#: vanilla build when the bundle has not been built yet, because a 404 here
#: looks like a broken route rather than a missing `npm run build`.
@app.get("/console")
def console() -> FileResponse:
    bundled = STATIC / "app" / "index.html"
    if bundled.exists():
        return FileResponse(bundled)
    return FileResponse(STATIC / "console.html")
