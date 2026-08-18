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
from blastradius.query import blast, graphview
from blastradius.query.advisory import Advisory

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
ADVISORIES = HERE.parent / "advisories"

app = FastAPI(title="Blast Radius Explorer", version="1.0.0")
client = HydraClient()


@app.get("/api/health")
def health():
    try:
        counts = client.counts_by_label(schema.NODE_LABELS)
        return {"ok": True, "counts": counts, "empty": not any(counts.values())}
    except HydraError as exc:
        return JSONResponse(status_code=503, content={"ok": False, "error": str(exc)})


@app.get("/api/graph")
def graph(mode: str = "macro"):
    """The whole layered graph for one view.

    Returned in full rather than filtered by query: the blast-radius
    highlighting is a reverse BFS the browser can do in microseconds, and
    round-tripping on every keystroke would make the search feel broken.
    """
    if mode not in ("macro", "micro"):
        raise HTTPException(status_code=400, detail="mode must be 'macro' or 'micro'")
    try:
        builder = graphview.macro_graph if mode == "macro" else graphview.micro_graph
        return builder(client)
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None


@app.get("/api/advisories")
def advisories():
    """Advisory files on disk become the one-click chips in the header."""
    out = []
    for path in sorted(ADVISORIES.glob("*.json")):
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


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")
