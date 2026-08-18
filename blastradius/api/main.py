"""FastAPI surface over the blast-radius queries.

Thin on purpose: every endpoint is a call into :mod:`blastradius.query.blast`
plus JSON serialisation. The interesting work is in the graph, and keeping the
API dumb makes the demo's timings honest -- what the UI shows as elapsed time
is query time, not framework overhead.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .. import schema
from ..hydra_client import HydraClient, HydraError
from ..query import blast
from ..query.advisory import Advisory

ROOT = Path(__file__).resolve().parent.parent.parent
ADVISORIES = ROOT / "advisories"
STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Blast Radius", version="1.0.0")
client = HydraClient()


class AdvisoryIn(BaseModel):
    advisory_id: str = "AD-HOC"
    package: str
    ecosystem: str = "npm"
    affected_versions: list[str] = []
    affected_range: str = ""
    published_at: int = 0
    withdrawn_at: int = schema.STILL_LIVE
    severity: str = "unknown"
    iocs: dict = {}


@app.get("/api/health")
def health() -> dict:
    """Is the node up, and what is in the graph right now?"""
    try:
        counts = client.counts_by_label(schema.NODE_LABELS)
        return {"ok": True, "counts": counts}
    except HydraError as exc:
        return JSONResponse(
            status_code=503, content={"ok": False, "error": str(exc)}
        )


@app.get("/api/advisories")
def list_advisories() -> list[dict]:
    """The sample advisories on disk -- the teammate contract, as files."""
    out = []
    for path in sorted(ADVISORIES.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["_file"] = path.name
        out.append(raw)
    return out


@app.get("/api/services")
def services() -> list[dict]:
    result = client.query(
        "MATCH (s:Service) RETURN s.id AS id, s.name AS name, s.repo AS repo "
        "ORDER BY name"
    )
    return result.rows


@app.post("/api/assess")
def assess(payload: AdvisoryIn) -> dict:
    """Run the full assessment for one advisory."""
    started = time.perf_counter()
    try:
        advisory = Advisory.from_dict(payload.model_dump())
        result = blast.assess(client, advisory)
    except HydraError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None

    findings = [asdict(f) for f in sorted(result.findings, key=lambda f: (f.rank, f.service))]
    return {
        "advisory_id": result.advisory_id,
        "package": result.package,
        "affected_keys": result.affected_keys,
        "findings": findings,
        "timings_ms": result.timings_ms,
        "wall_ms": (time.perf_counter() - started) * 1000,
        "max_call_depth": result.max_call_depth,
        "tiers": {
            "P0 CONFIRMED": "exposed and a persistence artifact is on disk",
            "P1 REACHABLE": "exposed and an HTTP route reaches the calling code",
            "P2 IMPORTED": "exposed and imported from source, no route path found",
            "P3 INSTALLED": "in the lockfile, never imported",
        },
    }


@app.post("/api/paths")
def paths(payload: dict) -> dict:
    """Dependency chains from compromised packages out to services."""
    keys = payload.get("keys") or []
    targets = payload.get("services") or []
    try:
        found = blast.dependency_paths(client, keys, targets)
    except HydraError as exc:
        # MSpaths config is the most server-version-sensitive thing we issue,
        # so surface the real message rather than an empty result that would
        # read as "no path exists".
        raise HTTPException(status_code=503, detail=str(exc)) from None
    return {"paths": found, "count": len(found)}


if STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")
