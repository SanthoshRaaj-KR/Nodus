"""The package blast radius, in the shape the Explorer draws.

The two existing views are whole-graph sweeps: every service, every package,
laid out in columns, with the highlight computed in the browser by reverse BFS
from whatever the user typed. That is the right design for them -- the code
graph is small, and the question there really is "what reaches this".

This view is deliberately not that. It is scoped to **one compromised
version**, and the highlight is not computed in the browser at all: exposure is
a fact already stored on an edge, so guessing it client-side by matching
package names would reintroduce exactly the range-only heuristic the whole
model exists to replace. The server marks each node and says with which
evidence atoms.

The column order is the argument:

    THREAT -> COMPROMISED -> RANGE ADMITS -> LOCKFILE RESOLVES -> PROJECTS

Column 2 (range admits) is a **dead end**. It holds every package version
whose declared range would accept the compromised one -- the leads a
range-only tool reports -- and it connects to nothing on its right, because
admitting a version is not installing it. Column 3 carries the resolutions a
lockfile actually recorded, and only those reach a project. On the corpus in
this repo column 2 holds 25 nodes and column 4 holds 1, and drawing them side
by side makes that difference impossible to miss.

Column 5 holds the relational neighbours -- shared maintainer, shared
repository, shared publisher, typosquats. They sit right next to the
compromised node and stay cold, which is the evidence model drawn rather than
described: a relational atom never raises a finding above INVESTIGATE.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from .. import schema
from ..hydra_client import HydraClient, HydraError
from ..ids import IdAllocator
from .blast import BlastRadiusEngine, Confidence, Evidence

__all__ = ["package_graph", "suggested_targets", "COLUMNS"]

COLUMNS = [
    "THREAT",
    "COMPROMISED VERSION",
    "RANGE ADMITS - UNCONFIRMED",
    "LOCKFILE RESOLVES - CONFIRMED",
    "EXPOSED PROJECTS",
    "RELATED BY IDENTITY",
]

#: The middle column is what a range-only tool would report in full. It is
#: capped for the drawing only; the count in the column header and in the
#: footer metric is the true one, so the cap never understates the over-report.
MAX_DRAWN_POSSIBLE = 30
MAX_DRAWN_RELATED = 24


def _severity_of(advisory: dict) -> str:
    """The advisory's severity word, or "" when nothing rated it.

    HydraDB answers an unwritten property with ``{"type": "null"}`` rather
    than a missing key, so a graph written before `severity` existed on the
    label hands back a dict here. Anything that is not a usable word is
    treated as unrated -- which it is.
    """
    raw = advisory.get("severity")
    if not isinstance(raw, str):
        return ""
    raw = raw.strip().lower()
    return "" if raw in ("", "unknown", schema.UNKNOWN_STR.lower()) else raw


def _advisory_subtitle(advisory: dict) -> str:
    severity = _severity_of(advisory)
    vector = advisory.get("cvss_vector")
    vector = vector if isinstance(vector, str) and vector.strip() else "no vector"
    return f"{severity.upper()} - {vector}" if severity else vector


def _fmt_ts(value: Any) -> str:
    """Epoch seconds -> a date, or a word where the sentinel means something."""
    try:
        ts = int(value)
    except (TypeError, ValueError):
        return "unknown"
    if ts <= schema.UNKNOWN_TS:
        return "unknown"
    if ts >= schema.STILL_LIVE:
        return "still live"
    return dt.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")


def _service_for_entries(client: HydraClient, entries: list[dict]) -> dict[int, str]:
    """Which project each lockfile entry belongs to.

    An entry hangs off a Lockfile, which hangs off a Service, and one pattern
    carries one relationship type -- so this is a pinned single hop per entry
    rather than one two-hop pattern. There is one entry per project per
    version, so the loop runs over a handful of rows, not over the corpus.
    """
    out: dict[int, str] = {}
    for entry in entries:
        try:
            rows = client.query(
                "MATCH (l:Lockfile)-[:HAS_ENTRY]->(e:LockfileEntry {id: $id}) "
                "RETURN l.service AS service, l.path AS path",
                {"id": entry["id"]},
            )
        except HydraError:
            continue
        if len(rows):
            out[entry["id"]] = rows.rows[0].get("service") or ""
    return out


def package_graph(
    client: HydraClient,
    ids: IdAllocator,
    name: str,
    version: str,
    max_depth: int = 5,
) -> dict:
    """One compromised version, everything it touches, and why."""
    engine = BlastRadiusEngine(client, ids, max_depth=max_depth)
    # Q3 is skipped: it is the single most expensive query here and the
    # view never draws its rows. The panel redraws on every click, so a
    # ~110 ms walk nothing reads would be paid over and over.
    result = engine.analyse(name, version, include_transitive=False)
    if not result.exists:
        return {
            "mode": "package",
            "cols": COLUMNS,
            "nodes": [],
            "edges": [],
            "serverHot": True,
            "target": f"{name}@{version}",
            "exists": False,
            "stats": {},
            "findings": [],
        }

    nodes: list[dict] = []
    edges: list[list[str]] = []
    target_id = result.target
    entry_service = _service_for_entries(client, result.lockfile_entries)
    compromised = bool(result.incidents)
    #: Whether anything at all marks this version. Without an incident or an
    #: advisory there is nothing to be exposed *to*, and a project resolving
    #: the version is a fact about an installation, not a finding.
    flagged = compromised or bool(result.advisories)

    # -- column 0: the threat ---------------------------------------------
    for incident in result.incidents:
        nid = "inc:" + str(incident.get("incident_id"))
        nodes.append({
            "id": nid, "layer": 0, "kind": "threat",
            "label": incident.get("incident_id") or "INCIDENT",
            "sub": "{} - live {}".format(
                incident.get("status", ""), _fmt_ts(incident.get("live_from"))
            ),
            "hot": True,
            "conf": Confidence.CERTAIN,
            "why": [Evidence.DIRECTLY_COMPROMISED],
            "verdict": "Simulated supply-chain compromise, recorded in our own database",
            "alarm": True,
            "flag": "INCIDENT",
            "file": "synthetic incident - no real package involved",
            "detail": incident.get("summary", ""),
        })
        edges.append([nid, target_id])

    for advisory in result.advisories:
        nid = "adv:" + str(advisory.get("advisory_id"))
        nodes.append({
            "id": nid, "layer": 0, "kind": "advisory",
            "label": advisory.get("advisory_id") or "ADVISORY",
            # The numeric score is deliberately absent -- the OSV rows carry
            # a vector and an empty score, and a number nobody computed is
            # worse than none. The qualitative label is real, though: it comes
            # straight from the feed, so it leads.
            "sub": _advisory_subtitle(advisory),
            "severity": _severity_of(advisory),
            "hot": False,
            "conf": Confidence.MEDIUM,
            "why": [Evidence.KNOWN_VULNERABILITY],
            "verdict": "Published advisory affecting this version",
            "alarm": True,
            "file": "advisory",
            "detail": advisory.get("summary", ""),
        })
        edges.append([nid, target_id])

    # -- column 1: the compromised version --------------------------------
    meta = result.metadata
    nodes.append({
        "id": target_id, "layer": 1,
        "kind": "compromised" if compromised else "subject",
        "label": result.target,
        "sub": "published " + _fmt_ts(meta.get("published_at"))
               + (" - install hook" if meta.get("has_install_script") else ""),
        "pkg": meta.get("name", name),
        "version": meta.get("version", version),
        "hot": compromised,
        "conf": Confidence.CERTAIN if compromised else Confidence.LOW,
        "flag": "COMPROMISED" if compromised else None,
        "why": [Evidence.DIRECTLY_COMPROMISED] if compromised else [],
        "neg": [] if compromised else ["no incident names this exact version"],
        "verdict": (
            "Compromised - a simulated incident names this exact version"
            if compromised else
            "Under review - nothing in the graph marks this version"
        ),
        "alarm": compromised,
        "file": "node_modules/" + str(meta.get("name", name)),
        "detail": "licence " + str(meta.get("license") or "unknown"),
    })

    # -- column 2: what a range-only tool would report ---------------------
    for dependent in result.direct_dependents[:MAX_DRAWN_POSSIBLE]:
        nid = dependent["key"]
        declared = dependent.get("range") or "?"
        nodes.append({
            "id": nid, "layer": 2, "kind": "possible",
            "label": "{}@{}".format(dependent["name"], dependent["version"]),
            "sub": "range {} - {}".format(declared, dependent.get("dep_type", "prod")),
            "pkg": dependent["name"],
            "version": dependent["version"],
            "hot": False,
            "conf": Confidence.MEDIUM,
            "why": [Evidence.POSSIBLE_EXACT],
            "neg": ["no lockfile in the corpus resolved this pairing"],
            "verdict": (
                "Unconfirmed - its declared range admits the version, but no "
                "lockfile resolved it"
            ),
            "alarm": False,
            "file": "node_modules/" + dependent["name"],
            "detail": "declares {}, which admits {}".format(declared, result.target),
        })
        edges.append([target_id, nid])

    # -- column 3: what a lockfile actually recorded ----------------------
    for entry in result.lockfile_entries:
        nid = "entry:" + str(entry["id"])
        service = entry_service.get(entry["id"], "")
        nodes.append({
            "id": nid, "layer": 3, "kind": "resolution",
            "label": "{}@{}".format(
                entry.get("package_name") or name,
                entry.get("resolved_version", ""),
            ),
            "sub": "{} - depth {}{}".format(
                service or "lockfile",
                entry.get("depth", "?"),
                " - dev" if entry.get("dev") else "",
            ),
            "pkg": entry.get("package_name") or name,
            "version": entry.get("resolved_version", ""),
            "hot": flagged,
            "conf": Confidence.HIGH if flagged else Confidence.LOW,
            "why": [
                Evidence.RESOLVES_COMPROMISED_VERSION if flagged
                else Evidence.RESOLVES_SUBJECT_VERSION
            ],
            "verdict": (
                "Confirmed - this lockfile resolved the compromised version"
                if flagged else
                "Installed - this lockfile resolved the version under review"
            ),
            "alarm": flagged,
            "flag": "CONFIRMED" if flagged else "RESOLVED",
            "file": (service + "/package-lock.json") if service else "package-lock.json",
            "detail": "integrity " + str(entry.get("integrity") or "unrecorded")[:44],
        })
        edges.append([target_id, nid])
        if service:
            edges.append([nid, "svc:" + service])

    # -- column 4: the projects -------------------------------------------
    live = {p["service"] for p in result.live_window_projects}
    for project in result.exposed_projects:
        nid = "svc:" + project["service"]
        direct = project.get("depth", 0) == schema.DIRECT_DEPTH
        if flagged:
            why = [Evidence.RESOLVES_COMPROMISED_VERSION]
            if not direct:
                why.append(Evidence.TRANSITIVELY_EXPOSED)
            if project["service"] in live:
                why.append(Evidence.LIVE_WINDOW_OVERLAP)
        else:
            why = [Evidence.RESOLVES_SUBJECT_VERSION]
        neg = []
        if project.get("dev_only"):
            neg.append("reached only through a devDependency")
        if flagged and result.live_window_projects and project["service"] not in live:
            neg.append("resolution window misses the incident window")
        if not flagged:
            neg.append("no incident or advisory names this version")
        nodes.append({
            "id": nid, "layer": 4, "kind": "exposed",
            "label": project["service"],
            "sub": "depth {} - via {}{}".format(
                project.get("depth"),
                project.get("via_direct") or "direct",
                " - dev only" if project.get("dev_only") else "",
            ),
            "hot": flagged,
            "conf": Confidence.HIGH if flagged else Confidence.LOW,
            "why": why,
            "neg": neg,
            "verdict": (
                "Exposed - a lockfile in this project resolved the compromised "
                "version" if flagged else
                "Installed - this project resolves the version, and nothing "
                "marks it compromised"
            ),
            "alarm": flagged,
            "flag": "EXPOSED" if flagged else "INSTALLED",
            "file": project["service"] + "/package-lock.json",
            "detail": "resolved {} .. {}".format(
                _fmt_ts(project.get("first_seen")), _fmt_ts(project.get("last_seen"))
            ),
        })

    # An exposed project with no drawn entry would float unconnected. That
    # happens when the version is reached transitively: the lockfile entry
    # naming it sits under the dependency, and the closure edge is the only
    # thing that knows the project. Draw that edge rather than dropping it.
    drawn = {e[1] for e in edges}
    for project in result.exposed_projects:
        nid = "svc:" + project["service"]
        if nid not in drawn:
            edges.append([target_id, nid])

    # -- column 5: relational neighbours, never hot ------------------------
    related: dict[str, dict] = {}

    def relate(key: str, label: str, sub: str, atom: str, detail: str) -> None:
        if key in related:
            if atom not in related[key]["why"]:
                related[key]["why"].append(atom)
            return
        related[key] = {
            "id": key, "layer": 5, "kind": "related",
            "label": label, "sub": sub,
            "hot": False,
            "conf": Confidence.INVESTIGATE,
            "why": [atom],
            "neg": [
                "no lockfile in the corpus resolves a compromised version of it",
                "not named by any incident or advisory",
            ],
            "verdict": (
                "Investigate - related by identity only. Sharing a maintainer, "
                "a repository or a publisher is not exposure"
            ),
            "alarm": False,
            "file": "identity relation",
            "detail": detail,
        }

    for row in result.shared_maintainer[:MAX_DRAWN_RELATED]:
        relate(
            "rel:" + row["package"], row["package"],
            "maintainer " + row["maintainer"], Evidence.SHARED_MAINTAINER,
            "published by the same account as " + name,
        )
    for row in result.shared_repository[:MAX_DRAWN_RELATED]:
        if row["package"] == name:
            continue
        relate(
            "rel:" + row["package"], row["package"],
            "same repository", Evidence.SHARED_REPOSITORY,
            "built from " + str(row["repository"]),
        )
    for row in result.shared_publisher[:MAX_DRAWN_RELATED]:
        if row["package"] == name:
            continue
        relate(
            "rel:" + row["package"], row["package"],
            "publisher " + row["publisher"], Evidence.SHARED_PUBLISHER,
            "{}@{} signed by the same account".format(row["package"], row["version"]),
        )
    for row in result.typosquats[:MAX_DRAWN_RELATED]:
        relate(
            "rel:" + row["name"], row["name"],
            "{} d={}".format(row.get("technique", "typosquat"), row.get("distance")),
            Evidence.TYPOSQUAT_NEIGHBOR,
            "name is {} edit(s) from {}".format(row.get("distance"), name),
        )

    for node in related.values():
        nodes.append(node)
        edges.append([target_id, node["id"]])

    present = {n["id"] for n in nodes}
    edges = [e for e in edges if e[0] in present and e[1] in present]

    return {
        "mode": "package",
        "cols": COLUMNS,
        "nodes": nodes,
        "edges": _dedupe(edges),
        # Tells the renderer not to guess the blast radius by walking edges.
        "serverHot": True,
        "target": result.target,
        "exists": True,
        "compromised": compromised,
        "stats": {
            "range_admits": len(result.direct_dependents),
            "lockfile_entries": len(result.lockfile_entries),
            "exposed_projects": len(result.exposed_projects),
            "live_window_projects": len(result.live_window_projects),
            "related": len(related),
            "drawn_possible": min(len(result.direct_dependents), MAX_DRAWN_POSSIBLE),
            "query_ms": round(result.total_ms, 2),
            "queries": [
                {"label": t.label, "ms": round(t.ms, 2), "rows": t.rows}
                for t in result.timings
            ],
        },
        "findings": [
            {
                "entity": f.entity,
                "entity_type": f.entity_type,
                "status": f.status,
                "confidence": f.confidence,
                "reason": f.reason,
                "atoms": sorted(f.atoms),
                "path": f.path,
                "negative_evidence": f.negative_evidence,
            }
            for f in result.findings
        ],
    }


def suggested_targets(client: HydraClient, limit: int = 6) -> list[dict]:
    """Versions worth marking, ranked by how much the graph can say about them.

    A chip that highlights nothing looks identical to "you are not affected",
    so the suggestions are drawn only from versions the corpus actually
    resolves, and ranked by the gap between what a range admits and what a
    lockfile installed -- which is the whole point being demonstrated.
    """
    try:
        resolved = client.query(
            "MATCH (v:PackageVersion)-[:RESOLVED_IN]->(s:Service) "
            "RETURN v.key AS key, v.name AS name, v.version AS version, "
            "count(*) AS projects ORDER BY projects DESC"
        ).rows
    except HydraError:
        return []

    try:
        admits = {
            row["key"]: row["n"]
            for row in client.query(
                "MATCH (v:PackageVersion)-[:SATISFIES]->(d:PackageVersion) "
                "RETURN v.key AS key, count(*) AS n"
            ).rows
        }
    except HydraError:
        admits = {}

    try:
        marked = {
            row["key"]
            for row in client.query(
                "MATCH (i:Incident)-[:COMPROMISES]->(v:PackageVersion) "
                "RETURN v.key AS key"
            ).rows
        }
    except HydraError:
        marked = set()

    out = []
    for row in resolved:
        key = row["key"]
        out.append({
            "spec": "{}@{}".format(row["name"], row["version"]),
            "projects": row["projects"],
            "range_admits": admits.get(key, 0),
            "marked": key in marked,
        })
    out.sort(
        key=lambda r: (r["marked"], r["range_admits"], r["projects"]), reverse=True
    )
    return out[:limit]


def _dedupe(edges: list[list[str]]) -> list[list[str]]:
    seen = set()
    out: list[list[str]] = []
    for src, dst in edges:
        if src != dst and (src, dst) not in seen:
            seen.add((src, dst))
            out.append([src, dst])
    return out
