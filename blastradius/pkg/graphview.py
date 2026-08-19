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
from ..query.exposure import DECAY, full_exposure, severity_base
from .blast import BlastRadiusEngine, Confidence, Evidence

__all__ = [
    "package_graph",
    "project_graph",
    "suggested_targets",
    "COLUMNS",
    "PROJECT_COLUMNS",
]

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


#: Worst severity first, so a version carrying three advisories is summarised
#: by the one that would get somebody paged.
_SEVERITY_ORDER = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1}


def _verdict(result: Any, compromised: bool) -> dict:
    """The conclusion in words: what was found, and does it reach anything.

    Separate from the graph on purpose. The columns carry the *argument* --
    what a range admits versus what a lockfile resolved -- and an argument is
    not an answer. This is the answer, including the answer "nothing", which
    on a graph alone is indistinguishable from a view that failed to render.
    """
    advisories = list(result.advisories)
    exposed = [p["service"] for p in result.exposed_projects]

    worst = ""
    for advisory in advisories:
        label = _severity_of(advisory)
        if _SEVERITY_ORDER.get(label, 0) > _SEVERITY_ORDER.get(worst, 0):
            worst = label

    ids = [a.get("advisory_id") for a in advisories if a.get("advisory_id")]
    fixes = sorted({
        a["fixed_version"] for a in advisories
        if a.get("fixed_version") and isinstance(a.get("fixed_version"), str)
    })

    if compromised:
        level, headline = "incident", "Marked as compromised (simulated)"
    elif advisories:
        level = worst or "advisory"
        headline = (
            f"{len(advisories)} known {'vulnerability' if len(advisories) == 1 else 'vulnerabilities'}"
        )
    else:
        level, headline = "clean", "No known vulnerabilities"

    if advisories or compromised:
        if exposed:
            reach = (
                f"reaches {len(exposed)} project"
                + ("" if len(exposed) == 1 else "s")
                + ": " + ", ".join(sorted(exposed)[:4])
            )
        else:
            reach = "no project's lockfile resolves this version"
    else:
        reach = (
            f"installed in {len(exposed)} project"
            + ("" if len(exposed) == 1 else "s")
            if exposed else "not installed by any project here"
        )

    return {
        "level": level,
        "severity": worst,
        "headline": headline,
        "reach": reach,
        "advisory_ids": ids,
        "fixed_versions": fixes,
        "exposed": sorted(exposed),
        "compromised": compromised,
    }


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


def _heat(base: float, hops: int, source: str, advisory: str, severity: str) -> dict:
    """Heat fields for one node of the six-column view.

    This view is already scoped to a single version, so distance is not
    something to walk for -- the columns *are* the distance. The threat and the
    version it names sit at hop 0, a lockfile that resolved that version is one
    hop out, and the project holding that lockfile is two. Feeding those through
    the same ramp constant as :mod:`blastradius.query.exposure` is what stops
    this view and the project view disagreeing about the same CVE.

    Columns 2 and 5 deliberately get no heat at all. `RANGE ADMITS` is the
    range-only guess the evidence model exists to replace -- a version a range
    would accept is not a version anything installed -- and a shared maintainer
    never raises a finding above INVESTIGATE. Colouring either of them warm
    would assert exactly the thing the drawing is arguing against; they keep
    their kind stripe instead, which says what they are without claiming they
    are exposed.
    """
    heat = max(0.0, base - hops * DECAY)
    return {
        "heat": round(heat, 4),
        "hops": hops,
        "severity": severity,
        "vuln": True,
        "vulnSource": source,
        "advisory": advisory,
    }


#: A node this view draws but which nothing marks: column 2, column 5, and an
#: unflagged subject. Same shape, no claim.
_COOL = {"heat": 0.0, "hops": -1, "severity": "", "vuln": False,
         "vulnSource": "", "advisory": ""}


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

    # Where this target starts on the shared ramp. An incident is a confirmed
    # live compromise, so it outranks any published severity word; otherwise the
    # worst advisory decides. Same scale as query/exposure.py, deliberately.
    worst_word = max(
        (_severity_of(a) for a in result.advisories),
        key=lambda w: _SEVERITY_ORDER.get(w, 0),
        default="",
    )
    base = 1.0 if compromised else severity_base(worst_word)
    heat_word = "incident" if compromised else (worst_word or "unknown")
    heat_src = result.target
    heat_adv = (
        (result.advisories[0].get("advisory_id") or "") if result.advisories else ""
    )

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
            **_heat(1.0, 0, result.target, "", "incident"),
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
            # A published advisory naming this exact version IS the threat.
            # This was False back when the only thing that could be hot was a
            # synthetic incident somebody clicked, and the consequence once
            # advisories became real was the view arguing against itself: the
            # threat column reported "0 of 1" and folded a genuine CVE behind
            # a "show all", while the simulated incident beside it was drawn
            # in full. Scanned findings are the headline; the simulation is
            # the what-if.
            "hot": True,
            **_heat(
                severity_base(_severity_of(advisory)), 0, result.target,
                advisory.get("advisory_id") or "",
                _severity_of(advisory) or "unknown",
            ),
            "conf": Confidence.HIGH,
            "why": [Evidence.KNOWN_VULNERABILITY],
            "verdict": "Published advisory affecting this exact version",
            "alarm": True,
            "flag": (_severity_of(advisory) or "advisory").upper(),
            "file": ", ".join(
                part for part in (
                    advisory.get("advisory_id") or "",
                    f"fixed in {advisory.get('fixed_version')}"
                    if advisory.get("fixed_version") else "",
                ) if part
            ),
            "detail": advisory.get("summary", ""),
        })
        edges.append([nid, target_id])

    # -- column 1: the compromised version --------------------------------
    meta = result.metadata
    nodes.append({
        "id": target_id, "layer": 1,
        # The browser derives its seed set from `kind == "compromised"`, so an
        # advisory-only finding produced no seed and lost the CVE badge and the
        # pulse. Anything flagged is a seed.
        "kind": "compromised" if flagged else "subject",
        "label": result.target,
        "sub": "published " + _fmt_ts(meta.get("published_at"))
               + (" - install hook" if meta.get("has_install_script") else ""),
        "pkg": meta.get("name", name),
        "version": meta.get("version", version),
        # `flagged`, not `compromised`. This node is the *subject* -- the
        # version the advisories in column 0 point at -- so marking it only for
        # a simulated incident meant a real scanned CVE drew its own target in
        # the cool "subject" hue while every node downstream of it was hot.
        # Worse, a non-empty hot set dims everything outside it, so the one
        # genuinely vulnerable package rendered at 34% opacity: the faintest
        # thing on a screen full of red. The advisory node one column left was
        # already fixed for exactly this reason; the fix stopped one node short.
        "hot": flagged,
        **(_heat(base, 0, heat_src, heat_adv, heat_word) if flagged else _COOL),
        "conf": Confidence.CERTAIN if compromised else (
            Confidence.HIGH if flagged else Confidence.LOW
        ),
        "flag": "COMPROMISED" if compromised else ("VULNERABLE" if flagged else None),
        "why": (
            [Evidence.DIRECTLY_COMPROMISED] if compromised
            else ([Evidence.KNOWN_VULNERABILITY] if flagged else [])
        ),
        "neg": [] if flagged else ["nothing in the graph marks this version"],
        "verdict": (
            "Compromised - a simulated incident names this exact version"
            if compromised else
            "Vulnerable - a published advisory names this exact version"
            if flagged else
            "Under review - nothing in the graph marks this version"
        ),
        "alarm": flagged,
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
            **_COOL,
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
            **(_heat(base, 1, heat_src, heat_adv, heat_word) if flagged else _COOL),
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
            **(_heat(base, 2, heat_src, heat_adv, heat_word) if flagged else _COOL),
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
            **_COOL,
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
        "view": "package",
        "exposure": {
            "exposed": sum(1 for n in nodes if n.get("vuln")),
            "total": len(nodes),
            "worst": {
                "heat": round(base, 4), "hops": 0, "severity": heat_word,
                "source": heat_src, "advisory": heat_adv,
            } if flagged else None,
            "advisories": len(result.advisories) + len(result.incidents),
        },
        # The finding, in words. The graph shows the argument; this states the
        # conclusion, because a user who has to read six columns to learn
        # whether they are affected has not been told whether they are
        # affected. "Clean" is a result too, and gets said out loud rather
        # than being left to look like a view that failed to load.
        "verdict": _verdict(result, compromised),
        "stats": {
            "advisories": len(result.advisories),
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


# ==========================================================================
# The project-wide view
# ==========================================================================
# `package_graph` above answers "tell me about this one version". That is the
# right question once you already know which version to ask about, and the
# wrong one when you have just scanned a repo and want to know what is wrong
# with it. This view answers the second question: the project, everything its
# lockfile resolves that is exposed to a published advisory, and the dependency
# chain carrying the exposure back to the project.
#
# Layers are dependency depth, so the drawing reads left to right as "the
# project, its direct dependencies, and how far down the tree the problem
# lives". Heat runs the other way -- hottest on the right, at the advisory --
# cooling as it climbs back toward the project. That is the blast radius drawn
# in the direction it actually travels.

PROJECT_COLUMNS = [
    "PROJECT",
    "DIRECT DEPENDENCIES",
    "DEPTH 2",
    "DEPTH 3",
    "DEPTH 4",
    "DEPTH 5+",
]

#: Depth beyond this is folded into the last column. A real npm tree is deeper
#: than any column strip, and a node's exact depth is still on the node.
MAX_LAYER = 5

#: Clean direct dependencies are drawn so the healthy majority is visible --
#: an all-green graph is a result, not an empty one. Deeper clean packages are
#: not: 774 nodes is a wall, and a clean transitive dependency four levels down
#: is not something anyone is looking at.
MAX_CLEAN_DIRECT = 40


def project_graph(client: HydraClient, ids: IdAllocator) -> dict:
    """Every exposed package in the project, and how the exposure reaches it."""
    started = dt.datetime.now()

    model = full_exposure(client)

    services = client.query(
        "MATCH (s:Service) RETURN s.id AS id, s.name AS name, s.repo AS repo"
    ).rows
    resolved = client.query(
        "MATCH (v:PackageVersion)-[e:PRESENT_IN]->(s:Service) "
        "RETURN v.id AS id, v.name AS name, v.version AS version, "
        "e.depth AS depth, e.dev AS dev, e.direct AS direct, s.id AS service"
    ).rows
    tree = client.query(
        "MATCH (a:PackageVersion)-[:DEPENDS_ON]->(b:PackageVersion) "
        "RETURN a.id AS src, b.id AS dst"
    ).rows
    roots = client.query(
        "MATCH (s:Service)-[:DEPENDS_ON]->(v:PackageVersion) "
        "RETURN s.id AS src, v.id AS dst"
    ).rows
    advisories = client.query(
        "MATCH (a:Advisory)-[:AFFECTS]->(v:PackageVersion) "
        "RETURN v.id AS version_id, a.advisory_id AS advisory_id, "
        "a.severity AS severity, a.summary AS summary"
    ).rows

    by_version: dict[int, list[dict]] = {}
    for row in advisories:
        by_version.setdefault(row["version_id"], []).append(row)

    meta = {row["id"]: row for row in resolved}

    # -- decide what is worth drawing --------------------------------------
    # Everything the exposure model touched, plus enough clean context that a
    # healthy project does not render as a blank page.
    visible: set[int] = {node_id for node_id in model.heat if node_id in meta}
    clean_direct = [
        row["id"] for row in resolved
        if row.get("direct") and row["id"] not in visible
    ]
    clean_direct.sort(key=lambda i: (meta[i].get("name") or ""))
    visible.update(clean_direct[:MAX_CLEAN_DIRECT])

    def layer_for(node_id: int) -> int:
        depth = meta.get(node_id, {}).get("depth")
        if not isinstance(depth, int) or depth < 1:
            depth = 1
        return min(depth, MAX_LAYER)

    nodes: list[dict] = []
    edges: list[list[str]] = []

    for service in services:
        sid = "svc:" + str(service["id"])
        hit = model.heat.get(service["id"])
        nodes.append({
            "id": sid, "layer": 0, "kind": "exposed" if hit else "service",
            "label": service.get("name") or "project",
            "sub": service.get("repo") or "",
            "heat": round(hit.heat, 4) if hit else 0.0,
            "hops": hit.hops if hit else -1,
            "severity": hit.severity if hit else "",
            "vuln": bool(hit),
            "vulnSource": hit.source if hit else "",
            "advisory": hit.advisory if hit else "",
            "hot": bool(hit),
            "conf": Confidence.CERTAIN if hit else Confidence.LOW,
            "flag": "EXPOSED" if hit else None,
            "alarm": bool(hit),
            "verdict": (
                f"Exposed - {hit.source} is in this project's dependency tree"
                if hit else "No advisory reaches this project"
            ),
            "file": service.get("repo") or "",
            "detail": "",
        })

    for node_id in sorted(visible, key=lambda i: (layer_for(i), meta[i].get("name") or "")):
        row = meta[node_id]
        hit = model.heat.get(node_id)
        own = by_version.get(node_id) or []
        worst_own = max(
            (_severity_of(a) for a in own),
            key=lambda w: _SEVERITY_ORDER.get(w, 0),
            default="",
        )
        label = f"{row.get('name')}@{row.get('version')}"
        seeded = bool(own)
        nodes.append({
            "id": "pv:" + str(node_id),
            "layer": layer_for(node_id),
            # `compromised` is the seed kind the browser badges; a package with
            # its own advisory is the origin of a radius, not a passenger in it.
            "kind": "compromised" if seeded else ("exposed" if hit else "resolution"),
            "label": label,
            "sub": (
                f"{len(own)} advisory(ies) - {worst_own or 'unrated'}"
                if seeded else
                f"depth {row.get('depth')}"
                + (" - dev only" if row.get("dev") else "")
                + (f" - via {hit.source}" if hit else "")
            ),
            "pkg": row.get("name"),
            "version": row.get("version"),
            "heat": round(hit.heat, 4) if hit else 0.0,
            "hops": hit.hops if hit else -1,
            "severity": hit.severity if hit else "",
            "vuln": bool(hit),
            "vulnSource": hit.source if hit else "",
            "advisory": hit.advisory if hit else "",
            "hot": bool(hit),
            "conf": (
                Confidence.CERTAIN if seeded
                else Confidence.HIGH if hit
                else Confidence.LOW
            ),
            "flag": (
                (worst_own or "advisory").upper() if seeded
                else "IN RADIUS" if hit else None
            ),
            "why": (
                [Evidence.KNOWN_VULNERABILITY] if seeded
                else [Evidence.TRANSITIVELY_EXPOSED] if hit else []
            ),
            "neg": [] if hit else ["no advisory reaches this version"],
            "alarm": seeded,
            "verdict": (
                f"{len(own)} published advisory(ies) name this exact version"
                if seeded else
                f"In the blast radius of {hit.source}, {hit.hops} hop(s) away"
                if hit else
                "Resolved by the lockfile; no advisory reaches it"
            ),
            "file": "node_modules/" + str(row.get("name")),
            "detail": "; ".join(
                f"{a['advisory_id']}: {(a.get('summary') or '')[:90]}" for a in own[:4]
            ),
        })

    drawn = {"pv:" + str(i) for i in visible}
    for row in roots:
        dst = "pv:" + str(row["dst"])
        if dst in drawn:
            edges.append(["svc:" + str(row["src"]), dst])
    for row in tree:
        src, dst = "pv:" + str(row["src"]), "pv:" + str(row["dst"])
        if src in drawn and dst in drawn:
            edges.append([src, dst])

    worst = model.worst()
    exposed_nodes = [n for n in nodes if n["vuln"]]
    return {
        "mode": "package",
        "view": "project",
        "cols": PROJECT_COLUMNS,
        "nodes": nodes,
        "edges": _dedupe(edges),
        "serverHot": True,
        "exists": bool(nodes),
        "target": ", ".join(s.get("name") or "project" for s in services),
        "compromised": False,
        "verdict": {
            "level": (worst.severity if worst else "clean"),
            "severity": (worst.severity if worst else ""),
            "headline": (
                f"{len(model.seeds)} vulnerable package version(s)"
                if model.seeds else "No known vulnerabilities"
            ),
            "reach": f"{len(exposed_nodes)} node(s) in the blast radius",
            "advisory_ids": sorted(
                {row["advisory_id"] for row in advisories if row["version_id"] in meta}
            ),
            "fixed_versions": [],
            "exposed": [s.get("name") or "project" for s in services],
            "compromised": False,
        },
        "exposure": {
            "exposed": len(exposed_nodes),
            "total": len(nodes),
            "worst": worst.as_dict() if worst else None,
            "advisories": len(model.seeds),
        },
        "stats": {
            "vulnerable_versions": len(model.seeds),
            "in_radius": len(exposed_nodes),
            "resolved_versions": len(meta),
            "drawn": len(nodes),
            "query_ms": round(
                (dt.datetime.now() - started).total_seconds() * 1000, 1
            ),
            "queries": [],
        },
        "findings": [],
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

    # What the scan found. Before advisories were scanned there were never
    # any, so ranking by range-admits alone was harmless; now it is the bug
    # that matters most here. A chip list ordered by how many versions a range
    # admits offers packages with no known vulnerability at all, and buries
    # the ones an advisory actually names -- which are the only reason anyone
    # opened this view.
    try:
        vulnerable: dict[str, int] = {}
        for row in client.query(
            "MATCH (a:Advisory)-[:AFFECTS]->(v:PackageVersion) "
            "RETURN v.key AS key, count(*) AS n"
        ).rows:
            vulnerable[row["key"]] = row["n"]
    except HydraError:
        vulnerable = {}

    out = []
    for row in resolved:
        key = row["key"]
        out.append({
            "spec": "{}@{}".format(row["name"], row["version"]),
            "projects": row["projects"],
            "range_admits": admits.get(key, 0),
            "marked": key in marked,
            "advisories": vulnerable.get(key, 0),
        })
    # Marked first (somebody is mid-investigation), then anything an advisory
    # names, then the range-only spread as the tie-break it always was.
    out.sort(
        key=lambda r: (
            r["marked"],
            r["advisories"],
            r["range_admits"],
            r["projects"],
        ),
        reverse=True,
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
