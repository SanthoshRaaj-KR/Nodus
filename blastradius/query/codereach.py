"""From a confirmed threat down to the function that will run its code.

The package tier answers *which services installed this*. That is the question
an incident starts with, and it is not the question anybody finishes with,
because "installed" and "reached from our source" are very different states.
This repo holds 1,703 resolved package versions and 8 external imports: almost
everything in the dependency tree is never named by a line of code here. A
tool that reports all of it equally has told a responder nothing about where to
look first.

So this module walks the last mile:

    Advisory / Incident
        -> PackageVersion            the thing that is actually bad
        -> (dependency chain)        how it got pulled in, if indirectly
        -> ExternalImport            the `import x from "y"` that names it
        -> Function                  the function whose body calls that import
        -> Function                  the functions that call *that* one

Two facts come out of the walk, and the second matters more than the first.
A threat with code reach names the file and line to open. A threat with **no**
code reach is not a false positive -- the package really is installed and the
advisory really does apply -- but nothing in this repository's source imports
it, which is the difference between "patch this now" and "patch this Tuesday".
Saying so out loud is the point; a list that cannot tell the two apart is the
flat lockfile scan this project exists to improve on.

**Direction of the walk.** Imports are walked *forward* down the dependency
tree, once each, rather than walking backwards from every threat. There are a
handful of imports and hundreds of threatened versions, so forward is one BFS
per import instead of one per threat, and it yields the hop distance to every
threat in the same pass. The result is a single reusable index.

**Nothing here is a new verdict.** Severity comes from the advisory, compromise
from an Incident node somebody wrote deliberately. This module only decides
*where to point*, and it never upgrades a finding for being close to code.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from .. import schema
from ..hydra_client import HydraClient
from .exposure import severity_base, severity_word

__all__ = [
    "CodeIndex",
    "Threat",
    "Reach",
    "Artifact",
    "build_index",
    "threats",
    "code_reach",
    "persistence_artifacts",
    "CALLER_DEPTH",
]

#: How far back up the call graph to follow callers of a function that touches
#: a threatened import. Two hops is what fits on screen and what a reader can
#: hold: the function that uses it, and who reaches that. Deeper chains exist
#: and are reported as a count rather than drawn, because a caller tree that
#: runs off the canvas reads as noise and hides the first two hops that matter.
CALLER_DEPTH = 2

#: Ceiling on how far down the dependency tree an import is followed. The
#: resolved tree here is shallow, but a cycle or a pathological monorepo must
#: not turn one BFS into a hang. Anything past this is genuinely too far from
#: source to call "reached from code".
MAX_DEP_DEPTH = 12


def _text(value) -> str:
    """A string property, or "" for anything missing.

    HydraDB returns an absent property as ``{"type": "null"}`` -- a dict with
    no ``value`` key, which the client's flattener passes through untouched
    because it is not a well-formed typed cell. Every read of an optional
    property has to survive that, and ``str(value)`` would render it as the
    literal text ``{'type': 'null'}`` into the UI.
    """
    return value.strip() if isinstance(value, str) else ""


def _int(value, default: int = -1) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _function_label(fn: dict) -> tuple[str, str]:
    """How to name a function on screen, and what to say underneath.

    The scanner records top-level code as a pseudo-function called
    ``<module>``, which is honest in the graph and useless on a diagram:
    ``<module>()`` names no function a reader can open, and several files each
    contribute one, so a column of them is unreadable. Module scope is shown
    as the file that holds it instead.
    """
    if fn["name"] == "<module>":
        return fn["file"] or "<module>", "module scope (top-level code)"
    return f"{fn['name']}()", f"{fn['file']}:{fn['line']}"


# --------------------------------------------------------------------------
# The index
# --------------------------------------------------------------------------

@dataclass
class CodeIndex:
    """Everything the reach walk needs, read once.

    Built as a whole rather than queried per threat for the same reason
    :mod:`.exposure` walks in Python: HydraDB needs a pinned source for a
    variable-length traversal, so a reverse walk would be one round trip per
    node. This is a dozen sweeps against a graph of a few thousand edges.
    """

    #: version id -> (name, version)
    versions: dict[int, tuple[str, str]] = field(default_factory=dict)
    #: version id -> version ids it depends on
    depends: dict[int, list[int]] = field(default_factory=dict)
    #: import id -> {id, specifier, file, service, names, version_id}
    imports: dict[int, dict] = field(default_factory=dict)
    #: function id -> {id, name, file, line, service}
    functions: dict[int, dict] = field(default_factory=dict)
    #: import id -> function ids whose body calls it
    import_users: dict[int, list[int]] = field(default_factory=dict)
    #: function id -> function ids that call it
    callers: dict[int, list[int]] = field(default_factory=dict)
    #: version id -> service names that resolved it
    services: dict[int, list[str]] = field(default_factory=dict)
    #: import id -> {reached version id: hops}, precomputed once
    import_reach: dict[int, dict[int, int]] = field(default_factory=dict)

    def label(self, version_id: int) -> str:
        name, version = self.versions.get(version_id, ("", ""))
        return f"{name}@{version}" if version else name


def build_index(client: HydraClient) -> CodeIndex:
    """Read the code tier, the bridge and the dependency tree in one pass."""
    index = CodeIndex()

    for row in client.query(
        f"MATCH (v:{schema.PACKAGE_VERSION}) "
        "RETURN v.id AS id, v.name AS name, v.version AS version"
    ).rows:
        node_id = _int(row.get("id"))
        if node_id >= 0:
            index.versions[node_id] = (_text(row.get("name")), _text(row.get("version")))

    for row in client.query(
        f"MATCH (a:{schema.PACKAGE_VERSION})-[:{schema.DEPENDS_ON}]->"
        f"(b:{schema.PACKAGE_VERSION}) RETURN a.id AS src, b.id AS dst"
    ).rows:
        src, dst = _int(row.get("src")), _int(row.get("dst"))
        if src >= 0 and dst >= 0:
            index.depends.setdefault(src, []).append(dst)

    for row in client.query(
        f"MATCH (v:{schema.PACKAGE_VERSION})-[:{schema.PRESENT_IN}]->"
        f"(s:{schema.SERVICE}) RETURN v.id AS id, s.name AS service"
    ).rows:
        node_id = _int(row.get("id"))
        service = _text(row.get("service"))
        if node_id >= 0 and service:
            index.services.setdefault(node_id, []).append(service)

    # The bridge. An import with no RESOLVES_TO edge is a builtin like
    # `node:fs` or an unresolved specifier; it is kept in the index with
    # version_id -1 so the UI can say "builtin" rather than silently drop it.
    resolved: dict[int, int] = {}
    for row in client.query(
        f"MATCH (e:{schema.EXTERNAL_IMPORT})-[:{schema.RESOLVES_TO}]->"
        f"(v:{schema.PACKAGE_VERSION}) RETURN e.id AS eid, v.id AS vid"
    ).rows:
        eid, vid = _int(row.get("eid")), _int(row.get("vid"))
        if eid >= 0 and vid >= 0:
            resolved[eid] = vid

    for row in client.query(
        f"MATCH (e:{schema.EXTERNAL_IMPORT}) RETURN e.id AS id, "
        "e.specifier AS specifier, e.file AS file, e.service AS service, "
        "e.names AS names"
    ).rows:
        node_id = _int(row.get("id"))
        if node_id < 0:
            continue
        index.imports[node_id] = {
            "id": node_id,
            "specifier": _text(row.get("specifier")),
            "file": _text(row.get("file")),
            "service": _text(row.get("service")),
            "names": [n for n in _text(row.get("names")).split(",") if n],
            "version_id": resolved.get(node_id, -1),
        }

    for row in client.query(
        f"MATCH (f:{schema.FUNCTION}) RETURN f.id AS id, f.name AS name, "
        "f.file AS file, f.line AS line, f.service AS service"
    ).rows:
        node_id = _int(row.get("id"))
        if node_id < 0:
            continue
        index.functions[node_id] = {
            "id": node_id,
            "name": _text(row.get("name")) or "<anonymous>",
            "file": _text(row.get("file")),
            "line": _int(row.get("line"), 0),
            "service": _text(row.get("service")),
        }

    for row in client.query(
        f"MATCH (f:{schema.FUNCTION})-[:{schema.CALLS_EXTERNAL}]->"
        f"(e:{schema.EXTERNAL_IMPORT}) RETURN f.id AS fid, e.id AS eid"
    ).rows:
        fid, eid = _int(row.get("fid")), _int(row.get("eid"))
        if fid >= 0 and eid >= 0:
            index.import_users.setdefault(eid, []).append(fid)

    # Stored reversed: every question asked of this map is "who calls X".
    for row in client.query(
        f"MATCH (a:{schema.FUNCTION})-[:{schema.CALLS}]->(b:{schema.FUNCTION}) "
        "RETURN a.id AS src, b.id AS dst"
    ).rows:
        src, dst = _int(row.get("src")), _int(row.get("dst"))
        if src >= 0 and dst >= 0:
            index.callers.setdefault(dst, []).append(src)

    for import_id, entry in index.imports.items():
        root = entry["version_id"]
        index.import_reach[import_id] = (
            _reachable(index.depends, root) if root >= 0 else {}
        )
    return index


def _reachable(depends: dict[int, list[int]], root: int) -> dict[int, int]:
    """Every version reachable from ``root``, with its hop distance.

    Breadth-first, so the recorded distance is the shortest one: a package
    pulled in both directly and through a chain is reported at the depth that
    makes it easiest to explain, not the worst one found.
    """
    seen = {root: 0}
    queue = deque([root])
    while queue:
        node = queue.popleft()
        depth = seen[node]
        if depth >= MAX_DEP_DEPTH:
            continue
        for child in depends.get(node, ()):
            if child not in seen:
                seen[child] = depth + 1
                queue.append(child)
    return seen


# --------------------------------------------------------------------------
# Confirmed threats
# --------------------------------------------------------------------------

@dataclass
class Threat:
    """One package version somebody has said something bad about.

    Grouped by version rather than by advisory. Three CVEs on `lodash@4.17.20`
    are one thing to go and fix, and listing them as three findings triples the
    apparent size of the problem without adding an action.
    """

    version_id: int
    package: str
    version: str
    #: vulnerable | compromised | deprecated -- the worst that applies.
    kind: str
    severity: str
    advisories: list[dict] = field(default_factory=list)
    incident: dict | None = None
    deprecated_reason: str = ""
    services: list[str] = field(default_factory=list)
    #: Import ids that reach this version, with hop distance.
    reached_by: dict[int, int] = field(default_factory=dict)
    #: Distinct functions that would run its code, counted not listed.
    function_count: int = 0

    @property
    def in_code(self) -> bool:
        return bool(self.reached_by)

    @property
    def rank(self) -> tuple:
        """Sort key. Reached-from-code first, then severity, then breadth.

        Code reach outranks severity deliberately. A moderate advisory on a
        package a route handler calls is a worse Monday than a critical one on
        a transitive dev dependency nothing here imports, and every ranking
        that sorts on severity alone buries the first behind the second.
        """
        return (
            0 if self.in_code else 1,
            0 if self.kind == "compromised" else 1,
            -severity_base(self.severity),
            -len(self.services),
            self.package,
            self.version,
        )

    def to_dict(self) -> dict:
        return {
            "id": self.version_id,
            "package": self.package,
            "version": self.version,
            "spec": f"{self.package}@{self.version}",
            "kind": self.kind,
            "severity": self.severity,
            "advisories": self.advisories,
            "incident": self.incident,
            "deprecated_reason": self.deprecated_reason,
            "services": sorted(self.services),
            "in_code": self.in_code,
            "import_count": len(self.reached_by),
            "function_count": self.function_count,
        }


def threats(client: HydraClient, index: CodeIndex | None = None) -> list[Threat]:
    """Every confirmed threat in the graph, ranked by where it can be reached.

    "Confirmed" is doing real work here. These are advisories somebody
    published, incidents somebody wrote down, and deprecations the registry
    itself reports -- not the heuristic leads from :mod:`~blastradius.pkg.anomaly`,
    which top out at INVESTIGATE and belong on the live console instead.
    """
    index = index if index is not None else build_index(client)
    found: dict[int, Threat] = {}

    def entry(version_id: int, kind: str) -> Threat:
        threat = found.get(version_id)
        if threat is None:
            name, version = index.versions.get(version_id, ("", ""))
            threat = Threat(
                version_id=version_id, package=name, version=version,
                kind=kind, severity="",
                services=list(index.services.get(version_id, ())),
            )
            found[version_id] = threat
        # A compromised package is also a vulnerable one; keep the worse word.
        if kind == "compromised":
            threat.kind = "compromised"
        return threat

    for row in client.query(
        f"MATCH (a:{schema.ADVISORY})-[:{schema.AFFECTS}]->"
        f"(v:{schema.PACKAGE_VERSION}) RETURN v.id AS vid, "
        "a.advisory_id AS advisory_id, a.severity AS severity, "
        "a.summary AS summary, a.cvss_vector AS cvss_vector"
    ).rows:
        version_id = _int(row.get("vid"))
        if version_id < 0:
            continue
        threat = entry(version_id, "vulnerable")
        severity = severity_word(row.get("severity"))
        threat.advisories.append({
            "advisory_id": _text(row.get("advisory_id")),
            "severity": severity,
            "summary": _text(row.get("summary")),
            "cvss_vector": _text(row.get("cvss_vector")),
        })
        # A version is as dangerous as the worst thing known about it.
        #
        # The emptiness test is not redundant with the comparison. An unset
        # severity is "", and severity_base("") returns UNRATED_BASE (0.55) --
        # the deliberate ranking for an advisory nobody rated, which is above
        # `low` at 0.45. Comparing against the sentinel therefore refuses to
        # store a low severity at all, and a version whose only advisory is
        # low-severity renders with a blank chip. Ask "is anything set yet"
        # first, and only then which is worse.
        if not threat.severity or severity_base(severity) > severity_base(threat.severity):
            threat.severity = severity

    for row in client.query(
        f"MATCH (i:{schema.INCIDENT})-[:{schema.COMPROMISES}]->"
        f"(v:{schema.PACKAGE_VERSION}) RETURN v.id AS vid, "
        "i.incident_id AS incident_id, i.status AS status, i.summary AS summary"
    ).rows:
        version_id = _int(row.get("vid"))
        if version_id < 0:
            continue
        threat = entry(version_id, "compromised")
        status = _text(row.get("status"))
        threat.incident = {
            "incident_id": _text(row.get("incident_id")),
            "status": status,
            "summary": _text(row.get("summary")),
            # Simulated incidents are written by the console's own compromise
            # drill. Flagging them is not cosmetic: an operator who cannot tell
            # a drill from a live compromise at a glance has been handed a
            # false alarm by their own tool.
            "simulated": status.upper().startswith("SIMULATED"),
        }
        if not threat.severity:
            threat.severity = "critical"

    for row in client.query(
        f"MATCH (v:{schema.PACKAGE_VERSION}) WHERE v.deprecated = true "
        "RETURN v.id AS vid, v.deprecated_reason AS reason"
    ).rows:
        version_id = _int(row.get("vid"))
        if version_id < 0:
            continue
        threat = entry(version_id, "deprecated")
        threat.deprecated_reason = _text(row.get("reason"))
        if threat.kind not in ("compromised", "vulnerable"):
            threat.kind = "deprecated"
        if not threat.severity:
            threat.severity = "unknown"

    # One pass over the precomputed import reach fills in every threat at once.
    for import_id, reach in index.import_reach.items():
        for version_id, hops in reach.items():
            threat = found.get(version_id)
            if threat is not None:
                threat.reached_by[import_id] = hops

    for threat in found.values():
        users: set[int] = set()
        for import_id in threat.reached_by:
            users.update(index.import_users.get(import_id, ()))
        threat.function_count = len(users)
        threat.advisories.sort(key=lambda a: -severity_base(a["severity"]))

    return sorted(found.values(), key=lambda t: t.rank)


# --------------------------------------------------------------------------
# The last mile
# --------------------------------------------------------------------------

@dataclass
class Reach:
    """The drawable subgraph from one threatened version to source."""

    found: bool = False
    spec: str = ""
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)
    #: Why there is nothing to draw, when there is nothing to draw.
    note: str = ""
    truncated_callers: int = 0

    def to_dict(self) -> dict:
        return {
            "found": self.found,
            "spec": self.spec,
            "nodes": self.nodes,
            "edges": self.edges,
            "note": self.note,
            "truncated_callers": self.truncated_callers,
        }


def code_reach(
    client: HydraClient,
    package: str,
    version: str,
    index: CodeIndex | None = None,
    caller_depth: int = CALLER_DEPTH,
) -> Reach:
    """The path from one threatened version to the functions that run it.

    Returns a layered node/edge list ready to draw. ``column`` is assigned
    here rather than in the browser because the columns *are* the semantics --
    package, then bridge, then import site, then the function that uses it,
    then who calls that -- and a layout computed from geometry alone would put
    them in whatever order the force solver settled on.
    """
    index = index if index is not None else build_index(client)
    spec = f"{package}@{version}"

    target_id = next(
        (vid for vid, (n, v) in index.versions.items()
         if n == package and v == version),
        None,
    )
    if target_id is None:
        return Reach(found=False, spec=spec, note=f"{spec} is not in the graph")

    hits = [
        (import_id, reach[target_id])
        for import_id, reach in index.import_reach.items()
        if target_id in reach
    ]
    if not hits:
        return Reach(
            found=False, spec=spec,
            note=(
                f"{spec} is installed, but nothing in this repository's source "
                f"imports it or anything that depends on it. It ships in the "
                f"tree without being reached from code here."
            ),
        )

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    seen_edges: set[tuple[str, str]] = set()

    def add(key: str, **fields) -> str:
        if key not in nodes:
            nodes[key] = {"key": key, **fields}
        return key

    def link(src: str, dst: str, kind: str) -> None:
        if (src, dst) not in seen_edges:
            seen_edges.add((src, dst))
            edges.append({"src": src, "dst": dst, "kind": kind})

    threat_key = add(
        f"pkg:{target_id}", column=0, kind="threat", label=spec,
        sub="the affected version",
        services=sorted(index.services.get(target_id, ())),
    )

    truncated = 0
    for import_id, hops in sorted(hits, key=lambda h: (h[1], h[0])):
        entry = index.imports[import_id]
        bridge_id = entry["version_id"]

        # Column 1 exists only when the import names something other than the
        # threat itself. Drawing `vite -> vite` as two circles would imply a
        # hop that is not there.
        anchor = threat_key
        if hops > 0 and bridge_id >= 0:
            bridge_label = index.label(bridge_id)
            anchor = add(
                f"pkg:{bridge_id}", column=1, kind="bridge",
                label=bridge_label,
                sub=f"pulls it in · {hops} hop(s)",
            )
            link(threat_key, anchor, "pulled-in-by")

        # The service is deliberately not in `sub`: "vite.config.js ·
        # blast-radius-console" does not fit under a circle, and truncating it
        # costs the filename, which is the one part a reader acts on. The
        # service is carried as a field and shown in the detail panel.
        import_key = add(
            f"im:{import_id}", column=2, kind="import",
            label=entry["specifier"],
            sub=entry["file"],
            names=entry["names"],
            file=entry["file"], service=entry["service"], hops=hops,
        )
        link(anchor, import_key, "imported-as")

        users = index.import_users.get(import_id, ())
        if not users:
            continue

        # Callers are walked breadth-first from every using function at once,
        # so a function reachable from two of them is placed at its shortest
        # distance and drawn once.
        frontier: dict[int, int] = {}
        for function_id in users:
            fn = index.functions.get(function_id)
            if fn is None:
                continue
            label, sub = _function_label(fn)
            function_key = add(
                f"fn:{function_id}", column=3, kind="uses",
                label=label, sub=sub,
                name=fn["name"],
                file=fn["file"], line=fn["line"], service=fn["service"],
            )
            link(import_key, function_key, "calls-into")
            frontier[function_id] = 0

        placed = dict(frontier)
        queue = deque(frontier.items())
        while queue:
            function_id, depth = queue.popleft()
            if depth >= caller_depth:
                truncated += len(
                    [c for c in index.callers.get(function_id, ())
                     if c not in placed]
                )
                continue
            for caller_id in index.callers.get(function_id, ()):
                if caller_id in placed:
                    # Recursion and mutual calls are ordinary in real code;
                    # revisiting would loop forever and redraw the same circle.
                    link(f"fn:{caller_id}", f"fn:{function_id}", "calls")
                    continue
                caller = index.functions.get(caller_id)
                if caller is None:
                    continue
                placed[caller_id] = depth + 1
                caller_label, caller_sub = _function_label(caller)
                add(
                    f"fn:{caller_id}", column=4 + depth, kind="caller",
                    label=caller_label, sub=caller_sub,
                    name=caller["name"],
                    file=caller["file"], line=caller["line"],
                    service=caller["service"],
                )
                link(f"fn:{caller_id}", f"fn:{function_id}", "calls")
                queue.append((caller_id, depth + 1))

    return Reach(
        found=True, spec=spec,
        nodes=list(nodes.values()), edges=edges,
        truncated_callers=truncated,
    )


# --------------------------------------------------------------------------
# Persistence: the compromise that survives the uninstall
# --------------------------------------------------------------------------

@dataclass
class Artifact:
    """One file found somewhere a worm hides to outlive its package.

    This is a different kind of fact from everything else in this module, and
    the difference is the whole reason it has its own section rather than
    being folded into the threat list. Every other finding here is *exposure*:
    a version you installed, a package you import, a maintainer who could
    push again. Removing the package resolves all of them.

    An artifact is *evidence*, and removing the package resolves none of it.
    The TanStack-class worm wrote into ``.claude/`` and ``.vscode/`` precisely
    so that ``npm uninstall`` would leave it running. Reporting it beside the
    advisories, under the same heading, would say the opposite of what is
    true.
    """

    path: str
    kind: str
    sha256: str
    service: str
    first_seen: int

    @property
    def watched_dir(self) -> str:
        """The directory that made this worth looking at, if it is one."""
        for watched in (".claude", ".vscode", ".github/workflows", ".husky"):
            if self.path.startswith(watched + "/") or self.path == watched:
                return watched
        return ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "kind": self.kind,
            "sha256": self.sha256,
            "short_sha": self.sha256[:12],
            "service": self.service,
            "first_seen": self.first_seen,
            "watched_dir": self.watched_dir,
        }


def persistence_artifacts(client: HydraClient) -> list[Artifact]:
    """Every persistence candidate on disk, newest first.

    Nothing here is a verdict either. A `.vscode/settings.json` is a file
    almost every repository has, and the check reports files in the places a
    worm is known to use -- not files that are known to be malicious. The
    kind says which: ``ioc-path`` and ``ioc-content`` matched something an
    advisory named, ``watched-dir`` is "this is one of the directories, go
    and look".
    """
    rows = client.query(
        f"MATCH (a:{schema.ARTIFACT}) RETURN a.path AS path, a.kind AS kind, "
        "a.sha256 AS sha256, a.service AS service, a.first_seen AS first_seen"
    ).rows
    found = [
        Artifact(
            path=_text(r.get("path")),
            kind=_text(r.get("kind")) or "watched-dir",
            sha256=_text(r.get("sha256")),
            service=_text(r.get("service")),
            first_seen=_int(r.get("first_seen"), 0),
        )
        for r in rows
        if _text(r.get("path"))
    ]
    # An IOC match outranks "it was in a watched directory", then newest
    # first: a file that appeared today is the one to open.
    order = {"ioc-content": 0, "ioc-path": 1, "watched-dir": 2}
    found.sort(key=lambda a: (order.get(a.kind, 3), -a.first_seen, a.path))
    return found
