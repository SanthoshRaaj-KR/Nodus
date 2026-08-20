"""What the agent is allowed to ask the graph, and how small the answers stay.

Every function here is a plain Python call over HydraDB that returns a small
dict. Nothing in this module imports OpenAI or needs an API key, which is the
whole point: a supply-chain tool that invents an exposure is worse than one
that says nothing, so the facts are produced by code that can be unit-tested
against a real graph and the model is left only to choose between them and
phrase the result.

Three rules hold across all of them.

**Everything is scoped to one workspace.** A `Scope` carries the service ids a
chatbot owns, and no query here reaches outside them. See `workspaces.py` for
why isolation lives at the service set rather than in the store.

**Answers are capped.** Tool output is the one input a user cannot see and
cannot bound. An uncapped list both slows generation and pushes the briefing
out of the prompt cache, so every list has a limit and reports what it left
out rather than truncating silently.

**"No data" is never rendered as "no exposure".** This is the project's own
distinction -- `installed but not reached` is not `not affected` -- and it is
the single most dangerous thing a chatbot here could blur. Tools return an
explicit `note` whenever the answer is empty because nothing was scanned,
rather than letting an empty list imply a clean bill of health.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any

from blastradius import schema
from blastradius.hydra_client import HydraClient, HydraError
from blastradius.ids import IdAllocator
from blastradius.pkg.identity import InvalidPackageName, version_key
from blastradius.query import blast, codereach

from .config import ROOT
from .workspaces import Workspace

ADVISORY_DIR = ROOT / "advisories"

#: Advisory detail keyed by advisory id, persisted across scans.
#:
#: `advisories/generated/` is cleared and rewritten on every `osv-scan`, so
#: after scanning repo B the fix data for repo A's advisories is gone from
#: disk -- while the `Advisory` nodes for both are still in the graph, because
#: they MERGE. Without this cache the second chatbot registered would answer
#: "how do I fix it" with a fixed version and the first would answer with
#: nothing, purely because of scan order.
ADVISORY_CACHE = ROOT / "data" / "chat-advisory-cache.json"

_lock = RLock()

#: (read_epoch) -> CodeIndex. The index is whole-graph, so it is shared across
#: workspaces and filtered per scope at use. Building it is a dozen sweeps.
_index_cache: tuple[Any, Any] = (None, None)

#: (read_epoch, workspace id) -> the versions that workspace's services hold.
_packages_cache: dict[tuple[Any, int], list[dict]] = {}

#: (read_epoch, workspace id) -> that workspace's confirmed threats. Cached
#: separately from the packages because `list_threats`, `threat_detail`,
#: `service_profile` and the briefing all want the same filtered list, and
#: recomputing it per tool call put ~140ms on every question for no new facts.
_threats_cache: dict[tuple[Any, int], list[dict]] = {}

_advisory_cache: dict[str, dict] | None = None


# --------------------------------------------------------------------------
# scope
# --------------------------------------------------------------------------


@dataclass
class Scope:
    """One chatbot's view of the graph: a client, and the services it owns."""

    client: HydraClient
    ids: IdAllocator
    workspace: Workspace

    @property
    def service_ids(self) -> list[int]:
        return list(self.workspace.service_ids)

    @property
    def service_names(self) -> list[str]:
        return list(self.workspace.service_names)

    @property
    def name_set(self) -> set[str]:
        """Lowercased owned service names, for filtering name-keyed results."""
        return {n.strip().lower() for n in self.workspace.service_names}

    def owns(self, service_name: str) -> bool:
        return (service_name or "").strip().lower() in self.name_set

    def mine(self, names: list[str]) -> list[str]:
        """Keep only the service names this workspace owns."""
        return sorted({n for n in names if self.owns(n)})


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _clean(value: Any, default: Any = "") -> Any:
    """HydraDB returns `{"type": "null"}` for a property that was never set.

    Left alone it reaches the model as a JSON object where a string belongs,
    and a model shown `{"type":"null"}` under `fixed_version` will cheerfully
    describe it as the fix. Normalised here, once.
    """
    if isinstance(value, dict):
        return default
    if value is None:
        return default
    return value


def _read_epoch(client: HydraClient) -> Any:
    """The graph's write epoch -- the cache key everything derived uses.

    Same trick `ui/server.py` uses. Returning None disables caching rather
    than risking a stale answer, which for exposure data is the right way to
    fail.
    """
    try:
        return client.query("MATCH (n {id: 0}) RETURN n.id AS id").read_epoch
    except HydraError:
        return None


def split_spec(spec: str) -> tuple[str, str]:
    """`lodash@4.17.21` -> ("lodash", "4.17.21"). Scoped names keep their @."""
    trimmed = (spec or "").strip()
    at = trimmed.rfind("@")
    if at <= 0:
        return trimmed, ""
    return trimmed[:at], trimmed[at + 1:]


def _cap(rows: list, limit: int) -> tuple[list, int]:
    """Trim a list and report the remainder, so nothing vanishes silently."""
    if len(rows) <= limit:
        return rows, 0
    return rows[:limit], len(rows) - limit


def _split_versions(values: Any) -> list[str]:
    """Normalise a fixed-version list that may hold joined strings.

    OSV reports one fixed version per affected range, and the scan writes them
    back joined -- `uuid` arrives as the single entry `"11.1.1; 12.0.1; 13.0.1"`
    for its three maintained majors. Left alone that string becomes the target
    of a generated `npm install uuid@11.1.1; 12.0.1; 13.0.1`, which is both
    wrong and, with the semicolons, a shell command the user did not intend.
    """
    from blastradius.pkg.semver import try_parse

    out: list[str] = []
    for value in values or []:
        for part in str(value).replace(",", ";").split(";"):
            token = part.strip()
            if token:
                out.append(token)

    def _key(text: str) -> tuple:
        parsed = try_parse(text)
        # Unparseable versions sort last rather than crashing the answer, and
        # keep their text so a human can still read them.
        return (0, parsed.major, parsed.minor, parsed.patch) if parsed else (1, 0, 0, 0)

    return sorted(dict.fromkeys(out), key=_key)


def recommended_fix(installed: str, fixed_versions: list[str]) -> str:
    """The lowest published fix that is actually an upgrade from `installed`.

    OSV lists a fixed version per affected *branch*, so a single advisory on
    `vite@5.4.21` reports `0.1.24`, `2.14.1`, `6.4.3`, `7.3.5` and `8.0.16`
    together. Taking the lowest of those -- the obvious "smallest upgrade"
    reading -- recommends `0.1.24`, which is a five-major **downgrade** onto a
    branch that was never patched. Telling somebody to downgrade in response
    to a vulnerability is worse advice than saying nothing, so the candidate
    set is filtered to versions above what is installed before the lowest is
    taken.

    Returns "" when no published fix is above the installed version, which is
    a real answer: it means the branch in use has no patch and the fix is a
    major upgrade the advisory did not enumerate, a replacement, or a
    compensating control.
    """
    from blastradius.pkg.semver import try_parse

    current = try_parse(installed)
    candidates = []
    for text in fixed_versions or []:
        parsed = try_parse(text)
        if parsed is None:
            continue
        if current is None or parsed > current:
            candidates.append((parsed, text))
    if not candidates:
        return ""
    candidates.sort(key=lambda pair: pair[0])
    return candidates[0][1]


# --------------------------------------------------------------------------
# advisory detail, merged from disk and remembered across scans
# --------------------------------------------------------------------------


def _load_advisory_cache() -> dict[str, dict]:
    global _advisory_cache
    with _lock:
        if _advisory_cache is not None:
            return _advisory_cache
        data: dict[str, dict] = {}
        if ADVISORY_CACHE.exists():
            try:
                data = json.loads(ADVISORY_CACHE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {}
        _advisory_cache = data if isinstance(data, dict) else {}
        return _advisory_cache


def advisory_facts(refresh: bool = False) -> dict[str, dict]:
    """advisory id -> the detail the graph node does not carry.

    `Advisory` nodes hold an id, a severity and a summary. Fixed versions,
    CVSS vectors, aliases and references live only in the JSON the scan wrote,
    and that directory is rewritten per scan -- so what is on disk now is
    folded into a cache that outlives it.
    """
    global _advisory_cache
    with _lock:
        cache = dict(_load_advisory_cache())
        changed = False
        files = list((ADVISORY_DIR / "generated").glob("*.json"))
        files += list(ADVISORY_DIR.glob("*.json"))
        for path in files:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            key = str(raw.get("advisory_id") or "").strip()
            if not key:
                continue
            entry = {
                "advisory_id": key,
                "package": raw.get("package", ""),
                "severity": raw.get("severity", ""),
                "summary": raw.get("summary", ""),
                "cvss_vector": raw.get("cvss_vector", ""),
                "affected_versions": list(raw.get("affected_versions") or []),
                "affected_range": raw.get("affected_range", ""),
                "fixed_versions": _split_versions(raw.get("fixed_versions")),
                "aliases": list(raw.get("aliases") or []),
                "references": list(raw.get("references") or [])[:3],
                "published_at": raw.get("published_at") or 0,
            }
            if cache.get(key) != entry:
                cache[key] = entry
                changed = True
        if changed or refresh:
            try:
                ADVISORY_CACHE.parent.mkdir(parents=True, exist_ok=True)
                ADVISORY_CACHE.write_text(
                    json.dumps(cache, indent=1), encoding="utf-8"
                )
            except OSError:
                pass  # a read-only data/ is not worth failing a question over
        _advisory_cache = cache
        return cache


# --------------------------------------------------------------------------
# the two cached reads everything else is built from
# --------------------------------------------------------------------------


def code_index(scope: Scope) -> codereach.CodeIndex:
    """The code tier, the bridge and the dependency tree, read once per epoch."""
    global _index_cache
    epoch = _read_epoch(scope.client)
    cached_epoch, cached = _index_cache
    if cached is not None and epoch is not None and cached_epoch == epoch:
        return cached
    index = codereach.build_index(scope.client)
    if epoch is not None:
        _index_cache = (epoch, index)
    return index


def workspace_packages(scope: Scope) -> list[dict]:
    """Every package version this workspace's services resolve.

    One pinned lookup per owned service over the flattened `PRESENT_IN`
    closure, so it is exact at any depth rather than bounded by a
    variable-length walk -- see the README on why the closure is materialised.
    """
    epoch = _read_epoch(scope.client)
    key = (epoch, scope.workspace.id)
    if epoch is not None and key in _packages_cache:
        return _packages_cache[key]

    names = _service_names_by_id(scope)
    rows: list[dict] = []
    for service_id in scope.service_ids:
        result = scope.client.query(
            f"MATCH (s:{schema.SERVICE} {{id: $id}})-[e:{schema.HAS_PACKAGE}]->"
            f"(v:{schema.PACKAGE_VERSION}) "
            "RETURN v.id AS id, v.name AS name, v.version AS version, "
            "e.depth AS depth, e.dev AS dev, e.direct AS direct",
            {"id": service_id},
        )
        name = names.get(service_id, str(service_id))
        for row in result.rows:
            rows.append({
                "id": row["id"],
                "name": _clean(row.get("name")),
                "version": _clean(row.get("version")),
                "service": name,
                "depth": _clean(row.get("depth"), -1),
                "dev": bool(_clean(row.get("dev"), False)),
                "direct": bool(_clean(row.get("direct"), False)),
            })
    if epoch is not None:
        _packages_cache[key] = rows
    return rows


def _service_names_by_id(scope: Scope) -> dict[int, str]:
    """service id -> name, resolved in one pass over the workspace.

    Built whole rather than looked up per row: the naive form is one sqlite
    hit per (service, candidate name) pair, which on a twelve-service repo is
    144 lookups to label twelve queries.
    """
    from blastradius.pkg.identity import service_key

    out: dict[int, str] = {}
    for name in scope.workspace.service_names:
        try:
            found = scope.ids.lookup(schema.SERVICE, service_key(name))
        except InvalidPackageName:
            continue
        if found is not None:
            out[found] = name
    return out


def has_code_graph(scope: Scope) -> bool:
    """True when any file in this workspace's services was actually parsed.

    The distinction this protects is the important one. An empty code tier
    makes every reachability question answer "nothing reaches your code",
    which is indistinguishable from a real all-clear and is wrong in the most
    flattering possible direction.
    """
    index = code_index(scope)
    return any(
        scope.owns(fn.get("service", ""))
        for fn in index.functions.values()
    )


# --------------------------------------------------------------------------
# tools
# --------------------------------------------------------------------------


def fleet_overview(scope: Scope) -> dict:
    """What this repository is, in counts. The zero-tool answer to "how bad is it"."""
    packages = workspace_packages(scope)
    by_service: dict[str, int] = {}
    for row in packages:
        by_service[row["service"]] = by_service.get(row["service"], 0) + 1

    threats = _scoped_threats(scope)
    reachable = [t for t in threats if t["in_code"]]
    return {
        "workspace": scope.workspace.label,
        "repo_path": scope.workspace.repo_path,
        "services": [
            {"name": name, "packages": count}
            for name, count in sorted(by_service.items())
        ],
        "service_count": len(scope.service_ids),
        "distinct_versions": len({r["id"] for r in packages}),
        "distinct_packages": len({r["name"] for r in packages}),
        "direct_dependencies": len({r["name"] for r in packages if r["direct"]}),
        "threats": {
            "total": len(threats),
            "reaching_code": len(reachable),
            "by_severity": _severity_counts(threats),
            "by_kind": _kind_counts(threats),
        },
        "code_graph_ingested": has_code_graph(scope),
        "note": (
            ""
            if has_code_graph(scope)
            else "No source was parsed for this repository, so reachability is "
                 "unknown rather than clear. Findings below are lockfile-level only."
        ),
    }


def _severity_counts(threats: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for threat in threats:
        label = threat.get("severity") or "unknown"
        out[label] = out.get(label, 0) + 1
    return out


def _kind_counts(threats: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for threat in threats:
        label = threat.get("kind") or "unknown"
        out[label] = out.get(label, 0) + 1
    return out


def _scoped_threats(scope: Scope) -> list[dict]:
    """Confirmed threats, filtered to versions this workspace's services hold.

    `codereach.threats` answers for the whole graph; a threat that only lands
    on another repository's services is not this chatbot's to report, and
    letting one through is exactly the mixing this design exists to stop.
    """
    epoch = _read_epoch(scope.client)
    key = (epoch, scope.workspace.id)
    if epoch is not None and key in _threats_cache:
        return _threats_cache[key]

    index = code_index(scope)
    try:
        found = codereach.threats(scope.client, index)
    except HydraError:
        return []

    facts = advisory_facts()
    held = {row["id"] for row in workspace_packages(scope)}

    out: list[dict] = []
    for threat in found:
        row = threat.to_dict()
        services = scope.mine(row.get("services") or [])
        # Two ways a threat belongs to this workspace: a service of ours
        # resolves it, or our closure holds the version. The second catches a
        # version present through the tree when the per-version service list
        # is empty.
        if not services and row["id"] not in held:
            continue
        row["services"] = services
        row["fixed_versions"] = _split_versions([
            fix
            for advisory in row.get("advisories") or []
            for fix in facts.get(
                str(advisory.get("advisory_id", "")), {}
            ).get("fixed_versions", [])
        ])
        row["recommended_fix"] = recommended_fix(
            row.get("version", ""), row["fixed_versions"]
        )
        out.append(row)

    if epoch is not None:
        _threats_cache[key] = out
    return out


def list_threats(
    scope: Scope,
    only_reaching_code: bool = False,
    severity: str = "",
    limit: int = 12,
) -> dict:
    """Everything confirmed wrong with this repository, worst first.

    Ranked by `codereach.Threat.rank`, which puts code reach above severity on
    purpose: a moderate advisory a route handler calls is a worse morning than
    a critical one on a dev dependency nothing imports.
    """
    threats = _scoped_threats(scope)
    if only_reaching_code:
        threats = [t for t in threats if t["in_code"]]
    if severity:
        wanted = severity.strip().lower()
        threats = [t for t in threats if (t.get("severity") or "").lower() == wanted]

    shown, omitted = _cap(threats, max(1, min(int(limit or 12), 40)))
    return {
        "count": len(threats),
        "reaching_code": sum(1 for t in threats if t["in_code"]),
        "threats": [
            {
                "spec": t["spec"],
                "kind": t["kind"],
                "severity": t["severity"],
                "advisories": [
                    a.get("advisory_id") for a in (t.get("advisories") or [])
                ],
                "services": t["services"],
                "reaches_code": t["in_code"],
                "functions": t.get("function_count", 0),
                "fixed_versions": t.get("fixed_versions") or [],
                "recommended_fix": t.get("recommended_fix", ""),
            }
            for t in shown
        ],
        "omitted": omitted,
        "code_graph_ingested": has_code_graph(scope),
        "note": _reach_caveat(scope),
    }


def _reach_caveat(scope: Scope) -> str:
    if has_code_graph(scope):
        return ""
    return (
        "The code graph is empty for this repository, so `reaches_code` is "
        "unknown for every row -- not false. Say so rather than reporting "
        "anything as unreachable."
    )


def resolve_package(scope: Scope, query: str) -> dict:
    """Turn a name a human typed into the exact versions this repo holds.

    The entry point for nearly every other tool. Without it a model asked
    about "lodash" has to guess a version, and a guessed version is a made-up
    finding. Matching happens over the workspace's own package list, so a
    version another repository holds is never offered here.
    """
    text = (query or "").strip().lower()
    if not text:
        return {"query": query, "matches": [], "note": "empty query"}

    name, version = split_spec(text)
    packages = workspace_packages(scope)

    by_spec: dict[str, dict] = {}
    for row in packages:
        spec = f"{row['name']}@{row['version']}"
        entry = by_spec.setdefault(spec, {
            "spec": spec,
            "name": row["name"],
            "version": row["version"],
            "services": [],
            "direct": False,
            "dev_only": True,
        })
        entry["services"].append(row["service"])
        entry["direct"] = entry["direct"] or row["direct"]
        entry["dev_only"] = entry["dev_only"] and row["dev"]

    exact = [e for e in by_spec.values() if e["name"] == name and (
        not version or e["version"] == version
    )]
    if exact:
        matches = exact
        how = "exact"
    else:
        contains = [e for e in by_spec.values() if text in e["name"]]
        if not contains and name:
            contains = [e for e in by_spec.values() if name in e["name"]]
        matches = contains
        how = "substring"

    matches = sorted(matches, key=lambda e: (e["name"], e["version"]))
    shown, omitted = _cap(matches, 12)
    return {
        "query": query,
        "match_type": how if matches else "none",
        "matches": [
            {
                "spec": e["spec"],
                "services": sorted(set(e["services"])),
                "direct": e["direct"],
                "dev_only": e["dev_only"],
            }
            for e in shown
        ],
        "omitted": omitted,
        "note": (
            ""
            if matches
            else f"No package matching {query!r} is resolved by any service in "
                 f"{scope.workspace.label}. It may exist in another repository, "
                 f"or not be installed here at all."
        ),
    }


def threat_detail(scope: Scope, spec: str) -> dict:
    """Everything known about one version: advisories, severity, fixes, reach."""
    name, version = split_spec(spec)
    threats = {t["spec"]: t for t in _scoped_threats(scope)}
    facts = advisory_facts()

    found = threats.get(f"{name}@{version}")
    if found is None:
        resolved = resolve_package(scope, spec)
        return {
            "spec": spec,
            "found": False,
            "suggestions": [m["spec"] for m in resolved["matches"][:5]],
            "note": (
                f"Nothing is filed against {spec} in {scope.workspace.label}. "
                "That means no advisory, incident or deprecation names it -- "
                "not that it is unused."
            ),
        }

    detail = []
    for advisory in found.get("advisories") or []:
        key = str(advisory.get("advisory_id", ""))
        extra = facts.get(key, {})
        detail.append({
            "advisory_id": key,
            "severity": advisory.get("severity") or extra.get("severity", ""),
            "summary": advisory.get("summary") or extra.get("summary", ""),
            "cvss_vector": extra.get("cvss_vector", ""),
            "fixed_versions": extra.get("fixed_versions", []),
            "aliases": extra.get("aliases", []),
            "references": extra.get("references", []),
        })

    return {
        "spec": found["spec"],
        "found": True,
        "kind": found["kind"],
        "severity": found["severity"],
        "advisories": detail,
        "incident": found.get("incident"),
        "deprecated_reason": found.get("deprecated_reason", ""),
        "services": found["services"],
        "reaches_code": found["in_code"],
        "functions": found.get("function_count", 0),
        "fixed_versions": found.get("fixed_versions") or [],
        "recommended_fix": found.get("recommended_fix", ""),
        "note": _reach_caveat(scope),
    }


def impacted_services(scope: Scope, spec: str) -> dict:
    """Which of this repository's services resolve one exact version, and how.

    `direct` and `dev` come off the closure edge rather than being inferred,
    because they decide the fix: a direct dependency is a version bump, a
    transitive one needs an override, and a dev-only one is not in production
    at all.
    """
    name, version = split_spec(spec)
    if not version:
        resolved = resolve_package(scope, spec)
        if len(resolved["matches"]) != 1:
            return {
                "spec": spec,
                "services": [],
                "note": "Needs an exact name@version. Candidates: "
                        + ", ".join(m["spec"] for m in resolved["matches"][:6])
                        + ("" if resolved["matches"] else "none in this repository."),
            }
        name, version = split_spec(resolved["matches"][0]["spec"])

    rows = [
        r for r in workspace_packages(scope)
        if r["name"] == name and r["version"] == version
    ]
    if not rows:
        return {
            "spec": f"{name}@{version}",
            "services": [],
            "note": f"No service in {scope.workspace.label} resolves "
                    f"{name}@{version}.",
        }

    return {
        "spec": f"{name}@{version}",
        "service_count": len({r["service"] for r in rows}),
        "services": sorted(
            (
                {
                    "service": r["service"],
                    "depth": r["depth"],
                    "direct": r["direct"],
                    "dev_only": r["dev"],
                }
                for r in rows
            ),
            key=lambda r: (not r["direct"], r["depth"], r["service"]),
        )[:25],
        "production_services": sorted(
            {r["service"] for r in rows if not r["dev"]}
        ),
        "dev_only_services": sorted(
            {r["service"] for r in rows if r["dev"]}
        ),
        "note": "",
    }


def code_reach(scope: Scope, spec: str) -> dict:
    """Can a line of source here actually run this version?

    The claim no lockfile scanner can make, and the one that separates
    patch-now from patch-Tuesday. Returns the import, the functions that call
    it and the routes that reach those functions -- all filtered to services
    this workspace owns.
    """
    name, version = split_spec(spec)
    if not has_code_graph(scope):
        return {
            "spec": spec,
            "reaches_code": None,
            "imports": [],
            "functions": [],
            "routes": [],
            "note": (
                f"No source was parsed for {scope.workspace.label}, so this is "
                "unknown, not clear. Run `python -m blastradius.cli ingest "
                f"--corpus {scope.workspace.repo_path}` to build the code graph."
            ),
        }

    index = code_index(scope)
    try:
        reach = codereach.code_reach(scope.client, name, version, index)
    except HydraError as exc:
        return {"spec": spec, "reaches_code": None, "note": f"graph error: {exc}"}

    payload = reach.to_dict()
    nodes = [
        n for n in payload.get("nodes") or []
        if not n.get("service") or scope.owns(n.get("service", ""))
    ]
    kinds: dict[str, list[dict]] = {}
    for node in nodes:
        kinds.setdefault(node.get("kind") or node.get("label") or "node", []).append(node)

    def _labels(kind: str, limit: int = 8) -> list[str]:
        rows = kinds.get(kind) or []
        return [str(n.get("label") or n.get("name") or n.get("id")) for n in rows[:limit]]

    imports = _labels("import") + _labels("ExternalImport")
    functions = _labels("function") + _labels("Function")
    routes = _labels("route") + _labels("Route")

    return {
        "spec": f"{name}@{version}",
        "reaches_code": bool(payload.get("found")) and bool(imports or functions),
        "imports": imports,
        "functions": functions,
        "routes": routes,
        "truncated_callers": payload.get("truncated_callers", 0),
        "note": payload.get("note", "") or (
            "" if imports or functions else
            f"{name}@{version} is installed here but no parsed source imports "
            "it. That is 'not reached from your code', which is weaker than "
            "'not affected' -- the package is still on disk."
        ),
    }


def dependency_path(scope: Scope, spec: str, service: str = "") -> dict:
    """Why this repository has a package at all -- the chain that pulled it in.

    Answers "we never installed that" with the parent that did.
    """
    name, version = split_spec(spec)
    targets = [service] if service and scope.owns(service) else scope.service_names
    try:
        key = version_key(name, version)
    except InvalidPackageName as exc:
        return {"spec": spec, "paths": [], "note": str(exc)}

    try:
        found = blast.dependency_paths(scope.client, [key], targets)
    except HydraError as exc:
        return {"spec": spec, "paths": [], "note": f"graph error: {exc}"}

    rendered: list[str] = []
    for path in found[:6]:
        text = _render_path(path)
        if text:
            rendered.append(text)

    return {
        "spec": f"{name}@{version}",
        "scanned_services": len(targets),
        "paths": rendered,
        "note": "" if rendered else (
            f"No dependency chain from {name}@{version} out to a service in "
            f"{scope.workspace.label} was found. It may be a direct dependency, "
            "or not installed here."
        ),
    }


def _prop(node: dict, name: str) -> str:
    """One property off a path node, through the engine's type wrappers.

    `algo.MSpaths` returns whole nodes rather than projections, and their
    properties arrive tagged -- `{"name": {"String": "find-my-way"}}`. Reading
    them like a flat dict yields nothing, which is how a dependency chain came
    out as `200000488 -> 200000474 -> 100000014`: every label fell through to
    the node id, turning the one answer a human most wants to read into a row
    of meaningless numbers.
    """
    raw = (node.get("properties") or {}).get(name)
    if isinstance(raw, dict):
        for value in raw.values():
            return str(value)
        return ""
    return "" if raw is None else str(raw)


def _node_label(node: dict) -> str:
    """A path node as a person would name it."""
    if not isinstance(node, dict):
        return str(node)
    labels = node.get("labels") or []
    name = _prop(node, "name")
    if schema.SERVICE in labels:
        return name or _prop(node, "key") or str(node.get("id", "?"))
    version = _prop(node, "version")
    if name and version:
        return f"{name}@{version}"
    # `key` is the canonical purl, which still reads far better than an id.
    return name or _prop(node, "key") or str(node.get("id", "?"))


def _render_path(path: Any) -> str:
    """A returned path rendered as `a -> b -> c`, defensively.

    The procedure's shape is engine-side and has changed before, so a bad
    shape degrades to a shorter answer rather than raising inside a tool call.
    """
    try:
        if isinstance(path, dict):
            nodes = path.get("nodes") or path.get("path") or []
            labels = [label for label in (_node_label(n) for n in nodes) if label]
            # An empty chain renders as nothing, never as the container's repr.
            # Falling through here once put `{'nodes': []}` in front of the
            # model as though it were a dependency path.
            return " -> ".join(labels)
        if isinstance(path, (list, tuple)):
            return " -> ".join(_node_label(p) for p in path)
        return str(path)[:300]
    except Exception:  # pragma: no cover -- shape guard, never a failed answer
        return ""


def remediation_plan(scope: Scope, spec: str) -> dict:
    """How to actually protect this repository from one bad version.

    Assembled from facts rather than advice: the fixed versions the advisory
    named, whether each affected service depends on it directly or through the
    tree, and therefore whether the fix is a bump or an override. Priority
    comes from reach, matching the tiering the rest of the tool uses.
    """
    detail = threat_detail(scope, spec)
    impact = impacted_services(scope, spec)
    name, version = split_spec(detail.get("spec") or spec)

    fixes = detail.get("fixed_versions") or []
    direct = [s for s in impact.get("services") or [] if s.get("direct")]
    indirect = [s for s in impact.get("services") or [] if not s.get("direct")]
    prod = impact.get("production_services") or []

    # Never the lowest published fix -- the lowest one above what is installed.
    # See `recommended_fix` for why the difference is a downgrade.
    target = detail.get("recommended_fix") or recommended_fix(version, fixes)

    steps: list[str] = []
    if target:
        if direct:
            steps.append(
                f"Bump the direct dependency in "
                f"{', '.join(s['service'] for s in direct[:6])}: "
                f"npm install {name}@{target}"
            )
        if indirect:
            steps.append(
                f"{len(indirect)} service(s) pull {name} in transitively, so a "
                f"direct install will not move them. Pin it with an overrides "
                f'block in package.json: {{"overrides": {{"{name}": "{target}"}}}}, '
                "then npm install to rewrite the lockfile."
            )
        steps.append(
            f"Re-run `python -m blastradius.cli pipeline {scope.workspace.repo_path}` "
            "and confirm the finding is gone rather than assuming the bump took."
        )
    elif fixes:
        steps.append(
            f"Every published fix for this advisory ({', '.join(fixes[:6])}) is "
            f"below the installed {version}, so there is no forward upgrade on "
            "this branch. Moving to a newer major, replacing the dependency, or "
            "a compensating control at the call site are the options -- do not "
            "downgrade onto an unpatched branch."
        )
    else:
        steps.append(
            f"No fixed version is published for {name}@{version} in the advisory "
            "data on hand. The options are to remove the dependency, replace it, "
            "or apply a compensating control at the call site."
        )

    if detail.get("reaches_code"):
        priority = "P1 REACHABLE -- application code calls into this. Patch now."
    elif detail.get("reaches_code") is None or not has_code_graph(scope):
        priority = (
            "UNKNOWN reach -- no source was parsed for this repository, so this "
            "cannot be deprioritised on reachability. Treat as reachable until "
            "the code graph is built."
        )
    elif prod:
        priority = (
            "P3 INSTALLED -- present in production dependencies but no parsed "
            "source imports it. Safe to schedule rather than page for."
        )
    else:
        priority = (
            "P3 INSTALLED, dev-only -- not shipped to users. The lowest "
            "priority thing on this list."
        )

    return {
        "spec": f"{name}@{version}",
        "found": detail.get("found", False),
        "severity": detail.get("severity", ""),
        "fixed_versions": fixes,
        "recommended_fix": target,
        "affected_services": impact.get("service_count", 0),
        "direct_services": [s["service"] for s in direct],
        "transitive_services": [s["service"] for s in indirect][:10],
        "production_services": prod,
        "priority": priority,
        "steps": steps,
        "note": detail.get("note", ""),
    }


def attack_frontier(scope: Scope, spec: str) -> dict:
    """Where the compromise goes next, and which credentials to rotate.

    The forward-looking half. Given a bad version, the accounts and CI
    repositories behind it can publish to other packages too -- and some of
    those are ones this repository already resolves. Every row is a lead at
    INVESTIGATE confidence, never a verdict, and is reported as such.
    """
    from blastradius.pkg.blast import BlastRadius
    from blastradius.pkg.frontier import FrontierEngine

    name, version = split_spec(spec)
    try:
        engine = FrontierEngine(scope.client, scope.ids)
        result = engine.analyse(
            name, version, result=BlastRadius(target=f"{name}@{version}"),
            measure_impact=True,
        )
    except (HydraError, LookupError) as exc:
        return {"spec": spec, "targets": [], "note": f"could not analyse: {exc}"}

    if not result.exists:
        return {
            "spec": spec,
            "targets": [],
            "note": f"{spec} is not a version this graph holds, so there is no "
                    "publish surface to project from it.",
        }

    mine = {r["name"] for r in workspace_packages(scope)}
    rows = []
    for target in result.targets:
        rows.append({
            "package": target.package,
            "already_used_here": target.package in mine,
            "routes": sorted(target.routes.keys()),
            "identities": sorted(target.identities)[:4],
            "confidence": target.confidence,
        })
    rows.sort(key=lambda r: (not r["already_used_here"], r["package"]))
    shown, omitted = _cap(rows, 12)

    return {
        "spec": f"{name}@{version}",
        "reachable_packages": result.reachable_packages,
        "already_used_here": sum(1 for r in rows if r["already_used_here"]),
        "targets": shown,
        "omitted": omitted,
        "rotate": {
            route: sorted(who)[:6] for route, who in result.implicated.items()
        },
        "note": "Every row here is a lead at INVESTIGATE confidence -- shared "
                "publish rights, not observed compromise. Rotate the named "
                "credentials; do not report these as compromised packages.",
    }


# --------------------------------------------------------------------------
# provenance -- who pushed the artifact, and who else could have
# --------------------------------------------------------------------------
#
# Every other tool here reads the two dependency tiers: what is installed, and
# what the code reaches. Neither can answer the first question anybody asks
# about a compromise -- *whose account published this?* -- because that lives
# on a third set of edges the ingest writes from registry metadata:
#
#     PackageVersion --PUBLISHED_BY-->  PublisherIdentity   pushed THIS artifact
#     Package        --MAINTAINED_BY--> Maintainer          COULD push one
#     PackageVersion --SOURCED_FROM-->  Repository          whose CI builds it
#
# Two honesty rules run through the tools below, and both of them cost answers.
#
# **A missing publisher is "not recorded", never "nobody".** Metadata is
# fetched per package and an ingest run with --no-metadata skips it entirely,
# so an empty result means the registry was never asked. Returned as
# `publisher_known: false` with the reason attached, because an empty list
# reads to a model as a finding and this one is an absence of data.
#
# **The account that published is not thereby the attacker.** A publisher
# outside the package's own maintainer list is the signature of a stolen
# token. It is also what every OIDC release, every bot and every former
# maintainer looks like. Reported as a lead, with the wording that says so.


def _publisher_rows(scope: Scope, version_id: int) -> list[dict]:
    """The accounts recorded against one exact artifact."""
    return [
        {"username": _clean(r.get("username")), "email": _clean(r.get("email"))}
        for r in scope.client.query(
            f"MATCH (v:{schema.PACKAGE_VERSION} {{id: $id}})"
            f"-[:{schema.PUBLISHED_BY}]->(p:{schema.PUBLISHER}) "
            "RETURN p.username AS username, p.email AS email ORDER BY username",
            {"id": version_id},
        ).rows
    ]


def _maintainer_rows(scope: Scope, package_id: int) -> list[dict]:
    """The accounts holding publish rights on the package name."""
    return [
        {"username": _clean(r.get("username")), "email": _clean(r.get("email"))}
        for r in scope.client.query(
            f"MATCH (p:{schema.PACKAGE} {{id: $id}})"
            f"-[:{schema.MAINTAINED_BY}]->(m:{schema.MAINTAINER}) "
            "RETURN m.username AS username, m.email AS email ORDER BY username",
            {"id": package_id},
        ).rows
    ]


def _pkg_ids(scope: Scope, name: str, version: str) -> tuple:
    """(version id, package id) out of the local id map, or (None, None)."""
    from blastradius.pkg.identity import package_key, version_key

    try:
        return (
            scope.ids.lookup(schema.PACKAGE_VERSION, version_key(name, version)),
            scope.ids.lookup(schema.PACKAGE, package_key(name)),
        )
    except InvalidPackageName:
        return None, None


def package_provenance(scope: Scope, spec: str) -> dict:
    """Who published one exact version, and who else holds publish rights.

    Reports the publishing account, the accounts listed as maintainers, the
    source repository, any incident filed against the artifact, and -- when
    this exact version carries no publisher record -- the accounts that pushed
    the package's *other* versions. That last one is still an answer to "whose
    credentials could have done this" on a version the ingest never enriched.

    Nothing here is a verdict; see the section comment above for why.
    """
    name, version = split_spec(spec)
    if not version:
        resolved = resolve_package(scope, spec)
        if len(resolved["matches"]) != 1:
            return {
                "spec": spec,
                "found": False,
                "suggestions": [m["spec"] for m in resolved["matches"][:6]],
                "note": "Needs an exact name@version to trace provenance."
                        + ("" if resolved["matches"] else
                           f" Nothing matching {spec!r} is resolved by "
                           f"{scope.workspace.label}."),
            }
        name, version = split_spec(resolved["matches"][0]["spec"])

    held = {(r["name"], r["version"]) for r in workspace_packages(scope)}
    if (name, version) not in held:
        return {
            "spec": f"{name}@{version}",
            "found": False,
            "note": f"No service in {scope.workspace.label} resolves "
                    f"{name}@{version}, so this chatbot holds no provenance "
                    "for it.",
        }

    version_id, package_id = _pkg_ids(scope, name, version)
    if version_id is None:
        return {
            "spec": f"{name}@{version}",
            "found": False,
            "note": f"{name}@{version} has no node in the graph's id map.",
        }

    from blastradius.pkg.identity import is_service_identity

    try:
        publishers = _publisher_rows(scope, version_id)
        maintainers = _maintainer_rows(scope, package_id) if package_id else []
        repos = scope.client.query(
            f"MATCH (v:{schema.PACKAGE_VERSION} {{id: $id}})"
            f"-[:{schema.SOURCED_FROM}]->(r:{schema.REPOSITORY}) "
            "RETURN r.url AS url ORDER BY url",
            {"id": version_id},
        ).rows
        node = scope.client.query(
            f"MATCH (v:{schema.PACKAGE_VERSION} {{id: $id}}) "
            "RETURN v.published_at AS published_at, "
            "v.has_install_script AS has_install_script",
            {"id": version_id},
        ).rows
        # Pinned on the *target*, because the ingest writes COMPROMISES and
        # not its inverse -- walking back from the version finds nothing.
        incidents = scope.client.query(
            f"MATCH (i:{schema.INCIDENT})-[:{schema.COMPROMISES}]->"
            f"(v:{schema.PACKAGE_VERSION} {{id: $id}}) "
            "RETURN i.incident_id AS incident_id, i.status AS status, "
            "i.summary AS summary",
            {"id": version_id},
        ).rows
        siblings = scope.client.query(
            f"MATCH (p:{schema.PACKAGE} {{id: $id}})"
            f"-[:{schema.HAS_VERSION}]->(v:{schema.PACKAGE_VERSION})"
            f"-[:{schema.PUBLISHED_BY}]->(q:{schema.PUBLISHER}) "
            "RETURN v.version AS version, q.username AS username "
            "ORDER BY username",
            {"id": package_id},
        ).rows if package_id else []
    except HydraError as exc:
        return {
            "spec": f"{name}@{version}",
            "found": False,
            "note": f"the graph could not be read: {exc}",
        }

    maintainer_names = [m["username"] for m in maintainers if m["username"]]
    listed = set(maintainer_names)

    published_by = []
    for row in publishers:
        who = row["username"]
        published_by.append({
            "username": who,
            "email": row["email"],
            "is_listed_maintainer": who in listed,
            # `GitHub Actions` / npm-oidc-no-reply is stamped on every artifact
            # pushed through trusted publishing, so it names a pipeline rather
            # than a person. Same rule the frontier uses, for the same reason:
            # treating it as a credential to rotate is a category error.
            "is_automation": is_service_identity(who, row["email"]),
        })

    # Who else has pushed this package. The fallback for a version whose own
    # publisher edge was never written -- distinct accounts, each with the
    # versions that witness them.
    others: dict = {}
    for row in siblings:
        who = _clean(row.get("username"))
        found_version = _clean(row.get("version"))
        if not who or found_version == version:
            continue
        others.setdefault(who, []).append(found_version)

    install_script = bool(_clean(node[0].get("has_install_script"), 0)) if node else False

    signals: list[str] = []
    for entry in published_by:
        if entry["is_automation"]:
            signals.append(
                f"{entry['username']} is a CI/OIDC publishing identity rather "
                "than a person -- it names the pipeline that pushed the "
                "artifact, not an account to rotate."
            )
        elif maintainer_names and not entry["is_listed_maintainer"]:
            signals.append(
                f"PUBLISHER_NOT_MAINTAINER: {entry['username']} pushed this "
                "version but is not among the listed maintainers "
                f"({', '.join(maintainer_names[:6])}). That is the shape of a "
                "stolen publish token, and also of a routine release by a bot "
                "or a former maintainer. INVESTIGATE, not a verdict."
            )
    if install_script:
        signals.append(
            "This version runs an install script, so installing it executes "
            "code before anything imports it."
        )

    return {
        "spec": f"{name}@{version}",
        "found": True,
        "publisher_known": bool(published_by),
        "published_by": published_by,
        "maintainers": maintainer_names,
        "source_repository": _clean(repos[0].get("url")) if repos else "",
        "published_at": _clean(node[0].get("published_at"), 0) if node else 0,
        "has_install_script": install_script,
        "incident": [
            {
                "incident_id": _clean(i.get("incident_id")),
                "status": _clean(i.get("status")),
                "summary": _clean(i.get("summary")),
            }
            for i in incidents
        ],
        "other_publishers_of_this_package": [
            {"username": who, "versions": sorted(versions)[:4]}
            for who, versions in sorted(others.items())
        ][:8],
        "signals": signals,
        "note": (
            ""
            if published_by
            else (
                f"No publishing account is recorded for {name}@{version}. The "
                "registry metadata for this version was never fetched -- an "
                "ingest run without it, or a version added by a simulation -- "
                "which is NOT the same as it having been published "
                "anonymously. Say 'not recorded' rather than naming anybody. "
                "The accounts under `other_publishers_of_this_package` are who "
                "holds publish rights on the package name, which is the "
                "nearest real answer; offer those instead if there are any."
            )
        ),
    }


def publish_anomalies(scope: Scope, package: str = "", limit: int = 12) -> dict:
    """Which releases in this repository were pushed in a suspicious way.

    The unprompted half of provenance: `package_provenance` answers "who
    pushed *this*", and this answers "which of our packages was pushed by
    somebody who should not have pushed it". It is what a question like *who
    published the malicious package* actually wants when no package is named.

    Read from the **registry metadata cache, never the network**. The signals
    are about publish *history* -- when versions appeared, who pushed them,
    what changed between consecutive releases -- and the graph stores the
    current state of each version rather than the sequence. Offline is not a
    fallback here, it is the mode: a chat question must never fan out hundreds
    of registry reads, and a cached answer is also a reproducible one.

    Packages the cache has never seen are counted and named as *unassessed*
    rather than dropped. A package nobody could read is not a package with
    nothing to report, and that distinction is the whole rule of this module.
    """
    from blastradius.pkg.anomaly import Signal

    wanted = (package or "").strip().lower()
    try:
        found = _publish_signals(scope)
    except Exception as exc:  # a cold cache must not fail the question
        return {
            "package": package,
            "signals": [],
            "note": f"publish history could not be read: {type(exc).__name__}: {exc}",
        }

    rows = found["signals"]
    if wanted:
        name = split_spec(wanted)[0] if "@" in wanted[1:] else wanted
        rows = [r for r in rows if r["package"].lower() == name]

    # Publisher-not-maintainer first: it is the only signal here that names an
    # account which had no business pushing the artifact, which is what makes
    # it the answer to the question rather than context for it.
    order = {
        Signal.PUBLISHER_NOT_MAINTAINER: 0,
        Signal.INSTALL_SCRIPT_ADDED: 1,
        Signal.REPOSITORY_CHANGED: 2,
        Signal.REPOSITORY_REMOVED: 3,
        Signal.DORMANCY_BREAK: 4,
        Signal.PUBLISH_BURST: 5,
    }
    rows = sorted(rows, key=lambda r: (order.get(r["signal"], 9), r["package"]))
    shown, omitted = _cap(rows, max(1, min(int(limit or 12), 40)))

    return {
        "package": package,
        "packages_assessed": found["assessed"],
        "packages_unassessed": found["unassessed"][:8],
        "count": len(rows),
        "signals": shown,
        "omitted": omitted,
        "correlated_bursts": found["bursts"],
        "note": (
            "Every row is a publish-time observation at INVESTIGATE "
            "confidence. None of them says a package is malicious -- "
            "PUBLISHER_NOT_MAINTAINER in particular is equally the shape of a "
            "bot release and of a stolen token. Name the account and the "
            "signal; do not call it an attacker."
            + (
                f" {len(found['unassessed'])} package(s) are not in the "
                "metadata cache and were not assessed at all, so this list is "
                "not exhaustive."
                if found["unassessed"] else ""
            )
        ),
    }


#: (workspace id, sorted package names) -> the publish-history report.
#:
#: Keyed by the package set rather than the graph's read epoch, because the
#: input is the on-disk registry cache and that moves only on an ingest --
#: an epoch key would rebuild this on every unrelated write.
_publish_cache: dict = {}


def _publish_signals(scope: Scope) -> dict:
    """Publish-time signals over this workspace's packages, computed once.

    Roughly 1.8s cold over ~500 packages, all of it reading and parsing cached
    packuments; a few milliseconds warm. Cheap enough to do inside a question,
    expensive enough that doing it per question would be felt.
    """
    from blastradius.pkg.anomaly import analyse_correlated_burst, analyse_package
    from blastradius.pkg.registry import RegistryClient

    names = sorted({r["name"] for r in workspace_packages(scope)})
    key = (scope.workspace.id, tuple(names))
    with _lock:
        if key in _publish_cache:
            return _publish_cache[key]

    missing: list[str] = []
    registry = RegistryClient(offline=True)
    packuments = registry.packuments(
        names, full=True, on_error=lambda n, exc: missing.append(n)
    )

    rows: list[dict] = []
    for packument in packuments.values():
        for signal in analyse_package(packument):
            rows.append({
                "signal": signal.signal,
                "package": signal.package,
                "version": signal.version,
                "spec": f"{signal.package}@{signal.version}",
                "detail": signal.detail,
                "witness": signal.witness,
            })

    bursts = [
        {
            "account": burst.identity,
            "packages": burst.package_count,
            "artifacts": burst.artifact_count,
            "minutes": round(burst.span_seconds / 60, 1),
            # A burst confined to one scope or one repository is a monorepo
            # releasing; volume alone does not separate a worm from a release.
            "verdict": burst.verdict,
            "explanation": burst.explain(),
        }
        for burst in analyse_correlated_burst(list(packuments.values()))
    ][:6]

    report = {
        "signals": rows,
        "bursts": bursts,
        "assessed": len(packuments),
        "unassessed": sorted(missing),
    }
    with _lock:
        _publish_cache[key] = report
    return report


def cached_publish_specs(scope: Scope) -> set:
    """Specs the publish-history tool has already reported, read never built.

    Feeds the grounding audit. These versions are real facts about real
    packages -- `fast-json-stringify@7.0.0` was genuinely published by an
    account outside the maintainer list -- but they are versions this
    repository does not *resolve*, so without this the audit reports the
    tool's own output back as an invention.

    Deliberately does not build the report. The audit runs on every answer and
    a cold build is ~2s, which would land on the first question of every
    conversation; an answer can only name one of these if `publish_anomalies`
    ran during the turn, and that leaves the cache warm behind it.
    """
    names = sorted({r["name"] for r in workspace_packages(scope)})
    with _lock:
        report = _publish_cache.get((scope.workspace.id, tuple(names)))
    if not report:
        return set()

    out = {str(row["spec"]).lower() for row in report["signals"]}
    for burst in report["bursts"]:
        # The burst rows name the versions inside the window in their prose,
        # and an answer quoting one is quoting the tool.
        for token in str(burst.get("explanation", "")).split():
            if "@" in token[1:]:
                out.add(token.strip(".,;:()[]").lower())
    return out


def service_profile(scope: Scope, service: str) -> dict:
    """One service: what it depends on, and what is wrong with it."""
    if not scope.owns(service):
        return {
            "service": service,
            "found": False,
            "note": f"{service!r} is not part of {scope.workspace.label}. This "
                    f"chatbot answers only for: "
                    f"{', '.join(scope.service_names[:12])}.",
        }

    rows = [r for r in workspace_packages(scope) if scope.owns(r["service"])
            and r["service"].lower() == service.strip().lower()]
    threats = [
        t for t in _scoped_threats(scope)
        if any(s.lower() == service.strip().lower() for s in t["services"])
    ]
    shown, omitted = _cap(threats, 10)
    return {
        "service": service,
        "found": True,
        "packages": len({r["id"] for r in rows}),
        "direct_dependencies": sorted({r["name"] for r in rows if r["direct"]})[:25],
        "threats": [
            {
                "spec": t["spec"],
                "severity": t["severity"],
                "reaches_code": t["in_code"],
                "recommended_fix": t.get("recommended_fix", ""),
            }
            for t in shown
        ],
        "threat_count": len(threats),
        "omitted": omitted,
        "note": _reach_caveat(scope),
    }


def search_advisories(scope: Scope, query: str) -> dict:
    """Find an advisory by CVE/GHSA id or by the package it names."""
    text = (query or "").strip().lower()
    facts = advisory_facts()
    threats = _scoped_threats(scope)

    held_ids = {
        str(a.get("advisory_id", ""))
        for t in threats for a in (t.get("advisories") or [])
    }

    hits = []
    for key, entry in facts.items():
        if key not in held_ids:
            continue  # scoped: only advisories that land on this repo
        haystack = " ".join([
            key.lower(),
            str(entry.get("package", "")).lower(),
            str(entry.get("summary", "")).lower(),
            " ".join(str(a).lower() for a in entry.get("aliases") or []),
        ])
        if not text or text in haystack:
            hits.append(entry)

    hits.sort(key=lambda e: str(e.get("advisory_id")))
    shown, omitted = _cap(hits, 10)
    return {
        "query": query,
        "count": len(hits),
        "advisories": [
            {
                "advisory_id": e.get("advisory_id"),
                "package": e.get("package"),
                "severity": e.get("severity"),
                "summary": e.get("summary"),
                "fixed_versions": e.get("fixed_versions") or [],
                "aliases": e.get("aliases") or [],
            }
            for e in shown
        ],
        "omitted": omitted,
        "note": "" if hits else (
            f"No advisory matching {query!r} affects a package "
            f"{scope.workspace.label} resolves."
        ),
    }


def clear_caches() -> None:
    """Drop every derived cache. Used by the tests and after an ingest."""
    global _index_cache, _advisory_cache
    with _lock:
        _index_cache = (None, None)
        _packages_cache.clear()
        _threats_cache.clear()
        _publish_cache.clear()
        _advisory_cache = None
