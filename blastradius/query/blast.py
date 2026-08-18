"""The blast-radius queries, and the severity assessment built from them.

Every traversal here pins its source id and walks forward, because HydraDB
accepts nothing else. Where a query needs to run "backwards" it walks a
materialised inverse edge instead -- see :mod:`blastradius.schema`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .. import schema
from ..hydra_client import HydraClient
from .advisory import Advisory

#: Depth bound for call-graph walks. Unlike the dependency closure -- which is
#: flattened at ingest precisely so it needs no bound -- call chains are short
#: and a bound is honest here. Reported in the result so nobody mistakes a
#: truncated answer for a complete one.
MAX_CALL_DEPTH = 8

TIER_CONFIRMED = "P0 CONFIRMED"
TIER_REACHABLE = "P1 REACHABLE"
TIER_IMPORTED = "P2 IMPORTED"
TIER_INSTALLED = "P3 INSTALLED"

TIER_ORDER = {TIER_CONFIRMED: 0, TIER_REACHABLE: 1, TIER_IMPORTED: 2, TIER_INSTALLED: 3}


@dataclass
class ServiceFinding:
    service: str
    tier: str
    packages: list[str] = field(default_factory=list)
    min_depth: int = 0
    dev_only: bool = True
    functions: list[dict] = field(default_factory=list)
    routes: list[dict] = field(default_factory=list)
    artifacts: list[dict] = field(default_factory=list)

    @property
    def rank(self) -> int:
        return TIER_ORDER.get(self.tier, 9)


@dataclass
class Assessment:
    advisory_id: str
    package: str
    affected_keys: list[str] = field(default_factory=list)
    findings: list[ServiceFinding] = field(default_factory=list)
    timings_ms: dict[str, float] = field(default_factory=dict)
    max_call_depth: int = MAX_CALL_DEPTH

    @property
    def total_ms(self) -> float:
        return sum(self.timings_ms.values())

    def render(self) -> str:
        if not self.affected_keys:
            return (
                f"{self.advisory_id}: no version of {self.package} in the corpus "
                f"matches this advisory. Nothing exposed."
            )
        lines = [
            f"{self.advisory_id}  --  {self.package}",
            f"affected versions present: {', '.join(self.affected_keys)}",
            "",
        ]
        if not self.findings:
            lines.append("No service depends on an affected version.")
            return "\n".join(lines)

        width = max(len(f.service) for f in self.findings)
        for finding in sorted(self.findings, key=lambda f: (f.rank, f.service)):
            detail = []
            if finding.routes:
                detail.append(f"{len(finding.routes)} route(s)")
            if finding.functions:
                detail.append(f"{len(finding.functions)} function(s)")
            if finding.artifacts:
                detail.append(f"{len(finding.artifacts)} artifact(s)")
            if finding.dev_only:
                detail.append("dev-only")
            detail.append(f"depth {finding.min_depth}")
            lines.append(
                f"  {finding.tier:14} {finding.service:{width}}  {', '.join(detail)}"
            )
            for route in finding.routes[:4]:
                lines.append(
                    f"      {route['method']:6} {route['pattern']}  ->  {route['handler']}"
                )
        lines.append("")
        lines.append(
            f"answered in {self.total_ms:.0f} ms  "
            + "  ".join(f"{k}={v:.0f}ms" for k, v in self.timings_ms.items())
        )
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Q0 -- what versions of this package does the corpus actually hold?
# --------------------------------------------------------------------------


def held_versions(client: HydraClient, package: str) -> list[dict]:
    """Every version of ``package`` present anywhere, with its node id."""
    result = client.query(
        "MATCH (p:PackageVersion) WHERE p.name = $name "
        "RETURN p.id AS id, p.version AS version, p.key AS key ORDER BY version",
        {"name": package},
    )
    return result.rows


# --------------------------------------------------------------------------
# Q1 -- exposed services. The 09:06 answer: one hop over the closure.
# --------------------------------------------------------------------------


def exposed_services(client: HydraClient, package_ids: list[int]) -> list[dict]:
    """Which services contain any of these package versions, and how deep."""
    if not package_ids:
        return []
    result = client.query(
        "UNWIND $rows AS row "
        "MATCH (p:PackageVersion {id: row.id})-[e:PRESENT_IN]->(s:Service) "
        "RETURN s.name AS service, p.key AS package, e.depth AS depth, "
        "e.dev AS dev, e.direct AS direct",
        {"rows": [{"id": i} for i in package_ids]},
    )
    return result.rows


# --------------------------------------------------------------------------
# Q2 -- the dependency chain. Many sources at once, resolved server-side.
# --------------------------------------------------------------------------


def dependency_paths(
    client: HydraClient,
    package_keys: list[str],
    services: list[str],
    max_len: int = 10,
    path_count: int = 3,
) -> list[Any]:
    """Whole paths from compromised packages out to the affected services.

    A plain MATCH returns endpoint projections; these procedures are the only
    way to get the chain itself back. Using the many-source form matters when
    a worm publishes across dozens of packages at once -- it is one call
    resolved inside the engine rather than a client-side fan-out.
    """
    if not package_keys or not services:
        return []
    result = client.query(
        "CALL algo.MSpaths({sourceLabel: 'PackageVersion', sourceProperty: 'key', "
        "sourceValues: $sources, targetLabel: 'Service', targetProperty: 'name', "
        "targetValues: $targets, relTypes: ['REQUIRED_BY'], relDirection: 'outgoing', "
        "maxLen: $maxlen, pathCount: $count}) "
        "YIELD path RETURN path",
        {
            "sources": package_keys,
            "targets": services,
            "maxlen": max_len,
            "count": path_count,
        },
    )
    return result.column("path")


# --------------------------------------------------------------------------
# Q3 -- which functions call into the package (bridge -> micro graph)
# --------------------------------------------------------------------------


def calling_functions(client: HydraClient, package_ids: list[int]) -> list[dict]:
    """Functions whose source calls a symbol imported from the package.

    Walks the bridge backwards using the two materialised inverses:
    PackageVersion -IMPORTED_AS-> ExternalImport -IMPORT_USED_BY-> Function.
    """
    if not package_ids:
        return []
    result = client.query(
        "UNWIND $rows AS row "
        "MATCH (p:PackageVersion {id: row.id})-[:IMPORTED_AS]->(e:ExternalImport)"
        "-[:IMPORT_USED_BY]->(f:Function) "
        "RETURN f.id AS id, f.name AS name, f.file AS file, f.line AS line, "
        "f.service AS service, e.specifier AS specifier",
        {"rows": [{"id": i} for i in package_ids]},
    )
    return result.rows


# --------------------------------------------------------------------------
# Q4 -- reachable entry points. The claim no lockfile scanner can make.
# --------------------------------------------------------------------------


def reachable_routes(
    client: HydraClient,
    function_ids: list[int],
    max_depth: int = MAX_CALL_DEPTH,
) -> list[dict]:
    """HTTP routes that can reach any of these functions.

    Two steps rather than one pattern. A single MATCH mixing a variable-length
    hop with a fixed hop is not something the parser is documented to accept,
    and being wrong here would mean silently reporting zero routes -- the
    failure mode that most flatters the tool. So the call-graph walk and the
    route lookup are separate statements, and both are plain pinned-source
    forward walks over materialised inverses.
    """
    if not function_ids:
        return []

    # Step 1: everything that transitively calls one of these functions. The
    # functions themselves count -- a route handler may call the package
    # directly.
    callers: dict[int, int] = {fid: 0 for fid in function_ids}
    result = client.query(
        "UNWIND $rows AS row "
        f"MATCH (f:Function {{id: row.id}})-[:CALLED_BY*1..{max_depth}]->(c:Function) "
        "RETURN c.id AS id",
        {"rows": [{"id": i} for i in function_ids]},
    )
    for row in result.rows:
        callers.setdefault(row["id"], 1)

    # Step 2: which of those are dispatched to by a route.
    routes = client.query(
        "UNWIND $rows AS row "
        "MATCH (f:Function {id: row.id})-[:HANDLES]->(r:Route) "
        "RETURN r.method AS method, r.pattern AS pattern, r.service AS service, "
        "r.file AS file, r.line AS line, f.name AS handler",
        {"rows": [{"id": i} for i in callers]},
    )
    return routes.rows


# --------------------------------------------------------------------------
# Q5 -- persistence artifacts: exposure vs. evidence
# --------------------------------------------------------------------------


def artifacts_for(client: HydraClient, services: list[str]) -> list[dict]:
    """Worm persistence artifacts found in the given services."""
    if not services:
        return []
    result = client.query(
        "UNWIND $rows AS row "
        "MATCH (s:Service {id: row.id})-[:HAS_ARTIFACT]->(a:PersistenceArtifact) "
        "RETURN s.name AS service, a.path AS path, a.kind AS kind, a.sha256 AS sha256",
        {"rows": [{"id": i} for i in services]},
    )
    return result.rows


def service_ids(client: HydraClient, names: list[str]) -> dict[str, int]:
    """Name -> id for the given services. No `IN`, so this is an UNWIND MATCH."""
    if not names:
        return {}
    result = client.query(
        "MATCH (s:Service) RETURN s.id AS id, s.name AS name",
    )
    wanted = set(names)
    return {r["name"]: r["id"] for r in result.rows if r["name"] in wanted}


# --------------------------------------------------------------------------
# Assessment -- compose the tiers
# --------------------------------------------------------------------------


def assess(client: HydraClient, advisory: Advisory) -> Assessment:
    """Run the full pipeline for one advisory and rank every affected service.

    The tiers exist to separate exposure from evidence and from reachability.
    P3 is not filler: telling a team which of forty alerts they can ignore is
    the thing a flat lockfile scan cannot do, and it is where most of the time
    saved on an incident actually comes from.
    """
    timings: dict[str, float] = {}

    def timed(name, fn, *args, **kwargs):
        import time

        started = time.perf_counter()
        out = fn(*args, **kwargs)
        timings[name] = (time.perf_counter() - started) * 1000
        return out

    versions = timed("held", held_versions, client, advisory.package)
    affected = [v for v in versions if advisory.matches(v["version"])]
    affected_ids = [v["id"] for v in affected]
    affected_keys = [v["key"] for v in affected]

    assessment = Assessment(
        advisory_id=advisory.advisory_id,
        package=advisory.package,
        affected_keys=affected_keys,
    )
    if not affected_ids:
        return assessment

    exposure = timed("exposed", exposed_services, client, affected_ids)
    if not exposure:
        return assessment

    by_service: dict[str, ServiceFinding] = {}
    for row in exposure:
        finding = by_service.setdefault(
            row["service"],
            ServiceFinding(service=row["service"], tier=TIER_INSTALLED, min_depth=99),
        )
        if row["package"] not in finding.packages:
            finding.packages.append(row["package"])
        finding.min_depth = min(finding.min_depth, int(row["depth"] or 99))
        if not row.get("dev"):
            finding.dev_only = False

    # Reachability: which functions call it, and which routes reach them.
    functions = timed("functions", calling_functions, client, affected_ids)
    for fn in functions:
        finding = by_service.get(fn["service"])
        if finding:
            finding.functions.append(fn)
            finding.tier = TIER_IMPORTED

    routes = timed("routes", reachable_routes, client, [f["id"] for f in functions])
    for route in routes:
        finding = by_service.get(route["service"])
        if finding:
            finding.routes.append(route)
            finding.tier = TIER_REACHABLE

    # Evidence outranks everything: an artifact on disk means removing the
    # package does not clear the compromise.
    ids = service_ids(client, list(by_service))
    for artifact in timed("artifacts", artifacts_for, client, list(ids.values())):
        finding = by_service.get(artifact["service"])
        if finding:
            finding.artifacts.append(artifact)
            finding.tier = TIER_CONFIRMED

    assessment.findings = list(by_service.values())
    assessment.timings_ms = timings
    return assessment
