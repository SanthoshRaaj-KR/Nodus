"""Blast-radius queries and the evidence model.

Query shapes are dictated by what HydraDB accepts on the read path, which is
narrower than the write path: reads use a plain ``MATCH`` with a scalar ``$id``
(labels work there, and ``UNWIND ... MATCH ... RETURN`` does not accept them),
there is no ``IN`` so a set membership test becomes one statement per member,
and a variable-length pattern must pin its source and declare a maximum.

The layering is deliberate and is where the speed comes from:

* **L0** resolves a purl to an integer id locally, with no graph hit at all.
* **L1** answers the headline question -- which projects are exposed -- in a
  single hop over the precomputed ``RESOLVED_IN`` closure, whose edge already
  carries depth, the direct dependency the path ran through, and the time
  window. No traversal runs for the summary.
* **L2** runs ``algo.SSpaths`` only for the node a user actually opens, so
  path reconstruction is paid for on demand rather than per query.

The evidence model keeps three claims apart that a naive tool merges:

    REQUIRES      a range names the package                  -> POSSIBLE
    SATISFIED_BY  the range provably admits this version     -> POSSIBLE_EXACT
    RESOLVES      a lockfile actually selected this version  -> CONFIRMED

Merging them is the over-report this design exists to prevent. In the
generated corpus, ``^4.17.21`` and ``^4.17.0`` both admit ``lodash@4.17.21``,
so a range-only tool reports five exposed projects. Exactly one lockfile
resolved it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .. import schema
from ..hydra_client import HydraClient
from ..ids import IdAllocator
from .identity import package_key, version_key

__all__ = [
    "Evidence",
    "Confidence",
    "Finding",
    "BlastRadius",
    "BlastRadiusEngine",
]


class Evidence:
    """Atoms. Each is one graph fact, carrying its own witness."""

    DIRECTLY_COMPROMISED = "DIRECTLY_COMPROMISED"
    RESOLVES_COMPROMISED_VERSION = "RESOLVES_COMPROMISED_VERSION"
    LIVE_WINDOW_OVERLAP = "LIVE_WINDOW_OVERLAP"
    TRANSITIVELY_EXPOSED = "TRANSITIVELY_EXPOSED"
    KNOWN_VULNERABILITY = "KNOWN_VULNERABILITY"
    #: A project resolved the version under review, and nothing marks that
    #: version as compromised or vulnerable. The fact is identical to
    #: RESOLVES_COMPROMISED_VERSION; the claim is not, and the two must not
    #: share an atom -- an atom whose name asserts a compromise cannot be
    #: emitted for a version no incident and no advisory names.
    RESOLVES_SUBJECT_VERSION = "RESOLVES_SUBJECT_VERSION"
    POSSIBLE_EXACT = "POSSIBLE_EXACT"
    POSSIBLE = "POSSIBLE"
    SHARED_MAINTAINER = "SHARED_MAINTAINER"
    SHARED_REPOSITORY = "SHARED_REPOSITORY"
    SHARED_PUBLISHER = "SHARED_PUBLISHER"
    TYPOSQUAT_NEIGHBOR = "TYPOSQUAT_NEIGHBOR"

    #: Atoms that describe a *relationship*, never a compromise. These can
    #: never raise a finding above INVESTIGATE, however many of them fire.
    #: Sharing a maintainer with a victim is a reason to look, not a verdict.
    RELATIONAL = frozenset({
        SHARED_MAINTAINER,
        SHARED_REPOSITORY,
        SHARED_PUBLISHER,
        TYPOSQUAT_NEIGHBOR,
    })


class Confidence:
    CERTAIN = "CERTAIN"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INVESTIGATE = "INVESTIGATE"


def derive_confidence(atoms: set[str]) -> str:
    """Confidence is a function of which atoms fired. Nothing is invented.

    The ordering rule that matters: relational atoms alone never produce more
    than INVESTIGATE. A package that shares a maintainer with a compromised one
    is not thereby compromised, and a tool that says otherwise trains its users
    to ignore it.
    """
    if Evidence.DIRECTLY_COMPROMISED in atoms:
        return Confidence.CERTAIN
    if atoms & {
        Evidence.RESOLVES_COMPROMISED_VERSION,
        Evidence.TRANSITIVELY_EXPOSED,
    }:
        return Confidence.HIGH
    if Evidence.POSSIBLE_EXACT in atoms:
        return Confidence.MEDIUM
    if Evidence.POSSIBLE in atoms:
        return Confidence.LOW
    if Evidence.RESOLVES_SUBJECT_VERSION in atoms:
        # A true statement about an installation, not a finding about a threat.
        return Confidence.LOW
    if atoms & Evidence.RELATIONAL:
        return Confidence.INVESTIGATE
    return Confidence.LOW


@dataclass
class Finding:
    """One entity, why it was flagged, and what we did *not* find."""

    entity: str
    entity_type: str
    status: str
    atoms: set[str] = field(default_factory=set)
    path: list[str] = field(default_factory=list)
    reason: str = ""
    negative_evidence: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def confidence(self) -> str:
        return derive_confidence(self.atoms)

    def explain(self) -> str:
        lines = [
            "WHY FLAGGED?",
            "",
            f"  {self.entity_type}: {self.entity}",
            f"  Status:      {self.status}",
            f"  Confidence:  {self.confidence}",
        ]
        if self.path:
            lines.append("")
            lines.append("  Path:")
            for i, hop in enumerate(self.path):
                lines.append(f"      {'  ' * i}{'-> ' if i else ''}{hop}")
        if self.reason:
            lines.append("")
            lines.append(f"  Reason:      {self.reason}")
        if self.atoms:
            lines.append(f"  Evidence:    {', '.join(sorted(self.atoms))}")
        if self.negative_evidence:
            lines.append("")
            lines.append("  Not found:")
            for item in self.negative_evidence:
                lines.append(f"      - {item}")
        return "\n".join(lines)


@dataclass
class Timing:
    label: str
    ms: float
    rows: int = 0


@dataclass
class BlastRadius:
    """The full answer for one compromised version."""

    target: str
    target_id: int = 0
    exists: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    direct_dependents: list[dict] = field(default_factory=list)

    #: Empty when ``analyse(include_transitive=False)`` skipped Q3. Empty here
    #: means "not asked", not "none found" -- see the flag on analyse().
    transitive_dependents: list[dict] = field(default_factory=list)
    transitive_measured: bool = True
    lockfile_entries: list[dict] = field(default_factory=list)
    exposed_projects: list[dict] = field(default_factory=list)
    live_window_projects: list[dict] = field(default_factory=list)
    shared_maintainer: list[dict] = field(default_factory=list)
    shared_repository: list[dict] = field(default_factory=list)
    shared_publisher: list[dict] = field(default_factory=list)
    typosquats: list[dict] = field(default_factory=list)
    advisories: list[dict] = field(default_factory=list)
    incidents: list[dict] = field(default_factory=list)

    #: Projects a range-only analysis would flag. Kept separately so the
    #: over-report a naive tool produces can be measured, not asserted.
    range_only_projects: list[dict] = field(default_factory=list)

    #: Whole paths from algo.SSpaths, populated only when explicitly asked for.
    paths: list[Any] = field(default_factory=list)

    findings: list[Finding] = field(default_factory=list)
    timings: list[Timing] = field(default_factory=list)

    @property
    def total_ms(self) -> float:
        return sum(t.ms for t in self.timings)

    def timing_table(self) -> str:
        width = max((len(t.label) for t in self.timings), default=10)
        lines = [f"  {'query'.ljust(width)}   {'ms':>8}  {'rows':>6}"]
        for t in self.timings:
            lines.append(f"  {t.label.ljust(width)}   {t.ms:>8.2f}  {t.rows:>6}")
        lines.append(f"  {'TOTAL'.ljust(width)}   {self.total_ms:>8.2f}")
        return "\n".join(lines)


class BlastRadiusEngine:
    """Runs the blast-radius queries against HydraDB."""

    #: Bound on the reverse dependency walk. Required -- HydraDB rejects an
    #: unbounded variable-length pattern -- and reported in the result, so a
    #: truncated answer is never mistaken for a complete one.
    MAX_REVERSE_DEPTH = 5

    def __init__(
        self,
        client: HydraClient,
        ids: IdAllocator,
        max_depth: int | None = None,
    ):
        self.client = client
        self.ids = ids
        self.max_depth = max_depth or self.MAX_REVERSE_DEPTH

    # -- L0: local id resolution, no graph hit ----------------------------

    def resolve(self, name: str, version: str) -> int | None:
        """purl -> integer id, from the local allocator. No round trip."""
        return self.ids.lookup(schema.PACKAGE_VERSION, version_key(name, version))

    def resolve_package(self, name: str) -> int | None:
        return self.ids.lookup(schema.PACKAGE, package_key(name))

    # -- helpers -----------------------------------------------------------

    def _timed(self, result: BlastRadius, label: str, statement: str, **params):
        started = time.perf_counter()
        rows = self.client.query(statement, params or None)
        elapsed = (time.perf_counter() - started) * 1000
        result.timings.append(Timing(label, elapsed, len(rows)))
        return rows

    # -- Q1 ----------------------------------------------------------------

    def package_version(self, result: BlastRadius, version_id: int) -> dict:
        rows = self._timed(
            result, "Q1 exact lookup",
            "MATCH (p:PackageVersion {id: $id}) "
            "RETURN p.key AS key, p.name AS name, p.version AS version, "
            "p.published_at AS published_at, p.license AS license, "
            "p.deprecated AS deprecated, "
            "p.has_install_script AS has_install_script, "
            "p.integrity AS integrity",
            id=version_id,
        )
        return dict(rows.rows[0]) if len(rows) else {}

    # -- Q2 ----------------------------------------------------------------

    def direct_dependents(self, result: BlastRadius, version_id: int) -> list[dict]:
        """Package versions whose declared range provably admits this version.

        One hop over SATISFIES, the materialised inverse of SATISFIED_BY.
        These are candidates, not confirmed exposure: a range admitting a
        version says nothing about what any lockfile actually chose.
        """
        rows = self._timed(
            result, "Q2 direct dependents",
            "MATCH (v:PackageVersion {id: $id})-[e:SATISFIES]->(d:PackageVersion) "
            "RETURN d.id AS id, d.key AS key, d.name AS name, "
            "d.version AS version, e.range AS range, e.dep_type AS dep_type "
            "ORDER BY key",
            id=version_id,
        )
        return [dict(r) for r in rows]

    # -- Q3 ----------------------------------------------------------------

    def transitive_dependents(
        self, result: BlastRadius, version_id: int
    ) -> list[dict]:
        """Everything reachable backwards within the depth bound.

        The bound is not a tuning choice -- HydraDB rejects `*` and `*1..` on
        principle, because an unbounded traversal has no predictable cost. The
        depth used is returned alongside the rows.
        """
        rows = self._timed(
            result, f"Q3 transitive (<={self.max_depth})",
            f"MATCH (v:PackageVersion {{id: $id}})-[:SATISFIES*1..{self.max_depth}]->"
            "(d:PackageVersion) "
            "RETURN DISTINCT d.id AS id, d.key AS key, d.name AS name, "
            "d.version AS version ORDER BY key",
            id=version_id,
        )
        return [dict(r) for r in rows]

    # -- Q4 ----------------------------------------------------------------

    def lockfile_entries(self, result: BlastRadius, version_id: int) -> list[dict]:
        """Lockfile entries that resolved exactly this version. Ground truth."""
        rows = self._timed(
            result, "Q4 lockfile entries",
            "MATCH (e:LockfileEntry)-[:RESOLVES_VERSION]->(v:PackageVersion {id: $id}) "
            "RETURN e.id AS id, e.package_name AS package_name, "
            "e.resolved_version AS resolved_version, e.dev AS dev, "
            "e.depth AS depth, e.integrity AS integrity ORDER BY id",
            id=version_id,
        )
        return [dict(r) for r in rows]

    # -- Q5: the headline, one hop ----------------------------------------

    def exposed_projects(self, result: BlastRadius, version_id: int) -> list[dict]:
        """Projects that resolved this version, with depth and witness.

        A single hop over the flattened closure. Everything needed to explain
        the finding is already on the edge, so this is one round trip and it is
        exact at any tree depth -- unlike a bounded walk, which would silently
        under-report the deep transitive cases that matter most.
        """
        rows = self._timed(
            result, "Q5 exposed projects",
            "MATCH (v:PackageVersion {id: $id})-[e:RESOLVED_IN]->(s:Service) "
            "RETURN s.id AS id, s.name AS service, e.depth AS depth, "
            "e.via_direct AS via_direct, e.dev_only AS dev_only, "
            "e.first_seen AS first_seen, e.last_seen AS last_seen "
            "ORDER BY depth, service",
            id=version_id,
        )
        return [dict(r) for r in rows]

    # -- Q8: the same, restricted to the live window ----------------------

    def exposed_during_window(
        self, result: BlastRadius, version_id: int, live_from: int, live_until: int
    ) -> list[dict]:
        """Projects whose resolution overlapped the window the version was live.

        The only semantic predicate that runs *inside* HydraDB. Everything else
        -- semver, string distance -- has to be precomputed, but epoch-second
        integers compare with the operators the subset does support, so the
        interval overlap is a real WHERE clause.
        """
        rows = self._timed(
            result, "Q8 live-window exposure",
            "MATCH (v:PackageVersion {id: $id})-[e:RESOLVED_IN]->(s:Service) "
            "WHERE e.first_seen <= $until AND e.last_seen >= $since "
            "RETURN s.name AS service, e.depth AS depth, "
            "e.via_direct AS via_direct, e.first_seen AS first_seen, "
            "e.last_seen AS last_seen ORDER BY service",
            id=version_id, since=live_from, until=live_until,
        )
        return [dict(r) for r in rows]

    # -- Q6: relationship signals -----------------------------------------

    def shared_maintainer(
        self, result: BlastRadius, package_id: int
    ) -> list[dict]:
        """Other packages published by the same accounts.

        Two hops, each pinned, because a single pattern cannot carry two
        relationship types. The result is explicitly *not* a compromise claim.
        """
        maintainers = self._timed(
            result, "Q6a maintainers",
            "MATCH (p:Package {id: $id})-[:MAINTAINED_BY]->(m:Maintainer) "
            "RETURN m.id AS id, m.username AS username ORDER BY username",
            id=package_id,
        )
        out: list[dict] = []
        for row in maintainers:
            siblings = self._timed(
                result, f"Q6b via {row['username']}",
                "MATCH (p:Package)-[:MAINTAINED_BY]->(m:Maintainer {id: $id}) "
                "RETURN p.id AS id, p.name AS name ORDER BY name",
                id=row["id"],
            )
            for sibling in siblings:
                if sibling["id"] == package_id:
                    continue
                out.append({
                    "package": sibling["name"],
                    "package_id": sibling["id"],
                    "maintainer": row["username"],
                })
        return out

    def shared_repository(self, result: BlastRadius, version_id: int) -> list[dict]:
        """Packages built from the same repository.

        Distinct from shared maintainer, and often the stronger signal: a
        breached CI pipeline publishes everything built out of that repo,
        regardless of which account is nominally the maintainer.
        """
        repos = self._timed(
            result, "Q6c repository",
            "MATCH (v:PackageVersion {id: $id})-[:SOURCED_FROM]->(r:Repository) "
            "RETURN r.id AS id, r.url AS url ORDER BY url",
            id=version_id,
        )
        out: list[dict] = []
        for row in repos:
            siblings = self._timed(
                result, "Q6d repo siblings",
                "MATCH (v:PackageVersion)-[:SOURCED_FROM]->(r:Repository {id: $id}) "
                "RETURN DISTINCT v.name AS name ORDER BY name",
                id=row["id"],
            )
            for sibling in siblings:
                out.append({"package": sibling["name"], "repository": row["url"]})
        return out

    def shared_publisher(self, result: BlastRadius, version_id: int) -> list[dict]:
        """Versions published by the same account.

        The account that published a specific artifact is often not the listed
        maintainer -- lodash lists jdalton, but 4.17.21 was published by
        bnjmnt4n. In a credential compromise it is the publishing account that
        matters, which is why this is a separate relationship.
        """
        publishers = self._timed(
            result, "Q6e publisher",
            "MATCH (v:PackageVersion {id: $id})-[:PUBLISHED_BY]->(p:PublisherIdentity) "
            "RETURN p.id AS id, p.username AS username ORDER BY username",
            id=version_id,
        )
        out: list[dict] = []
        for row in publishers:
            siblings = self._timed(
                result, "Q6f publisher siblings",
                "MATCH (v:PackageVersion)-[:PUBLISHED_BY]->(p:PublisherIdentity {id: $id}) "
                "RETURN DISTINCT v.name AS name, v.version AS version ORDER BY name",
                id=row["id"],
            )
            for sibling in siblings:
                out.append({
                    "package": sibling["name"],
                    "version": sibling["version"],
                    "publisher": row["username"],
                })
        return out

    def typosquats(self, result: BlastRadius, package_id: int) -> list[dict]:
        rows = self._timed(
            result, "Q6g typosquats",
            "MATCH (o:Package)-[e:TYPOSQUAT_OF]->(p:Package {id: $id}) "
            "RETURN o.name AS name, e.distance AS distance, "
            "e.technique AS technique, e.popularity_ratio AS ratio "
            "ORDER BY distance, name",
            id=package_id,
        )
        return [dict(r) for r in rows]

    # -- security state ----------------------------------------------------

    def incidents_for(self, result: BlastRadius, version_id: int) -> list[dict]:
        rows = self._timed(
            result, "incidents",
            "MATCH (i:Incident)-[:COMPROMISES]->(v:PackageVersion {id: $id}) "
            "RETURN i.incident_id AS incident_id, i.status AS status, "
            "i.summary AS summary, i.live_from AS live_from, "
            "i.live_until AS live_until",
            id=version_id,
        )
        return [dict(r) for r in rows]

    def advisories_for(self, result: BlastRadius, version_id: int) -> list[dict]:
        rows = self._timed(
            result, "advisories",
            "MATCH (a:Advisory)-[e:AFFECTS]->(v:PackageVersion {id: $id}) "
            "RETURN a.advisory_id AS advisory_id, a.summary AS summary, "
            "a.cvss_vector AS cvss_vector, a.severity_score AS severity_score, "
            "a.severity AS severity, "
            "e.fixed_version AS fixed_version",
            id=version_id,
        )
        return [dict(r) for r in rows]

    # -- Q7: paths, on demand ---------------------------------------------

    def paths_to_projects(
        self, result: BlastRadius, version_id: int, limit: int = 25
    ) -> list[Any]:
        """Whole paths, for explaining one finding.

        A plain MATCH returns endpoint projections; the path procedures are the
        only way to get the chain itself, which is what an explanation needs.
        Run lazily, never as part of the summary.
        """
        rows = self._timed(
            result, "Q7 paths",
            "CALL algo.SSpaths({sourceNode: $id, "
            f"relTypes: ['{schema.SATISFIES}', '{schema.RESOLVED_IN}'], "
            f"maxLen: {self.max_depth}, relDirection: 'outgoing', "
            f"pathCount: {limit}}}) YIELD path RETURN path",
            id=version_id,
        )
        return [r.get("path") for r in rows]

    # -- the whole answer --------------------------------------------------

    def analyse(
        self,
        name: str,
        version: str,
        include_paths: bool = False,
        include_transitive: bool = True,
    ) -> BlastRadius:
        """Everything, for one compromised version.

        ``include_transitive`` covers Q3 alone -- the bounded reverse walk that
        lists every version transitively admitting this one. It is the most
        expensive query here (~110 ms against ~3 ms for the exposure answer)
        and nothing downstream of it changes a verdict, so an interactive
        caller redrawing on every click turns it off. When it is off the field
        stays empty and callers must not read the empty list as a measured
        zero.
        """
        target = f"{name}@{version}"
        result = BlastRadius(target=target)

        version_id = self.resolve(name, version)
        if version_id is None:
            return result
        result.target_id = version_id

        result.transitive_measured = include_transitive
        result.metadata = self.package_version(result, version_id)
        result.exists = bool(result.metadata)
        if not result.exists:
            return result

        result.incidents = self.incidents_for(result, version_id)
        result.advisories = self.advisories_for(result, version_id)

        result.direct_dependents = self.direct_dependents(result, version_id)
        if include_transitive:
            result.transitive_dependents = self.transitive_dependents(
                result, version_id
            )
        result.lockfile_entries = self.lockfile_entries(result, version_id)
        result.exposed_projects = self.exposed_projects(result, version_id)

        package_id = self.resolve_package(name)
        if package_id is not None:
            result.shared_maintainer = self.shared_maintainer(result, package_id)
            result.typosquats = self.typosquats(result, package_id)
        result.shared_repository = self.shared_repository(result, version_id)
        result.shared_publisher = self.shared_publisher(result, version_id)

        for incident in result.incidents:
            live_from = incident.get("live_from") or schema.UNKNOWN_TS
            live_until = incident.get("live_until") or schema.STILL_LIVE
            result.live_window_projects = self.exposed_during_window(
                result, version_id, live_from, live_until
            )
            break

        if include_paths:
            try:
                result.paths = self.paths_to_projects(result, version_id)
            except Exception as exc:  # noqa: BLE001 - procedure support varies
                result.timings.append(Timing(f"Q7 paths unavailable: {exc}", 0.0))

        result.findings = self._build_findings(result)
        return result

    # -- explainability ----------------------------------------------------

    def _build_findings(self, result: BlastRadius) -> list[Finding]:
        """Turn graph facts into findings. Deterministic; nothing generated."""
        findings: list[Finding] = []
        compromised = bool(result.incidents)
        incident_id = (
            result.incidents[0].get("incident_id") if result.incidents else ""
        )

        if compromised:
            findings.append(Finding(
                entity=result.target,
                entity_type="PackageVersion",
                status="DIRECTLY_COMPROMISED",
                atoms={Evidence.DIRECTLY_COMPROMISED},
                reason=f"named by incident {incident_id}",
                detail=result.metadata,
            ))
        if result.advisories:
            findings.append(Finding(
                entity=result.target,
                entity_type="PackageVersion",
                status="VULNERABLE",
                atoms={Evidence.KNOWN_VULNERABILITY},
                reason="; ".join(
                    a.get("advisory_id", "") for a in result.advisories[:3]
                ),
                negative_evidence=(
                    [] if compromised else
                    ["not named by any supply-chain incident"]
                ),
                detail={"advisories": result.advisories},
            ))

        live = {p["service"] for p in result.live_window_projects}
        # Exposure needs something to be exposed *to*. With no incident and no
        # advisory, "this project resolves this version" is a true statement
        # about an installation and nothing more; calling it exposure would
        # paint every project in the corpus red the moment anyone looked up a
        # perfectly healthy package.
        flagged = compromised or bool(result.advisories)

        for project in result.exposed_projects:
            direct = project.get("depth", 0) == schema.DIRECT_DEPTH
            if flagged:
                atoms = {Evidence.RESOLVES_COMPROMISED_VERSION}
                if not direct:
                    atoms.add(Evidence.TRANSITIVELY_EXPOSED)
            else:
                atoms = {Evidence.RESOLVES_SUBJECT_VERSION}
            if flagged and project["service"] in live:
                atoms.add(Evidence.LIVE_WINDOW_OVERLAP)

            via = project.get("via_direct", "")
            path = [project["service"]]
            if not direct and via:
                path.append(via)
            path.append(result.target)

            negatives = []
            if project.get("dev_only"):
                negatives.append(
                    "reached only through a devDependency, so not in a "
                    "production install"
                )
            if project["service"] not in live and result.live_window_projects:
                negatives.append(
                    "resolution window does not overlap the incident window"
                )

            if flagged:
                status = "DIRECTLY_EXPOSED" if direct else "TRANSITIVELY_EXPOSED"
            else:
                status = "RESOLVES_VERSION"
            findings.append(Finding(
                entity=project["service"],
                entity_type="Project",
                status=status,
                atoms=atoms,
                path=path,
                reason=(
                    f"its lockfile resolves {result.target}"
                    + (f" at depth {project['depth']} via {via}" if not direct else "")
                ),
                negative_evidence=negatives,
                detail=project,
            ))

        # Relationship signals. Deliberately assembled after the exposure
        # findings and never merged with them.
        for row in result.shared_maintainer:
            findings.append(Finding(
                entity=row["package"],
                entity_type="Package",
                status="RELATED / INVESTIGATE",
                atoms={Evidence.SHARED_MAINTAINER},
                path=[row["package"], f"maintainer {row['maintainer']}", result.target],
                reason=(
                    f"shares maintainer {row['maintainer']} with the "
                    f"compromised package"
                ),
                negative_evidence=[
                    "not itself named by the incident",
                    "does not resolve a compromised version in any lockfile",
                    "no independent evidence of compromise",
                ],
                detail=row,
            ))

        for row in result.typosquats:
            findings.append(Finding(
                entity=row["name"],
                entity_type="Package",
                status="RELATED / INVESTIGATE",
                atoms={Evidence.TYPOSQUAT_NEIGHBOR},
                reason=(
                    f"name resembles the compromised package "
                    f"({row['technique']}, distance {row['distance']})"
                ),
                negative_evidence=[
                    "name similarity only; no compromise evidence",
                ],
                detail=row,
            ))

        return findings
