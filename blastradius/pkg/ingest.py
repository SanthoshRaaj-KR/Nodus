"""Ingest: lockfiles + registry + advisories -> the package graph.

The pipeline is fetch, normalise, deduplicate, stage, write, and it is safe to
re-run: ids are a persisted function of a natural key, so a second pass MERGEs
the same rows rather than duplicating them.

Three decisions here shape everything the query side can do.

**Which versions get a node.** The registry holds 117 versions of lodash alone;
materialising every version of every package, and then every ``SATISFIED_BY``
edge into them, is the graph explosion the design exists to avoid. So a version
gets a node when it is *interesting*: it was resolved by some lockfile, it is
named by an advisory or incident, or it is among the newest few of its package.
The cap is recorded in the report, because a bounded graph that says so is
honest and a bounded graph that stays quiet is a lie.

**Depth is computed, not read off the path.** npm hoists, so a package sitting
at top-level ``node_modules/lodash`` may still be nobody's direct dependency --
in this corpus ``cli-tool`` has exactly that, with lodash hoisted to the root
but required only by ``inquirer``. Depth therefore comes from walking the
declared dependency relations from the project's own manifest outward, never
from counting path segments.

**The closure is flattened at ingest.** A variable-length traversal in HydraDB
must declare a maximum depth, and real npm trees run deeper than any bound
worth hardcoding, so a bounded walk would silently under-report. Computing the
transitive closure here makes the exposure query exact at any depth *and* a
single hop.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .. import schema
from ..hydra_client import HydraClient
from ..ids import IdAllocator
from ..ingest.lockfile import ParsedLock, find_lockfiles, parse_package_lock
from . import semver
from .identity import (
    InvalidPackageName,
    maintainer_key,
    normalize_name,
    normalize_repo_url,
    organization_key,
    package_key,
    split_scope,
    version_key,
)
from .osv import Advisory, OsvScan, load_osv_csv
from .registry import PackumentSummary, RegistryClient
from .typosquat import TyposquatIndex
from .writer import PackageGraphWriter, WriteReport

__all__ = ["IngestConfig", "IngestReport", "ingest"]


@dataclass
class IngestConfig:
    """Knobs that bound the graph. Every one of them shows up in the report."""

    #: Newest N versions of each package to materialise beyond the interesting
    #: ones. 0 keeps the graph to exactly what the fleet and the advisories
    #: touch; raising it widens the "who could be affected" tier.
    versions_per_package: int = 3
    #: Ceiling on SATISFIED_BY edges emitted per REQUIRES edge. A floating
    #: range like ^4 can admit eighty versions; the newest few plus anything an
    #: advisory names are the ones anyone ever queries.
    max_satisfied_by: int = 8
    #: Fetch full packuments (maintainers, repository, publisher, publish
    #: times). The abbreviated document is 3-4x smaller but carries none of it.
    fetch_full_metadata: bool = True
    #: Build the typosquat neighbourhood. Needs download counts.
    detect_typosquats: bool = True
    #: Popular names the typosquat index compares against.
    typosquat_targets: int = 300
    source_registry: str = "npm-registry"
    source_lockfile: str = "package-lock.json"
    source_manifest: str = "package.json"
    source_osv: str = "osv-csv"
    source_derived: str = "derived"


@dataclass
class IngestReport:
    projects: list[str] = field(default_factory=list)
    lockfiles: int = 0
    lock_entries: int = 0
    packages: int = 0
    versions: int = 0
    requires_edges: int = 0
    satisfied_by_edges: int = 0
    closure_edges: int = 0
    maintainers: int = 0
    repositories: int = 0
    typosquat_edges: int = 0
    advisories: int = 0
    unresolved: set[str] = field(default_factory=set)
    registry_errors: list[str] = field(default_factory=list)
    write: WriteReport | None = None
    elapsed_s: float = 0.0
    config: IngestConfig | None = None

    def render(self) -> str:
        lines = [
            f"projects        {len(self.projects)}",
            f"lockfiles       {self.lockfiles}",
            f"lock entries    {self.lock_entries:,}",
            f"packages        {self.packages:,}",
            f"versions        {self.versions:,}",
            f"REQUIRES        {self.requires_edges:,}",
            f"SATISFIED_BY    {self.satisfied_by_edges:,}",
            f"closure         {self.closure_edges:,}",
            f"maintainers     {self.maintainers:,}",
            f"repositories    {self.repositories:,}",
            f"typosquat       {self.typosquat_edges:,}",
            f"advisories      {self.advisories:,}",
        ]
        if self.unresolved:
            lines.append(f"unresolved deps {len(self.unresolved)}")
        if self.registry_errors:
            lines.append(f"registry errors {len(self.registry_errors)}")
        if self.config:
            lines.append("")
            lines.append(
                f"bounds: newest {self.config.versions_per_package} version(s) per "
                f"package, <= {self.config.max_satisfied_by} SATISFIED_BY per "
                f"requirement"
            )
        lines.append(f"\ningest took {self.elapsed_s:.1f}s")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Closure
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Exposure:
    """One package version reachable from one project, with its witness."""

    package_version: str   # "name@version"
    depth: int
    via_direct: str        # the direct dependency the path started from
    dev_only: bool


def compute_closure(lock: ParsedLock, service: str) -> dict[str, Exposure]:
    """Flatten the dependency tree to (version -> shortest path witness).

    Breadth-first from the project's own declared dependencies, so the first
    time a version is reached is by a shortest path and the depth is minimal.
    ``via_direct`` is carried down from the depth-1 ancestor, which is what
    turns "you are exposed" into "you are exposed *through express*" without a
    second query.

    A version reachable both through a dev-only path and a production path is
    recorded as production: the stronger claim wins, because telling someone a
    production exposure is dev-only is the dangerous direction to be wrong in.
    """
    children: dict[str, list[str]] = {}
    for parent, child in lock.edges:
        children.setdefault(parent, []).append(child)

    seen: dict[str, Exposure] = {}
    queue: deque[Exposure] = deque()

    for svc, key, dev in lock.direct:
        if svc != service:
            continue
        exposure = Exposure(key, schema.DIRECT_DEPTH, key, dev)
        previous = seen.get(key)
        if previous is None or (previous.dev_only and not dev):
            seen[key] = exposure
            queue.append(exposure)

    while queue:
        current = queue.popleft()
        for child in children.get(current.package_version, ()):
            candidate = Exposure(
                child, current.depth + 1, current.via_direct, current.dev_only
            )
            previous = seen.get(child)
            if previous is None:
                seen[child] = candidate
                queue.append(candidate)
            elif previous.dev_only and not candidate.dev_only:
                # Same node, but now reachable without dev. Upgrade and
                # re-expand so the correction propagates to its subtree.
                seen[child] = Exposure(
                    child, previous.depth, previous.via_direct, False
                )
                queue.append(seen[child])
    return seen


# --------------------------------------------------------------------------
# The pipeline
# --------------------------------------------------------------------------

def ingest(
    client: HydraClient,
    ids: IdAllocator,
    corpus: Path | str,
    osv_csv: Path | str | None = None,
    registry: RegistryClient | None = None,
    config: IngestConfig | None = None,
    verbose: bool = True,
) -> IngestReport:
    """Run the whole pipeline into HydraDB."""
    started = time.perf_counter()
    config = config or IngestConfig()
    registry = registry or RegistryClient()
    report = IngestReport(config=config)
    writer = PackageGraphWriter(client, ids, verbose=False)

    def log(message: str) -> None:
        if verbose:
            print(message, flush=True)

    # -- 1. lockfiles ------------------------------------------------------

    lock_paths = find_lockfiles(corpus)
    if not lock_paths:
        raise FileNotFoundError(f"no package-lock.json found under {corpus}")
    log(f"[1/7] parsing {len(lock_paths)} lockfile(s)")

    locks: list[ParsedLock] = []
    for path in lock_paths:
        try:
            locks.append(parse_package_lock(path))
        except Exception as exc:  # noqa: BLE001 - a bad lockfile is data, not a bug
            log(f"      skipped {path}: {exc}")
    report.lockfiles = len(locks)

    #: Every name@version any lockfile resolved. These always get a node: they
    #: are ground truth about what is actually installed.
    resolved: dict[str, tuple[str, str]] = {}
    for lock in locks:
        for key, entry in lock.packages.items():
            resolved[key] = (entry.name, entry.version)
        report.unresolved |= lock.unresolved
    report.lock_entries = sum(len(l.packages) for l in locks)
    log(f"      {report.lock_entries:,} entries, {len(resolved):,} distinct versions")

    # -- 2. advisories -----------------------------------------------------

    scan: OsvScan | None = None
    advisory_versions: set[tuple[str, str]] = set()
    if osv_csv:
        scan = load_osv_csv(osv_csv)
        log(f"[2/7] advisories: {scan.summary()}")
        for advisory in scan.advisories.values():
            for name, version in advisory.affected:
                advisory_versions.add((name, version))
    else:
        log("[2/7] advisories: none supplied")

    # -- 3. registry -------------------------------------------------------

    package_names = sorted({name for name, _ in resolved.values()})
    log(f"[3/7] registry: {len(package_names):,} packages "
        f"({'full' if config.fetch_full_metadata else 'abbreviated'})")

    def on_error(name: str, exc: Exception) -> None:
        report.registry_errors.append(f"{name}: {exc}")

    packuments = registry.packuments(
        package_names, full=config.fetch_full_metadata, on_error=on_error
    )
    log(f"      {registry.render_stats()}")

    # -- 4. decide which versions get a node -------------------------------
    # A version is materialised when it is resolved by a lockfile, named by an
    # advisory, or among the newest few of its package. Anything else would
    # inflate the graph without answering a question anyone asks.

    materialised: dict[str, set[str]] = {}
    for name, version in resolved.values():
        materialised.setdefault(name, set()).add(version)
    for name, version in advisory_versions:
        try:
            materialised.setdefault(normalize_name(name), set()).add(version)
        except InvalidPackageName:
            continue
    if config.versions_per_package:
        for name, packument in packuments.items():
            parsed = sorted(
                (v for v in (semver.try_parse(x) for x in packument.versions) if v),
                reverse=True,
            )
            newest = [str(v) for v in parsed[: config.versions_per_package]]
            materialised.setdefault(name, set()).update(newest)

    report.packages = len(materialised)
    report.versions = sum(len(v) for v in materialised.values())
    log(f"[4/7] materialising {report.versions:,} versions of "
        f"{report.packages:,} packages")

    # -- 5. stage the ecosystem tier ---------------------------------------

    now = int(time.time())
    package_ids: dict[str, int] = {}
    version_ids: dict[tuple[str, str], int] = {}
    maintainer_ids: dict[str, int] = {}
    repository_ids: dict[str, int] = {}
    org_ids: dict[str, int] = {}
    publisher_ids: dict[str, int] = {}

    for name, versions in materialised.items():
        packument = packuments.get(name)
        scope, _ = split_scope(name)
        pkg_id = writer.node(
            schema.PACKAGE,
            package_key(name),
            name=name,
            scope=scope or "",
            latest_version=(packument.latest if packument else ""),
            version_count=(packument.version_count if packument else len(versions)),
            deprecated=(packument.deprecated if packument else False),
            source=config.source_registry,
            ingested_at=now,
        )
        package_ids[name] = pkg_id

        # Organisation from the npm scope. A scope is an account boundary, so
        # a stolen scope token reaches every package inside it.
        if scope:
            org = organization_key(scope)
            if org not in org_ids:
                org_ids[org] = writer.node(
                    schema.ORGANIZATION, org, name=scope.lstrip("@"),
                    kind="npm-scope", source=config.source_registry, ingested_at=now,
                )
            writer.edge(schema.OWNED_BY, pkg_id, org_ids[org],
                        source=config.source_registry)

        # Maintainers attach to the package, not the version: publish rights
        # are held over the name.
        if packument:
            for username, email in packument.maintainers:
                key = maintainer_key(username, email)
                if not key:
                    continue
                if key not in maintainer_ids:
                    maintainer_ids[key] = writer.node(
                        schema.MAINTAINER, key, username=username, email=email,
                        source=config.source_registry, ingested_at=now,
                    )
                writer.edge(schema.MAINTAINED_BY, pkg_id, maintainer_ids[key],
                            source=config.source_registry)

        for version in sorted(versions):
            summary = packument.versions.get(version) if packument else None
            ver_id = writer.node(
                schema.PACKAGE_VERSION,
                version_key(name, version),
                name=name,
                version=version,
                integrity=(summary.integrity if summary else ""),
                published_at=(summary.published_at if summary else schema.UNKNOWN_TS),
                license=(summary.license if summary else ""),
                description=(summary.description if summary else ""),
                deprecated=(summary.deprecated if summary else False),
                has_install_script=(summary.has_install_script if summary else False),
                source=config.source_registry,
                ingested_at=now,
            )
            version_ids[(name, version)] = ver_id
            writer.edge(schema.HAS_VERSION, pkg_id, ver_id,
                        source=config.source_registry)

            if summary:
                repo = normalize_repo_url(summary.repository or (
                    packument.repository if packument else ""
                ))
                if repo:
                    if repo.key not in repository_ids:
                        repository_ids[repo.key] = writer.node(
                            schema.REPOSITORY, repo.key, host=repo.host,
                            owner=repo.owner, name=repo.name, url=repo.url,
                            source=config.source_registry, ingested_at=now,
                        )
                    writer.edge(schema.SOURCED_FROM, ver_id,
                                repository_ids[repo.key],
                                source=config.source_registry)
                if summary.publisher:
                    key = maintainer_key(summary.publisher, summary.publisher_email)
                    if key:
                        if key not in publisher_ids:
                            publisher_ids[key] = writer.node(
                                schema.PUBLISHER, key, username=summary.publisher,
                                email=summary.publisher_email,
                                source=config.source_registry, ingested_at=now,
                            )
                        writer.edge(schema.PUBLISHED_BY, ver_id,
                                    publisher_ids[key],
                                    source=config.source_registry)

    report.maintainers = len(maintainer_ids)
    report.repositories = len(repository_ids)

    # -- 6. REQUIRES and SATISFIED_BY --------------------------------------
    # REQUIRES points at the Package and carries the declared range. It says
    # only that a dependency exists. SATISFIED_BY names the exact versions that
    # range admits, evaluated here because Cypher cannot do it. The two are
    # never collapsed: a range naming a package is not exposure, and treating
    # it as such is the over-report this whole design is built to prevent.

    for (name, version), ver_id in list(version_ids.items()):
        packument = packuments.get(name)
        summary = packument.versions.get(version) if packument else None
        if not summary:
            continue
        for dep_name, dep_range, dep_type, optional, peer, bundled in summary.dependencies:
            try:
                dep_norm = normalize_name(dep_name)
            except InvalidPackageName:
                continue
            dep_pkg_id = package_ids.get(dep_norm)
            if dep_pkg_id is None:
                continue  # outside the materialised universe

            writer.edge(
                schema.REQUIRES, ver_id, dep_pkg_id,
                range=dep_range, dep_type=dep_type, optional=optional,
                peer=peer, bundled=bundled, source=config.source_manifest,
            )
            report.requires_edges += 1

            # Expand the range against the versions we hold.
            candidates = materialised.get(dep_norm, set())
            try:
                admitted = semver.filter_satisfying(candidates, dep_range)
            except semver.InvalidRange:
                # git:, file:, workspace: and friends are not semver at all.
                # Refusing beats guessing '*', which would attach every version.
                continue
            if not admitted:
                continue
            # Newest first, but never drop a version an advisory names -- those
            # are precisely the ones a blast-radius query asks about.
            ordered = sorted(admitted, reverse=True)
            keep = ordered[: config.max_satisfied_by]
            for candidate in ordered[config.max_satisfied_by :]:
                if (dep_norm, str(candidate)) in advisory_versions:
                    keep.append(candidate)
            for candidate in keep:
                target = version_ids.get((dep_norm, str(candidate)))
                if target is None:
                    continue
                writer.edge(
                    schema.SATISFIED_BY, ver_id, target,
                    range=dep_range, dep_type=dep_type,
                    source=config.source_derived,
                )
                report.satisfied_by_edges += 1

    log(f"[5/7] {report.requires_edges:,} REQUIRES, "
        f"{report.satisfied_by_edges:,} SATISFIED_BY")

    # -- 7. projects, lockfiles, entries, closure --------------------------

    for lock in locks:
        lock_file = Path(lock.lock_path)
        observed = int(lock_file.stat().st_mtime) if lock_file.exists() else schema.UNKNOWN_TS

        for rel_path, service in lock.services.items():
            svc_id = writer.node(
                schema.SERVICE, f"svc:{service}", name=service,
                repo=lock.repo, path=rel_path or ".",
            )
            report.projects.append(service)

            lf_key = f"lock:{service}:{rel_path or '.'}"
            lf_id = writer.node(
                schema.LOCKFILE, lf_key, path=str(lock.lock_path), service=service,
                lockfile_version=lock.lock_version, observed_at=observed,
                entry_count=len(lock.packages),
                source=config.source_lockfile, ingested_at=now,
            )
            writer.edge(schema.HAS_LOCKFILE, svc_id, lf_id,
                        source=config.source_lockfile)

            closure = compute_closure(lock, service)

            for key, exposure in closure.items():
                entry = lock.packages.get(key)
                if entry is None:
                    continue
                try:
                    name = normalize_name(entry.name)
                except InvalidPackageName:
                    continue
                ver_id = version_ids.get((name, entry.version))
                if ver_id is None:
                    # Resolved but not materialised should not happen; if it
                    # does, add it rather than silently losing an exposure.
                    ver_id = writer.node(
                        schema.PACKAGE_VERSION, version_key(name, entry.version),
                        name=name, version=entry.version,
                        source=config.source_lockfile, ingested_at=now,
                    )
                    version_ids[(name, entry.version)] = ver_id

                entry_key = f"entry:{service}:{key}"
                entry_id = writer.node(
                    schema.LOCKFILE_ENTRY, entry_key,
                    path=entry.resolved or "", package_name=name,
                    resolved_version=entry.version,
                    resolved_url=entry.resolved or "",
                    integrity=entry.integrity or "",
                    dev=entry.dev, depth=exposure.depth,
                    source=config.source_lockfile, ingested_at=now,
                )
                writer.edge(schema.HAS_ENTRY, lf_id, entry_id,
                            source=config.source_lockfile)
                writer.edge(schema.RESOLVES_VERSION, entry_id, ver_id,
                            source=config.source_lockfile)

                # The one-hop closure edge. Everything the headline exposure
                # query needs is on this edge, so the answer is a single hop
                # with its own witness attached.
                writer.edge(
                    schema.RESOLVED_IN, ver_id, svc_id,
                    depth=exposure.depth,
                    via_direct=exposure.via_direct,
                    dev_only=exposure.dev_only,
                    first_seen=observed,
                    last_seen=schema.STILL_LIVE,
                    source=config.source_derived,
                )
                report.closure_edges += 1

    log(f"[6/7] {len(report.projects)} project(s), "
        f"{report.closure_edges:,} closure edges")

    # -- 8. advisories into the graph --------------------------------------

    if scan:
        for advisory in scan.advisories.values():
            adv_id = writer.node(
                schema.ADVISORY, advisory.advisory_id,
                advisory_id=advisory.advisory_id,
                aliases=sorted(advisory.aliases),
                summary=advisory.summary[:200],
                cvss_vector=advisory.cvss_vector,
                severity_score=advisory.severity_score,
                published=advisory.published, modified=advisory.modified,
                source=config.source_osv, ingested_at=now,
            )
            report.advisories += 1
            for (name, version), fixed in advisory.affected.items():
                try:
                    norm = normalize_name(name)
                except InvalidPackageName:
                    continue
                target = version_ids.get((norm, version))
                if target is None:
                    continue
                writer.edge(schema.AFFECTS, adv_id, target,
                            fixed_version=fixed, source=config.source_osv)

    # -- 9. typosquat neighbourhood ----------------------------------------

    if config.detect_typosquats and package_ids:
        log("[7/7] typosquat neighbourhood")
        counts = registry.download_counts(list(package_ids))
        popular = dict(
            sorted(counts.items(), key=lambda kv: -kv[1])[: config.typosquat_targets]
        )
        popular = {k: v for k, v in popular.items() if v > 0}
        if popular:
            index = TyposquatIndex(popular)
            for name, pkg_id in package_ids.items():
                # counts.get(name) is None when the registry gave no figure.
                # That is unknown, not zero, and the detector declines to
                # claim asymmetry it cannot demonstrate.
                for finding in index.find(name, counts.get(name)):
                    target_id = package_ids.get(finding.target)
                    if target_id is None or target_id == pkg_id:
                        continue
                    writer.edge(
                        schema.TYPOSQUAT_OF, pkg_id, target_id,
                        distance=finding.distance,
                        technique=finding.technique,
                        popularity_ratio=int(min(finding.popularity_ratio, 1e9)),
                        source=config.source_derived,
                    )
                    report.typosquat_edges += 1
    else:
        log("[7/7] typosquat detection disabled")

    staged_nodes, staged_edges = writer.staged_counts()
    log(f"\nwriting {staged_nodes:,} nodes and {staged_edges:,} edges")
    report.write = writer.flush()
    report.elapsed_s = time.perf_counter() - started
    return report
