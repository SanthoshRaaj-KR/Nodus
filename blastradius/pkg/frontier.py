"""The blast *frontier*: what the attacker can publish to next.

Blast radius is backward-looking -- a version is compromised, which projects
already hold it. That is the question every scanner answers, and by the time it
is answered the damage is done.

The TanStack-class worm poses a different question. It did not spread by being
depended upon; it spread by **publishing**. Credentials were taken from a CI
pipeline and used to push 84 artifacts across 42 packages in six minutes. Every
one of those packages was predictable the moment the first was known, because
publish rights are a graph the registry hands out for free:

    the compromised artifact --PUBLISHED_BY--> an account
    that account                              --> everything else it can publish
    the compromised package  --MAINTAINED_BY--> accounts with publish rights
    the compromised version  --SOURCED_FROM--> a repository whose CI publishes

So the frontier is the attacker's **reachable publish surface**, and it is
three one-hop queries over edges the ingest already writes.

**Ranked by what it would cost you, not by how many there are.** A package the
attacker can publish to that nobody in the fleet depends on is a lower priority
than one sitting under forty services. Each frontier package is therefore
scored by how many of *your* services resolve it today -- which is the same
closure the blast radius uses, read forwards.

**This is a prediction, and it is labelled as one.** Every atom here is
relational: shared publisher, shared maintainer, shared repository. Under the
rule in ``blast.derive_confidence`` those can never raise a finding above
INVESTIGATE however many fire, and nothing in this module tries to. A package
on the frontier is not compromised. It is a place to look first, and -- more
usefully -- a list of accounts whose credentials to rotate before the worm gets
to use them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import schema
from ..hydra_client import HydraClient
from ..ids import IdAllocator
from .blast import BlastRadius, Evidence
from .identity import is_service_identity, package_key, version_key

__all__ = [
    "Route",
    "FrontierTarget",
    "Frontier",
    "FrontierEngine",
]


class Route:
    """How the attacker reaches a package. Recorded, never merged into a score."""

    #: The account that published the compromised artifact. Strongest of the
    #: three: those are the credentials demonstrably in play.
    PUBLISHER = "publisher"
    #: An account listed as maintainer, which holds publish rights whether or
    #: not it published this particular artifact.
    MAINTAINER = "maintainer"
    #: A repository whose CI publishes. This is the TanStack route -- the
    #: pipeline is breached, and every package built out of it is reachable
    #: regardless of which account is nominally responsible.
    REPOSITORY = "repository"

    #: Each route maps to the relational atom it justifies. They are all
    #: relational on purpose: a frontier entry is a lead, not a verdict.
    ATOM = {
        PUBLISHER: Evidence.SHARED_PUBLISHER,
        MAINTAINER: Evidence.SHARED_MAINTAINER,
        REPOSITORY: Evidence.SHARED_REPOSITORY,
    }


@dataclass
class FrontierTarget:
    """One package the attacker could publish to, and why we think so."""

    package: str
    package_id: int = 0
    #: route -> the identities that reach this package by that route. Kept as
    #: the witness set rather than a count, because "rotate these three
    #: accounts" is the action and a number does not name them.
    routes: dict[str, set[str]] = field(default_factory=dict)
    #: Services in the fleet that resolve some version of this package today.
    exposed_services: set[str] = field(default_factory=set)
    #: True when fleet impact was not computed for this row (see the cap in
    #: FrontierEngine.analyse). Distinguishes "no services" from "not asked".
    impact_measured: bool = True

    @property
    def atoms(self) -> set[str]:
        return {Route.ATOM[r] for r in self.routes if r in Route.ATOM}

    @property
    def confidence(self) -> str:
        """Always INVESTIGATE, and derived rather than asserted.

        Routed through the same function the rest of the tool uses so that if
        the confidence rules ever change, this changes with them instead of
        quietly keeping a hardcoded answer.
        """
        from .blast import derive_confidence

        return derive_confidence(self.atoms)

    @property
    def identities(self) -> set[str]:
        """Every account or repository implicated, across all routes."""
        return {who for witnesses in self.routes.values() for who in witnesses}

    def explain(self) -> str:
        lines = [f"  {self.package}"]
        if self.impact_measured:
            n = len(self.exposed_services)
            lines.append(
                f"      fleet impact   {n} service(s) resolve it today"
                if n else "      fleet impact   nothing in the fleet uses it"
            )
        else:
            lines.append("      fleet impact   not measured (past the cap)")
        for route in (Route.PUBLISHER, Route.MAINTAINER, Route.REPOSITORY):
            if route in self.routes:
                who = ", ".join(sorted(self.routes[route])[:4])
                more = len(self.routes[route]) - 4
                lines.append(
                    f"      via {route:<11}{who}" + (f" (+{more} more)" if more > 0 else "")
                )
        lines.append(f"      confidence     {self.confidence}")
        return "\n".join(lines)


@dataclass
class Frontier:
    """The whole forward-looking answer for one compromised version."""

    target: str
    target_id: int = 0
    exists: bool = False
    targets: list[FrontierTarget] = field(default_factory=list)
    #: Accounts and repositories to rotate, deduplicated across routes. This is
    #: the actionable half: the frontier tells you what is at risk, this tells
    #: you what to revoke.
    implicated: dict[str, set[str]] = field(default_factory=dict)
    #: Frontier rows whose fleet impact was skipped because of the cap, so a
    #: truncated ranking is never mistaken for a complete one.
    impact_skipped: int = 0
    #: CI pseudo-identities found on the artifact and deliberately not
    #: followed. Negative evidence in the sense the rest of the tool uses it:
    #: what we looked for and chose not to conclude from.
    service_identities: list[str] = field(default_factory=list)

    @property
    def reachable_packages(self) -> int:
        return len(self.targets)

    @property
    def at_risk_services(self) -> set[str]:
        """Every service that would be touched if the whole frontier fell.

        The union rather than the sum: one service depending on six frontier
        packages is one service at risk, and summing would report six.
        """
        out: set[str] = set()
        for t in self.targets:
            out |= t.exposed_services
        return out

    def _service_identity_note(self) -> list[str]:
        """State the publisher route we declined to follow, and why."""
        if not self.service_identities:
            return []
        who = ", ".join(self.service_identities)
        return [
            "",
            f"  LOOKED FOR, NOT FOLLOWED  published by {who}, which is a CI",
            "  identity rather than an account. Packages sharing it share a build",
            "  system, not a credential, so no publisher route is drawn from it.",
        ]

    def render(self, limit: int = 20) -> str:
        lines = [
            f"BLAST FRONTIER: {self.target}",
            "",
            "  What the credentials behind this compromise could publish to next.",
            "  Every row is INVESTIGATE -- a publish path, not a compromise.",
            "",
        ]
        if not self.exists:
            lines.append("  Version not in the graph; nothing to project from.")
            return "\n".join(lines)
        if not self.targets:
            lines.append(
                "  No reachable packages. No shared publisher, maintainer or\n"
                "  repository links this version to anything else in the graph."
            )
            lines.extend(self._service_identity_note())
            return "\n".join(lines)

        lines.append(
            f"  {self.reachable_packages} package(s) reachable, "
            f"{len(self.at_risk_services)} fleet service(s) behind them."
        )
        lines.extend(self._service_identity_note())
        if self.impact_skipped:
            lines.append(
                f"  Fleet impact not measured for {self.impact_skipped} row(s) "
                f"past the cap; they are ranked last, not dropped."
            )
        lines.append("")
        for t in self.targets[:limit]:
            lines.append(t.explain())
        if len(self.targets) > limit:
            lines.append(f"\n  ... and {len(self.targets) - limit} more")

        if self.implicated:
            lines.append("")
            lines.append("  ROTATE THESE FIRST")
            for kind in sorted(self.implicated):
                for who in sorted(self.implicated[kind]):
                    lines.append(f"      {kind:<12} {who}")
        return "\n".join(lines)


class FrontierEngine:
    """Projects the attacker's publish surface from one compromised version."""

    #: Fleet impact costs one query per frontier package, so a maintainer with
    #: nine hundred packages would otherwise turn a six-minute answer into a
    #: nine-hundred-query one. Rows past the cap keep their routes and are
    #: reported as unmeasured rather than dropped -- a silent truncation would
    #: read as "these have no fleet impact", which is the wrong direction to be
    #: wrong in.
    IMPACT_CAP = 200

    def __init__(self, client: HydraClient, ids: IdAllocator):
        self.client = client
        self.ids = ids

    # -- L0: local resolution, no graph hit -------------------------------

    def resolve(self, name: str, version: str) -> int | None:
        return self.ids.lookup(schema.PACKAGE_VERSION, version_key(name, version))

    def resolve_package(self, name: str) -> int | None:
        return self.ids.lookup(schema.PACKAGE, package_key(name))

    # -- the three routes --------------------------------------------------

    def _publisher_route(
        self, result: BlastRadius, version_id: int, exclude: str,
        skipped: list[str] | None = None,
    ) -> dict[str, set[str]]:
        """Packages the publishing account can also push to.

        CI pseudo-identities are excluded. `GitHub Actions` /
        `npm-oidc-no-reply@github.com` is stamped on every artifact published
        through npm's OIDC trusted publishing, so following it links packages
        that share a build system rather than a credential -- see
        `identity.is_service_identity`. The exclusion is reported to the caller
        instead of being silent, because "we found no publisher route" and "we
        declined to follow the one there was" are different answers.
        """
        out: dict[str, set[str]] = {}
        publishers = self._timed(
            result, "F1a publisher identity",
            "MATCH (v:PackageVersion {id: $id})"
            f"-[:{schema.PUBLISHED_BY}]->(p:{schema.PUBLISHER}) "
            "RETURN p.id AS id, p.username AS username, p.email AS email "
            "ORDER BY username",
            id=version_id,
        )
        for row in publishers:
            if is_service_identity(row.get("username"), row.get("email")):
                if skipped is not None:
                    skipped.append(row.get("username") or "")
                continue
            siblings = self._timed(
                result, "F1b packages that account publishes",
                "MATCH (v:PackageVersion)"
                f"-[:{schema.PUBLISHED_BY}]->(p:{schema.PUBLISHER} {{id: $id}}) "
                "RETURN DISTINCT v.name AS name ORDER BY name",
                id=row["id"],
            )
            for s in siblings:
                if s["name"] == exclude:
                    continue
                out.setdefault(s["name"], set()).add(row["username"])
        return out

    def _maintainer_route(
        self, result: BlastRadius, package_id: int, exclude: str
    ) -> dict[str, set[str]]:
        """Packages the listed maintainers can also push to."""
        out: dict[str, set[str]] = {}
        maintainers = self._timed(
            result, "F2a maintainers",
            f"MATCH (p:{schema.PACKAGE} {{id: $id}})"
            f"-[:{schema.MAINTAINED_BY}]->(m:{schema.MAINTAINER}) "
            "RETURN m.id AS id, m.username AS username ORDER BY username",
            id=package_id,
        )
        for row in maintainers:
            siblings = self._timed(
                result, "F2b packages that account maintains",
                f"MATCH (p:{schema.PACKAGE})"
                f"-[:{schema.MAINTAINED_BY}]->(m:{schema.MAINTAINER} {{id: $id}}) "
                "RETURN DISTINCT p.name AS name ORDER BY name",
                id=row["id"],
            )
            for s in siblings:
                if s["name"] == exclude:
                    continue
                out.setdefault(s["name"], set()).add(row["username"])
        return out

    def _repository_route(
        self, result: BlastRadius, version_id: int, exclude: str
    ) -> dict[str, set[str]]:
        """Packages built out of the same repository -- the CI route."""
        out: dict[str, set[str]] = {}
        repos = self._timed(
            result, "F3a source repository",
            "MATCH (v:PackageVersion {id: $id})"
            f"-[:{schema.SOURCED_FROM}]->(r:{schema.REPOSITORY}) "
            "RETURN r.id AS id, r.url AS url ORDER BY url",
            id=version_id,
        )
        for row in repos:
            if not row["url"]:
                continue
            siblings = self._timed(
                result, "F3b packages from that repository",
                "MATCH (v:PackageVersion)"
                f"-[:{schema.SOURCED_FROM}]->(r:{schema.REPOSITORY} {{id: $id}}) "
                "RETURN DISTINCT v.name AS name ORDER BY name",
                id=row["id"],
            )
            for s in siblings:
                if s["name"] == exclude:
                    continue
                out.setdefault(s["name"], set()).add(row["url"])
        return out

    # -- fleet impact ------------------------------------------------------

    def fleet_impact(self, result: BlastRadius, package_id: int) -> set[str]:
        """Services resolving any version of this package today.

        Two pinned hops -- package to its versions, versions to the services
        that resolved them -- over the same closure the blast radius reads.
        Distinct service names are returned rather than a count so the caller
        can union across frontier rows without double-counting a service that
        depends on several of them.
        """
        rows = self._timed(
            result, "F4 fleet impact",
            f"MATCH (p:{schema.PACKAGE} {{id: $id}})"
            f"-[:{schema.HAS_VERSION}]->(v:{schema.PACKAGE_VERSION})"
            f"-[:{schema.RESOLVED_IN}]->(s:{schema.SERVICE}) "
            "RETURN DISTINCT s.name AS name ORDER BY name",
            id=package_id,
        )
        return {r["name"] for r in rows}

    # -- orchestration -----------------------------------------------------

    def analyse(
        self,
        name: str,
        version: str,
        result: BlastRadius | None = None,
        measure_impact: bool = True,
    ) -> Frontier:
        """The whole frontier for one version.

        ``result`` is the timing sink shared with the blast-radius engine, so a
        combined run reports one latency table rather than two.
        """
        result = result or BlastRadius(target=f"{name}@{version}")
        frontier = Frontier(target=f"{name}@{version}")

        version_id = self.resolve(name, version)
        if version_id is None:
            return frontier
        frontier.target_id = version_id
        frontier.exists = True

        package_id = self.resolve_package(name)

        skipped_identities: list[str] = []
        by_route: dict[str, dict[str, set[str]]] = {
            Route.PUBLISHER: self._publisher_route(
                result, version_id, name, skipped=skipped_identities
            ),
            Route.REPOSITORY: self._repository_route(result, version_id, name),
        }
        frontier.service_identities = sorted({s for s in skipped_identities if s})
        if package_id is not None:
            by_route[Route.MAINTAINER] = self._maintainer_route(
                result, package_id, name
            )

        merged: dict[str, FrontierTarget] = {}
        for route, found in by_route.items():
            for pkg, witnesses in found.items():
                target = merged.setdefault(pkg, FrontierTarget(package=pkg))
                target.routes.setdefault(route, set()).update(witnesses)
                frontier.implicated.setdefault(route, set()).update(witnesses)

        for pkg, target in merged.items():
            resolved = self.resolve_package(pkg)
            target.package_id = resolved if resolved is not None else 0

        # Rank before measuring impact so the cap spends its budget on the rows
        # most likely to matter: more routes means more ways in.
        ordered = sorted(
            merged.values(), key=lambda t: (-len(t.routes), t.package)
        )

        if measure_impact:
            for i, target in enumerate(ordered):
                if i >= self.IMPACT_CAP or not target.package_id:
                    target.impact_measured = False
                    frontier.impact_skipped += 1
                    continue
                target.exposed_services = self.fleet_impact(
                    result, target.package_id
                )
        else:
            for target in ordered:
                target.impact_measured = False
            frontier.impact_skipped = len(ordered)

        # Final ranking is by what it would cost the fleet. Unmeasured rows sort
        # last rather than as zero, since "not asked" is not "nothing found".
        frontier.targets = sorted(
            ordered,
            key=lambda t: (
                not t.impact_measured,
                -len(t.exposed_services),
                -len(t.routes),
                t.package,
            ),
        )
        return frontier

    # -- timing ------------------------------------------------------------

    def _timed(self, result: BlastRadius, label: str, statement: str, **params):
        import time

        from .blast import Timing

        started = time.perf_counter()
        rows = self.client.query(statement, params or None)
        result.timings.append(
            Timing(label, (time.perf_counter() - started) * 1000, len(rows))
        )
        return rows
