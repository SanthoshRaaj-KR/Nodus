"""Publish-time anomalies: the worm's signature, from metadata already fetched.

`registry.py` reads `has_install_script`, `published_at`, `publisher` and
`repository` for every version, and the ingest writes them onto the node. Until
now nothing read them back. This module does, because those four fields between
them describe the TanStack compromise almost exactly:

    84 artifacts across 42 packages, inside six minutes, from a CI pipeline
    whose credentials had just been taken.

Every clause of that is a metadata fact. A burst of publishes far tighter than
the package's own history. Versions pushed by an account that is not among the
listed maintainers. Install scripts appearing on packages that never had one.
And -- the signal no per-package check can see -- the same account bursting
across *many* packages at once, which is what separates a worm from a
maintainer having a busy afternoon.

**Unknown is not "no".** This is the rule the whole module is built around, and
it is the one that decides whether the output is usable. The abbreviated
packument carries no maintainers and no publish times; a missing `published_at`
is the sentinel 0, not 1970. Treating either as a negative would emit
"published by an unknown account" for every package whose metadata we simply
did not fetch, which is most of them on a fast ingest. So each check states its
own preconditions and declines to fire when they are not met -- the same
discipline `typosquat.py` applies to unknown download counts, and for the same
reason.

**Nothing here is a verdict.** These are INVESTIGATE-grade leads feeding the
existing evidence model. A package that gained an install script is usually a
package that gained an install script.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

from .identity import is_service_identity, normalize_repo_url, split_scope
from .registry import PackumentSummary, VersionSummary

__all__ = [
    "Signal",
    "AnomalySignal",
    "CorrelatedBurst",
    "analyse_package",
    "analyse_correlated_burst",
    "DORMANCY_SECONDS",
    "BURST_WINDOW_SECONDS",
    "BURST_MIN_VERSIONS",
]


#: A package quiet for this long, then publishing, is worth a second look.
#: One year rather than a few months: legitimate low-traffic libraries go
#: quiet for a season all the time, and a threshold that fires on those
#: produces a list nobody reads.
DORMANCY_SECONDS = 365 * 24 * 60 * 60

#: The TanStack window was six minutes. Fifteen gives room for a slower worm
#: while staying far below any human release cadence.
BURST_WINDOW_SECONDS = 15 * 60

#: Three versions inside the window. Two is a botched release followed by a
#: fix, which is ordinary and common.
BURST_MIN_VERSIONS = 3

#: Distinct packages one account must touch inside the window before it reads
#: as propagation rather than a maintainer tidying up a monorepo.
BURST_MIN_PACKAGES = 3

#: How far back a version may have been published and still be assessed.
#:
#: This is not a performance knob, it is a correctness one, and leaving it out
#: made the first version of this module unusable. Two of the checks compare a
#: historical publish against *current* state:
#:
#:   * `maintainers` is the list as it stands today. `chalk@0.5.1` was pushed
#:     by `jbnicolai` in 2014, who was a maintainer then and is not now;
#:     `debug@0.0.1` by `tjholowaychuk`, who wrote it and has since handed it
#:     on. Both are correct history and neither is a finding.
#:   * `repository` moves when a project joins an org -- visionmedia to
#:     debug-js, strongloop to expressjs. Real events, all of them years old.
#:
#: Run without a horizon over six ordinary packages, those two checks produced
#: 290 and 6 rows respectively, none of them actionable. A supply-chain tool is
#: asked "what happened recently that looks wrong", not "what has ever happened
#: in this package's twelve-year history", and answering the second question
#: buries the first.
#:
#: Pass ``horizon_seconds=None`` to assess the whole history anyway, which is
#: what the tests do when they are exercising the detection logic itself.
RECENT_SECONDS = 90 * 24 * 60 * 60


class Signal:
    """One publish-time observation. Names match the evidence-atom style."""

    INSTALL_SCRIPT_ADDED = "INSTALL_SCRIPT_ADDED"
    PUBLISHER_NOT_MAINTAINER = "PUBLISHER_NOT_MAINTAINER"
    DORMANCY_BREAK = "DORMANCY_BREAK"
    PUBLISH_BURST = "PUBLISH_BURST"
    REPOSITORY_REMOVED = "REPOSITORY_REMOVED"
    REPOSITORY_CHANGED = "REPOSITORY_CHANGED"
    CORRELATED_BURST = "CORRELATED_BURST"

    #: Every signal in this module is relational or circumstantial, so none may
    #: raise a finding above INVESTIGATE. Mirrors Evidence.RELATIONAL, and is
    #: asserted in the tests rather than trusted.
    ALL = frozenset({
        INSTALL_SCRIPT_ADDED,
        PUBLISHER_NOT_MAINTAINER,
        DORMANCY_BREAK,
        PUBLISH_BURST,
        REPOSITORY_REMOVED,
        REPOSITORY_CHANGED,
        CORRELATED_BURST,
    })


@dataclass(frozen=True)
class AnomalySignal:
    """One observation about one version, carrying its own witness."""

    signal: str
    package: str
    version: str
    detail: str
    #: What the check compared against, so a reader can dispute it.
    witness: str = ""

    def explain(self) -> str:
        line = f"{self.package}@{self.version}: {self.detail}"
        return f"{line} [{self.witness}]" if self.witness else line


@dataclass
class CorrelatedBurst:
    """Many packages published by one account inside one window.

    The cross-package signal -- and the one that needed the most work to be
    worth anything, because *volume alone does not distinguish a worm from a
    release*. Measured against the live feed, 500 consecutive publishes
    produced seventeen bursts, the largest being `metamaskbot` pushing 97
    packages in 4.6 minutes. That is quantitatively bigger than the TanStack
    compromise (84 artifacts, 42 packages, six minutes) and entirely routine:
    it is one monorepo releasing.

    So the shape is necessary but not sufficient, and `cohesion` is what
    carries the rest. A burst whose packages all sit under one npm scope, or
    all build out of one repository, is a monorepo doing what monorepos do.
    A burst spread across unrelated scopes and repositories is an account
    reaching places it has no reason to reach at once -- which is the actual
    signature.
    """

    identity: str
    started_at: int
    ended_at: int
    #: package -> the versions it published inside the window
    packages: dict[str, list[str]] = field(default_factory=dict)
    #: Distinct npm scopes touched. One scope over many packages reads as a
    #: monorepo; unscoped packages each count as their own.
    scopes: set[str] = field(default_factory=set)
    #: Distinct source repositories, where the registry told us.
    repositories: set[str] = field(default_factory=set)

    @property
    def package_count(self) -> int:
        return len(self.packages)

    @property
    def artifact_count(self) -> int:
        return sum(len(v) for v in self.packages.values())

    @property
    def span_seconds(self) -> int:
        return max(0, self.ended_at - self.started_at)

    @property
    def cohesive(self) -> bool:
        """Do these packages plausibly belong to one project?

        True when one scope or one repository covers the whole burst. A
        cohesive burst is still reported -- the count is never suppressed --
        but it is the ordinary case and must not read like an incident.
        """
        if self.package_count < 2:
            return True
        if len(self.repositories) == 1:
            return True
        return len(self.scopes) == 1 and "" not in self.scopes

    @property
    def verdict(self) -> str:
        return "release" if self.cohesive else "spread"

    def explain(self) -> str:
        minutes = self.span_seconds / 60
        head = (
            f"{self.identity} published {self.artifact_count} artifact(s) "
            f"across {self.package_count} package(s) in {minutes:.1f} minute(s)"
        )
        if self.cohesive:
            where = (
                f"one repository ({next(iter(self.repositories))})"
                if len(self.repositories) == 1 and next(iter(self.repositories))
                else f"one scope ({next(iter(self.scopes))})"
            )
            return f"{head} -- all within {where}, which reads as a release"
        return (
            f"{head} -- across {len(self.scopes)} scope(s) and "
            f"{len(self.repositories) or 'unknown'} repository(ies), which does not"
        )


# --------------------------------------------------------------------------
# Per-package checks
# --------------------------------------------------------------------------

def _dated(versions: dict[str, VersionSummary]) -> list[VersionSummary]:
    """Versions with a known publish time, oldest first.

    Anything with the sentinel 0 is dropped rather than sorted to the front:
    an unknown timestamp compared against a real one manufactures a decades-long
    dormancy gap out of missing data.
    """
    return sorted(
        (v for v in versions.values() if v.published_at > 0),
        key=lambda v: v.published_at,
    )


def analyse_package(
    packument: PackumentSummary,
    now: int | None = None,
    horizon_seconds: int | None = RECENT_SECONDS,
) -> list[AnomalySignal]:
    """Every publish-time signal for one package.

    Comparisons are between consecutive versions *in publish order*, not in
    semver order. A patch backported onto an old branch is published after a
    newer minor, and comparing it against its semver predecessor would report a
    repository change that never happened.

    ``horizon_seconds`` bounds which versions may *emit* a signal, not which
    may serve as the predecessor -- a version published yesterday is still
    compared against the one before it, however old that is. See
    :data:`RECENT_SECONDS` for why the bound exists at all.
    """
    import time

    out: list[AnomalySignal] = []
    ordered = _dated(packument.versions)

    now = int(now if now is not None else time.time())
    cutoff = None if horizon_seconds is None else now - horizon_seconds

    def recent(v: VersionSummary) -> bool:
        return cutoff is None or v.published_at >= cutoff

    maintainers = {user.lower() for user, _ in packument.maintainers if user}
    # The abbreviated document carries no maintainer list at all, so an empty
    # set there means "not fetched", not "nobody maintains this".
    maintainers_known = bool(maintainers) and not packument.abbreviated_only

    for index, current in enumerate(ordered):
        previous = ordered[index - 1] if index else None
        if not recent(current):
            continue

        # A CI pseudo-identity is never in the maintainer list, by
        # construction: npm's OIDC trusted publishing stamps every artifact
        # with the same "GitHub Actions" label. Left in, this check fires on
        # every OIDC-published package in the ecosystem -- reporting the
        # modern, token-less publishing path as the anomaly.
        if (
            maintainers_known
            and current.publisher
            and not is_service_identity(current.publisher, current.publisher_email)
        ):
            if current.publisher.lower() not in maintainers:
                out.append(AnomalySignal(
                    Signal.PUBLISHER_NOT_MAINTAINER,
                    packument.name, current.version,
                    f"published by {current.publisher!r}, who is not a listed "
                    f"maintainer",
                    witness=f"maintainers: {', '.join(sorted(maintainers)[:5])}",
                ))

        if previous is None:
            continue

        if current.has_install_script and not previous.has_install_script:
            out.append(AnomalySignal(
                Signal.INSTALL_SCRIPT_ADDED,
                packument.name, current.version,
                "gained an install script the previous version did not have",
                witness=f"previous: {previous.version}",
            ))

        gap = current.published_at - previous.published_at
        if gap >= DORMANCY_SECONDS:
            out.append(AnomalySignal(
                Signal.DORMANCY_BREAK,
                packument.name, current.version,
                f"published after {gap // 86400} quiet day(s)",
                witness=f"previous: {previous.version}",
            ))

        # Repository comparisons need the full document; the abbreviated one
        # carries no repository field, so every version would look like a
        # removal.
        if not packument.abbreviated_only:
            # Compared as RepoRef, not as text: `git+https://github.com/a/b.git`
            # and `https://github.com/a/b` are the same repository spelled two
            # ways, and a string comparison would report a change on every
            # package that tidied its manifest.
            before = normalize_repo_url(previous.repository or "")
            after = normalize_repo_url(current.repository or "")
            if before and not after:
                out.append(AnomalySignal(
                    Signal.REPOSITORY_REMOVED,
                    packument.name, current.version,
                    "dropped the repository field its predecessor carried",
                    witness=f"was: {before.url}",
                ))
            elif before and after and before != after:
                out.append(AnomalySignal(
                    Signal.REPOSITORY_CHANGED,
                    packument.name, current.version,
                    f"changed repository from {before.url} to {after.url}",
                    witness=f"previous: {previous.version}",
                ))

    out.extend(_burst_within_package(packument, ordered, recent))
    return out


def _burst_within_package(
    packument: PackumentSummary,
    ordered: list[VersionSummary],
    recent: Callable[[VersionSummary], bool],
) -> list[AnomalySignal]:
    """Versions published unusually close together.

    A sliding window rather than a fixed bucket: three versions at 0s, 1s and
    2s land in one bucket, but the same three at 59s, 60s and 61s would be
    split across two and reported as nothing at all.
    """
    out: list[AnomalySignal] = []
    if len(ordered) < BURST_MIN_VERSIONS:
        return out

    start = 0
    reported: set[str] = set()
    for end in range(len(ordered)):
        while ordered[end].published_at - ordered[start].published_at > BURST_WINDOW_SECONDS:
            start += 1
        count = end - start + 1
        if count >= BURST_MIN_VERSIONS:
            window = ordered[start : end + 1]
            # The burst is reported against its newest member, so that is the
            # version the horizon is applied to.
            if not recent(window[-1]):
                continue
            key = window[0].version
            if key in reported:
                continue
            reported.add(key)
            span = window[-1].published_at - window[0].published_at
            out.append(AnomalySignal(
                Signal.PUBLISH_BURST,
                packument.name, window[-1].version,
                f"{count} versions published within {span // 60} minute(s)",
                witness=", ".join(v.version for v in window[:6]),
            ))
    return out


# --------------------------------------------------------------------------
# The cross-package check
# --------------------------------------------------------------------------

def analyse_correlated_burst(
    packuments: list[PackumentSummary],
    window_seconds: int = BURST_WINDOW_SECONDS,
    min_packages: int = BURST_MIN_PACKAGES,
    now: int | None = None,
    horizon_seconds: int | None = RECENT_SECONDS,
) -> list[CorrelatedBurst]:
    """One account publishing across many packages inside one window.

    This is the signal that distinguishes a worm from a busy maintainer, and it
    is invisible to any per-package check -- each individual package may look
    like a single ordinary release. Only when the publishes are grouped by
    *account* and sorted by time does the shape appear.

    Grouped by publishing identity rather than by maintainer, because in a
    credential compromise the publisher is the account actually in use, and it
    is frequently not the one listed as maintainer.
    """
    import time

    now = int(now if now is not None else time.time())
    cutoff = None if horizon_seconds is None else now - horizon_seconds

    # (published_at, package, version, scope, repository) -- scope and
    # repository are what let a release be told from a spread later.
    by_identity: dict[str, list[tuple[int, str, str, str, str]]] = defaultdict(list)
    for packument in packuments:
        try:
            scope = split_scope(packument.name)[0] or ""
        except Exception:  # noqa: BLE001 - registry names are not ours
            scope = ""
        repo_ref = normalize_repo_url(packument.repository or "")
        repo = repo_ref.key if repo_ref else ""
        for version in packument.versions.values():
            if version.published_at <= 0 or not version.publisher:
                continue
            if cutoff is not None and version.published_at < cutoff:
                continue
            # The most dangerous false positive in this module. Every package
            # published through npm's OIDC trusted publishing carries the same
            # "GitHub Actions" label, so grouping by it collects unrelated
            # projects across the whole ecosystem -- and several of them
            # publishing inside any given quarter-hour is not a worm, it is a
            # Tuesday. A genuine CI compromise still shows up: as a burst
            # within one package, and as the frontier's repository route.
            if is_service_identity(version.publisher, version.publisher_email):
                continue
            by_identity[version.publisher.lower()].append(
                (
                    version.published_at, packument.name, version.version,
                    scope, repo or (version.repository or ""),
                )
            )

    bursts: list[CorrelatedBurst] = []
    for identity, events in by_identity.items():
        events.sort()
        start = 0
        best: CorrelatedBurst | None = None
        for end in range(len(events)):
            while events[end][0] - events[start][0] > window_seconds:
                start += 1
            window = events[start : end + 1]
            names = {name for _, name, _, _, _ in window}
            if len(names) < min_packages:
                continue
            # Keep the widest window per identity rather than one per position,
            # so a fifteen-package burst reports once instead of thirteen times.
            if best is None or len(names) > best.package_count or (
                len(names) == best.package_count
                and len(window) > best.artifact_count
            ):
                grouped: dict[str, list[str]] = defaultdict(list)
                for _, name, version, _, _ in window:
                    grouped[name].append(version)
                best = CorrelatedBurst(
                    identity=identity,
                    started_at=window[0][0],
                    ended_at=window[-1][0],
                    packages=dict(grouped),
                    scopes={scope for _, _, _, scope, _ in window},
                    repositories={
                        repo for _, _, _, _, repo in window if repo
                    },
                )
        if best is not None:
            bursts.append(best)

    # A spread burst outranks a cohesive one however much smaller it is: 97
    # packages inside one monorepo is a release, and four across four
    # unrelated repositories is the thing worth looking at.
    bursts.sort(key=lambda b: (
        b.cohesive, -b.package_count, -b.artifact_count, b.identity
    ))
    return bursts
