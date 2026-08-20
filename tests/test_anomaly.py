"""Publish-time anomalies, and the silence that keeps them usable.

Two things decide whether this module is worth shipping.

**Does it fire on the shape the worm actually had?** The TanStack compromise
was a burst -- many artifacts, many packages, one account, six minutes. There
is a test that reconstructs exactly that and asserts it is caught.

**Does it stay quiet when it does not know?** Far more important, and the
reason most anomaly detectors get switched off. The abbreviated packument
carries no maintainers, no publish times and no repository; if missing data
read as a negative, every package on a fast ingest would be reported as
"published by an unknown account" and the signal would be worth nothing. Most
of the tests here are about that silence.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.pkg.anomaly import (  # noqa: E402
    BURST_MIN_PACKAGES,
    DORMANCY_SECONDS,
    Signal,
    analyse_correlated_burst,
    analyse_package,
)
from blastradius.pkg.registry import PackumentSummary, VersionSummary  # noqa: E402

DAY = 86_400
BASE = 1_700_000_000


OIDC_EMAIL = "npm-oidc-no-reply@github.com"


def version(v, at, *, script=False, publisher="", repo="", publisher_email=""):
    return VersionSummary(
        name="demo", version=v, published_at=at,
        has_install_script=script, publisher=publisher, repository=repo,
        publisher_email=publisher_email,
    )


def packument(*versions, maintainers=(("alice", "a@x"),), full=True, name="demo"):
    return PackumentSummary(
        name=name,
        versions={v.version: v for v in versions},
        maintainers=list(maintainers),
        abbreviated_only=not full,
    )


def analyse(packument, **kw):
    """Assess the whole history unless a test says otherwise.

    The detection tests are about whether a shape is recognised, so they opt
    out of the recency horizon rather than dating every fixture to this week.
    The horizon has its own tests below.
    """
    kw.setdefault("horizon_seconds", None)
    return analyse_package(packument, **kw)


def bursts(packuments, **kw):
    kw.setdefault("horizon_seconds", None)
    return analyse_correlated_burst(packuments, **kw)


def signals(result, kind):
    return [s for s in result if s.signal == kind]


# -- the shape the worm had -------------------------------------------------


def test_catches_a_tanstack_shaped_burst():
    """Many packages, one account, six minutes. The headline case."""
    packuments = []
    for i in range(12):
        vs = [
            version(f"1.0.{n}", BASE + n * 20, publisher="ci-bot")
            for n in range(3)
        ]
        packuments.append(packument(*vs, name=f"pkg-{i}"))

    found = bursts(packuments)
    assert len(found) == 1
    burst = found[0]
    assert burst.identity == "ci-bot"
    assert burst.package_count == 12
    assert burst.artifact_count == 36
    assert burst.span_seconds <= 15 * 60
    assert "12 package(s)" in burst.explain()


def test_a_single_busy_maintainer_is_not_a_correlated_burst():
    """One package published three times fast is a release, not propagation.

    The cross-package check must require breadth, or it fires on every
    monorepo release and gets muted before it ever sees a worm.
    """
    vs = [version(f"1.0.{n}", BASE + n * 10, publisher="alice") for n in range(6)]
    assert bursts([packument(*vs)]) == []


def test_correlated_burst_needs_enough_distinct_packages():
    """Right at the threshold, and just under it."""
    def build(count):
        return [
            packument(version("1.0.0", BASE, publisher="bot"), name=f"p{i}")
            for i in range(count)
        ]

    assert bursts(build(BURST_MIN_PACKAGES - 1)) == []
    assert len(bursts(build(BURST_MIN_PACKAGES))) == 1


def test_publishes_spread_over_days_are_not_a_burst():
    """The window is what makes it a burst; spread them out and it is normal."""
    packuments = [
        packument(version("1.0.0", BASE + i * DAY, publisher="bot"), name=f"p{i}")
        for i in range(10)
    ]
    assert bursts(packuments) == []


def test_one_identity_reports_one_burst_not_one_per_position():
    """A wide burst must not produce a row per sliding-window position."""
    packuments = [
        packument(version("1.0.0", BASE + i * 5, publisher="bot"), name=f"p{i}")
        for i in range(20)
    ]
    found = bursts(packuments)
    assert len(found) == 1
    assert found[0].package_count == 20


# -- unknown is not "no" ----------------------------------------------------


def test_abbreviated_packument_emits_no_publisher_signal():
    """No maintainer list means unfetched, not unmaintained.

    The abbreviated document is what a fast ingest reads. If this fired there,
    every package in the graph would carry the signal and it would mean nothing.
    """
    p = packument(
        version("1.0.0", BASE, publisher="stranger"),
        maintainers=(), full=False,
    )
    assert signals(analyse(p), Signal.PUBLISHER_NOT_MAINTAINER) == []


def test_missing_publish_times_produce_no_temporal_signals():
    """A sentinel 0 timestamp is unknown, not 1970.

    Sorting it alongside a real timestamp would manufacture a fifty-year
    dormancy gap out of missing data.
    """
    p = packument(
        version("1.0.0", 0), version("1.0.1", 0), version("1.0.2", 0),
    )
    result = analyse(p)
    assert signals(result, Signal.DORMANCY_BREAK) == []
    assert signals(result, Signal.PUBLISH_BURST) == []


def test_a_dated_version_is_not_compared_against_an_undated_one():
    """Mixing known and unknown timestamps must not invent a gap."""
    p = packument(version("1.0.0", 0), version("1.0.1", BASE))
    assert signals(analyse(p), Signal.DORMANCY_BREAK) == []


def test_abbreviated_packument_emits_no_repository_signal():
    """The abbreviated document carries no repository field at all."""
    p = packument(
        version("1.0.0", BASE, repo="https://github.com/a/b"),
        version("1.0.1", BASE + 10),
        full=False,
    )
    assert signals(analyse(p), Signal.REPOSITORY_REMOVED) == []


def test_publisher_in_maintainer_list_is_silent():
    p = packument(version("1.0.0", BASE, publisher="Alice"))
    assert signals(analyse(p), Signal.PUBLISHER_NOT_MAINTAINER) == []


# -- a release is not a worm ------------------------------------------------


def scoped(scope, i, at, publisher="bot", repo=""):
    name = f"@{scope}/pkg-{i}"
    return PackumentSummary(
        name=name, abbreviated_only=False, repository=repo,
        versions={"1.0.0": VersionSummary(
            name=name, version="1.0.0", published_at=at,
            publisher=publisher, repository=repo,
        )},
    )


def test_a_monorepo_release_is_marked_cohesive():
    """The finding that forced this rule.

    Against the live feed, 500 consecutive publishes produced seventeen
    bursts; the largest was `metamaskbot` pushing 97 packages in 4.6 minutes.
    That is bigger than the TanStack compromise and entirely routine -- one
    monorepo releasing. Volume alone cannot tell them apart.
    """
    fleet = [scoped("acme", i, BASE + i) for i in range(20)]
    found = bursts(fleet)
    assert len(found) == 1
    assert found[0].cohesive
    assert found[0].verdict == "release"
    assert "reads as a release" in found[0].explain()


def test_one_repository_across_several_scopes_is_still_cohesive():
    """Some monorepos publish under more than one scope."""
    fleet = [
        scoped("a" if i % 2 else "b", i, BASE + i, repo="https://github.com/o/mono")
        for i in range(8)
    ]
    found = bursts(fleet)
    assert len(found) == 1
    assert found[0].cohesive


def test_an_account_spread_across_unrelated_projects_is_not_cohesive():
    """The actual signature: one account reaching places it should not."""
    fleet = [
        scoped(f"org{i}", i, BASE + i, repo=f"https://github.com/org{i}/lib{i}")
        for i in range(6)
    ]
    found = bursts(fleet)
    assert len(found) == 1
    assert not found[0].cohesive
    assert found[0].verdict == "spread"
    assert "which does not" in found[0].explain()


def test_unscoped_packages_from_unknown_repositories_are_not_cohesive():
    """Absent provenance must not be read as shared provenance.

    Every unscoped package has scope "", and treating that as one shared
    scope would mark the widest possible spread as a tidy release.
    """
    fleet = [
        PackumentSummary(
            name=f"plain-{i}", abbreviated_only=False,
            versions={"1.0.0": VersionSummary(
                name=f"plain-{i}", version="1.0.0",
                published_at=BASE + i, publisher="bot",
            )},
        )
        for i in range(6)
    ]
    found = bursts(fleet)
    assert len(found) == 1
    assert not found[0].cohesive


def test_spread_bursts_rank_above_bigger_cohesive_ones():
    """A four-package spread matters more than a ninety-package release."""
    fleet = [scoped("mono", i, BASE + i, publisher="release-bot") for i in range(30)]
    fleet += [
        scoped(f"other{i}", i, BASE + i, publisher="mallory",
               repo=f"https://github.com/other{i}/x")
        for i in range(4)
    ]
    found = bursts(fleet)
    assert len(found) == 2
    assert found[0].identity == "mallory", "the spread must sort first"
    assert not found[0].cohesive
    assert found[1].cohesive


# -- CI identities are not shared credentials -------------------------------


def test_oidc_publisher_is_not_reported_as_an_outsider():
    """npm's OIDC identity is never in the maintainer list, by construction.

    Found on real data: this check's only surviving finding over six ordinary
    packages was `inquirer@14.1.0` "published by 'GitHub Actions'". Every
    OIDC-published package in the ecosystem would report the same thing, which
    would flag the modern token-less publishing path as the anomaly.
    """
    p = packument(
        version("1.0.0", BASE, publisher="GitHub Actions",
                publisher_email=OIDC_EMAIL),
    )
    assert signals(analyse(p), Signal.PUBLISHER_NOT_MAINTAINER) == []


def test_a_real_outsider_still_fires_alongside_ci_publishes():
    """The exclusion must not swallow the case the check exists for."""
    p = packument(
        version("1.0.0", BASE, publisher="GitHub Actions",
                publisher_email=OIDC_EMAIL),
        version("1.0.1", BASE + DAY, publisher="stranger"),
    )
    found = signals(analyse(p), Signal.PUBLISHER_NOT_MAINTAINER)
    assert [s.version for s in found] == ["1.0.1"]


def test_ci_identity_does_not_manufacture_a_correlated_burst():
    """The worst false positive available to this module.

    Thousands of unrelated packages publish through GitHub Actions OIDC and
    share its label. Grouping by it would report a worm every time a handful
    of them happened to release in the same quarter-hour.
    """
    packuments = [
        packument(
            version("1.0.0", BASE + i, publisher="GitHub Actions",
                    publisher_email=OIDC_EMAIL),
            name=f"unrelated-{i}",
        )
        for i in range(20)
    ]
    assert bursts(packuments) == []


def test_a_named_account_bursting_across_packages_still_fires():
    """A real account is still followed; only the CI pseudo-identity is not."""
    packuments = [
        packument(version("1.0.0", BASE + i, publisher="mallory"), name=f"p{i}")
        for i in range(6)
    ]
    found = bursts(packuments)
    assert len(found) == 1
    assert found[0].identity == "mallory"


# -- the recency horizon ----------------------------------------------------


def test_ancient_history_is_not_reported_by_default():
    """The failure that motivated the horizon.

    `maintainers` is current state; a 2014 publish by a since-departed
    maintainer is correct history and not a finding. Over six ordinary
    packages this check alone produced 290 rows before the horizon existed.
    """
    old = packument(version("1.0.0", BASE, publisher="stranger"))
    assert analyse_package(old, now=BASE + 10 * 365 * DAY) == []


def test_a_recent_publish_is_still_assessed():
    """The horizon must not silence the case the tool exists for."""
    p = packument(version("1.0.0", BASE, publisher="stranger"))
    found = analyse_package(p, now=BASE + DAY)
    assert signals(found, Signal.PUBLISHER_NOT_MAINTAINER)


def test_the_predecessor_may_be_older_than_the_horizon():
    """Only the *emitting* version has to be recent.

    A package dormant for years and then updated is precisely the interesting
    case; requiring both versions to be recent would discard it.
    """
    p = packument(
        version("1.0.0", BASE, script=False, repo="https://github.com/a/b"),
        version("1.0.1", BASE + 5 * 365 * DAY, script=True,
                repo="https://github.com/evil/b"),
    )
    found = analyse_package(p, now=BASE + 5 * 365 * DAY + DAY)
    assert signals(found, Signal.INSTALL_SCRIPT_ADDED)
    assert signals(found, Signal.REPOSITORY_CHANGED)
    assert signals(found, Signal.DORMANCY_BREAK)


def test_correlated_burst_respects_the_horizon():
    """A burst in 2012 is archaeology, not an incident."""
    packuments = [
        packument(version("1.0.0", BASE, publisher="bot"), name=f"p{i}")
        for i in range(10)
    ]
    assert analyse_correlated_burst(packuments, now=BASE + 10 * 365 * DAY) == []
    assert len(analyse_correlated_burst(packuments, now=BASE + DAY)) == 1


# -- the per-package signals ------------------------------------------------


def test_publisher_outside_the_maintainer_list_fires():
    p = packument(version("1.0.0", BASE, publisher="stranger"))
    found = signals(analyse(p), Signal.PUBLISHER_NOT_MAINTAINER)
    assert len(found) == 1
    assert "stranger" in found[0].detail
    assert "alice" in found[0].witness


def test_install_script_appearing_fires_once():
    p = packument(
        version("1.0.0", BASE),
        version("1.0.1", BASE + DAY, script=True),
        version("1.0.2", BASE + 2 * DAY, script=True),
    )
    found = signals(analyse(p), Signal.INSTALL_SCRIPT_ADDED)
    assert [s.version for s in found] == ["1.0.1"], (
        "only the version that gained the script should fire, not every "
        "version that has one"
    )


def test_a_package_that_always_had_an_install_script_is_silent():
    """Plenty of legitimate packages need one; only the change is notable."""
    p = packument(
        version("1.0.0", BASE, script=True),
        version("1.0.1", BASE + DAY, script=True),
    )
    assert signals(analyse(p), Signal.INSTALL_SCRIPT_ADDED) == []


def test_dormancy_break_fires_past_the_threshold_and_not_under_it():
    quiet = packument(
        version("1.0.0", BASE),
        version("1.0.1", BASE + DORMANCY_SECONDS + DAY),
    )
    assert len(signals(analyse(quiet), Signal.DORMANCY_BREAK)) == 1

    busy = packument(
        version("1.0.0", BASE),
        version("1.0.1", BASE + DORMANCY_SECONDS - DAY),
    )
    assert signals(analyse(busy), Signal.DORMANCY_BREAK) == []


def test_repository_removal_and_change_are_distinct_signals():
    removed = packument(
        version("1.0.0", BASE, repo="https://github.com/a/b"),
        version("1.0.1", BASE + DAY),
    )
    assert len(signals(analyse(removed), Signal.REPOSITORY_REMOVED)) == 1

    changed = packument(
        version("1.0.0", BASE, repo="https://github.com/a/b"),
        version("1.0.1", BASE + DAY, repo="https://github.com/evil/b"),
    )
    found = signals(analyse(changed), Signal.REPOSITORY_CHANGED)
    assert len(found) == 1
    assert "evil" in found[0].detail


def test_respelling_the_same_repository_is_not_a_change():
    """`git+https://…​.git` and `https://…` are one repository, two spellings.

    Compared as text this fires on every package that tidied its manifest,
    which is enough noise to bury the real thing.
    """
    p = packument(
        version("1.0.0", BASE, repo="git+https://github.com/a/b.git"),
        version("1.0.1", BASE + DAY, repo="https://github.com/a/b"),
    )
    assert signals(analyse(p), Signal.REPOSITORY_CHANGED) == []


def test_within_package_burst_uses_a_sliding_window():
    """Three versions at 59s/60s/61s are a burst even across a bucket edge."""
    p = packument(
        version("1.0.0", BASE + 59),
        version("1.0.1", BASE + 60),
        version("1.0.2", BASE + 61),
    )
    assert len(signals(analyse(p), Signal.PUBLISH_BURST)) == 1


def test_versions_compared_in_publish_order_not_semver_order():
    """A backport published last must not look like a repository change.

    1.0.2 ships, then 1.0.1 is backported onto an old branch with the old
    repository URL. Comparing in semver order pairs 1.0.1 against 1.0.0 and
    reports a change that never happened.
    """
    p = packument(
        version("1.0.0", BASE, repo="https://github.com/a/b"),
        version("1.0.2", BASE + DAY, repo="https://github.com/a/b"),
        version("1.0.1", BASE + 2 * DAY, repo="https://github.com/a/b"),
    )
    assert signals(analyse(p), Signal.REPOSITORY_CHANGED) == []


def test_empty_packument_is_handled():
    assert analyse(packument()) == []
    assert bursts([]) == []


def test_every_signal_name_is_registered():
    """A new signal must be added to Signal.ALL, which the UI reads."""
    emitted = set()
    p = packument(
        version("1.0.0", BASE, repo="https://github.com/a/b"),
        version("1.0.1", BASE + DORMANCY_SECONDS + DAY, script=True,
                publisher="stranger", repo="https://github.com/evil/b"),
        version("1.0.2", BASE + DORMANCY_SECONDS + DAY + 1),
        version("1.0.3", BASE + DORMANCY_SECONDS + DAY + 2),
    )
    for s in analyse(p):
        emitted.add(s.signal)
    assert emitted, "the fixture should trigger something"
    assert emitted <= Signal.ALL
