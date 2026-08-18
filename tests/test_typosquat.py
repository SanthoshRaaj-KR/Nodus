"""Typosquat detection tests.

Two failure modes are tested with equal weight. Missing a real squat is bad;
flagging `lodash.merge` as a forgery of `lodash` is worse, because a responder
who sees obvious nonsense in the list stops trusting the rest of it.
"""

from __future__ import annotations

import pytest

from blastradius.pkg.typosquat import (
    Technique,
    TyposquatIndex,
    damerau_levenshtein,
    skeleton,
)


POPULAR = {
    "lodash": 50_000_000,
    "express": 30_000_000,
    "react": 25_000_000,
    "node-fetch": 20_000_000,
    "chalk": 18_000_000,
    "debug": 15_000_000,
    "axios": 12_000_000,
    "cross-env": 5_000_000,
}


@pytest.fixture
def index():
    return TyposquatIndex(POPULAR)


# -- distance --------------------------------------------------------------


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("lodash", "lodash", 0),
        ("lodash", "lodahs", 1),      # transposition counts as one
        ("lodash", "l0dash", 1),
        ("lodash", "lodas", 1),
        ("lodash", "lodashh", 1),
        ("lodash", "loadash", 1),
        ("express", "expres", 1),
        ("express", "exprress", 1),
    ],
)
def test_damerau_levenshtein(a, b, expected):
    assert damerau_levenshtein(a, b) == expected


def test_distance_is_bounded_and_says_so():
    # Beyond the bound we return threshold+1 rather than the true distance,
    # which is what lets the inner loop bail out early.
    assert damerau_levenshtein("lodash", "completely-different", 2) == 3


def test_skeleton_folds_confusables():
    assert skeleton("node-fetch") == skeleton("node_fetch") == skeleton("nodefetch")
    assert skeleton("l0dash") == skeleton("lodash")
    assert skeleton("rnoment") == skeleton("moment")


# -- true positives --------------------------------------------------------


@pytest.mark.parametrize(
    "name,target",
    [
        ("lodahs", "lodash"),       # transposition
        ("l0dash", "lodash"),       # homoglyph
        ("lodashh", "lodash"),      # repeated character
        ("lodas", "lodash"),        # omission
        ("expres", "express"),
        ("nodefetch", "node-fetch"),  # separator dropped
        ("node_fetch", "node-fetch"),
        ("crossenv", "cross-env"),  # the classic real-world squat shape
        ("axio", "axios"),
    ],
)
def test_detects_squats(index, name, target):
    findings = index.find(name, popularity=10)
    assert target in {f.target for f in findings}, f"{name} should flag {target}"


def test_technique_is_recorded_not_just_a_score(index):
    finding = next(f for f in index.find("lodahs", 10) if f.target == "lodash")
    assert finding.technique == Technique.TRANSPOSITION
    assert finding.distance == 1
    assert "lodahs" in finding.explain() and "lodash" in finding.explain()


def test_homoglyph_classified_as_such(index):
    finding = next(f for f in index.find("l0dash", 10) if f.target == "lodash")
    assert finding.technique == Technique.HOMOGLYPH


def test_separator_classified_as_such(index):
    finding = next(f for f in index.find("nodefetch", 10) if f.target == "node-fetch")
    assert finding.technique == Technique.SEPARATOR


# -- false positives, the part that decides whether this is usable ---------


@pytest.mark.parametrize(
    "legit",
    ["lodash.merge", "lodash.debounce", "lodash-es", "@types/lodash", "express-session"],
)
def test_namespace_conventions_are_not_squats(index, legit):
    """Official siblings and type stubs sit within a trivial edit distance of
    their parent. Flagging them would bury the real findings."""
    findings = index.find(legit, popularity=100_000)
    assert not any(f.target in ("lodash", "express") for f in findings), (
        f"{legit} must not be reported as a squat"
    )


def test_popularity_asymmetry_is_required(index):
    """A comparably-popular neighbour is a sibling, not a squat."""
    # Same name shape, but this package is itself hugely popular.
    findings = index.find("lodahs", popularity=40_000_000)
    assert not findings, "no asymmetry, so no finding"


def test_asymmetry_threshold_is_the_discriminator(index):
    strong = index.find("lodahs", popularity=10)
    weak = index.find("lodahs", popularity=int(50_000_000 / 2))
    assert strong and not weak


def test_unrelated_names_are_not_flagged(index):
    for name in ("webpack", "typescript", "some-unrelated-package"):
        assert not index.find(name, popularity=10), name


def test_very_short_names_are_skipped(index):
    """At three characters nearly everything is within distance 2 of
    everything, so the signal is meaningless and we decline to emit it."""
    assert index.find("axi", popularity=1) == []


def test_package_is_never_its_own_squat(index):
    assert not any(f.target == "lodash" for f in index.find("lodash", 50_000_000))


# -- evidence --------------------------------------------------------------


def test_finding_exposes_the_ratio_not_a_verdict(index):
    finding = next(f for f in index.find("lodahs", 1000) if f.target == "lodash")
    assert finding.popularity_ratio == pytest.approx(50_000.0)
    assert finding.candidate_popularity == 1000
    assert finding.target_popularity == 50_000_000


def test_findings_ordered_closest_first(index):
    findings = index.find("lodahs", 10)
    distances = [f.distance for f in findings]
    assert distances == sorted(distances)


def test_find_all_accepts_a_popularity_map(index):
    out = index.find_all({"lodahs": 5, "webpack": 900})
    assert {f.candidate for f in out} == {"lodahs"}


# -- the index is a sound filter, not a guess ------------------------------


def test_deletion_index_never_misses_a_within_distance_pair():
    """The candidate generator may over-generate, but it must not miss.

    Brute force over every pair is the oracle; the index must find everything
    the oracle finds.
    """
    popular = {n: 1_000_000 for n in POPULAR}
    index = TyposquatIndex(popular)
    probes = ["lodahs", "lodas", "expres", "reactt", "chalkk", "debu", "axio", "chak"]
    for probe in probes:
        brute = {
            name
            for name in popular
            if damerau_levenshtein(probe, name.split("/")[-1], 2) <= 2
        }
        got = {f.target for f in index.find(probe, popularity=1)}
        assert brute <= got, f"{probe}: index missed {brute - got}"


# -- regressions found on the real corpus ---------------------------------


def test_unknown_popularity_emits_nothing(index):
    """None means unknown, which is not zero.

    npm's bulk download endpoint declines scoped packages. Reading that
    silence as "zero downloads" made the asymmetry guard pass unconditionally,
    and every scoped package in the corpus was reported as a squat of
    something famous.
    """
    assert index.find("lodahs", popularity=None) == []
    assert index.find("lodahs") == []


def test_scoped_package_is_not_a_squat_of_an_unscoped_one(index):
    """A scope is an account boundary, not decoration.

    These are the exact false positives the first real-corpus run produced:
    every one is a legitimate package whose bare name happens to sit near a
    popular unscoped name.
    """
    for scoped in (
        "@webpack-cli/serve",     # was flagged against 'semver'
        "@colors/colors",         # was flagged against 'color' and 'cors'
        "@types/cors",            # was flagged against 'acorn'
        "@xtuc/long",             # was flagged against 'clone'
    ):
        assert index.find(scoped, popularity=1) == [], scoped


def test_same_scope_comparison_still_works():
    """Scope confusion within one namespace is a real attack and must survive
    the cross-scope rule."""
    idx = TyposquatIndex({"@types/lodash": 9_000_000})
    hits = idx.find("@types/lodahs", popularity=1)
    assert [h.target for h in hits] == ["@types/lodash"]


def test_identical_bare_name_across_scopes_is_still_comparable():
    """@typos/lodash beside @types/lodash is the genuine scope-confusion
    attack, so identical bare names stay comparable across scopes."""
    idx = TyposquatIndex({"@types/lodash": 9_000_000})
    assert idx.find("@typos/lodash", popularity=1)


def test_real_corpus_produces_no_findings():
    """Every package in the generated fleet is legitimate, so a correct
    detector reports nothing. This is the regression that matters: the first
    run produced seven findings and all seven were wrong."""
    legit = {
        "@webpack-cli/serve": 5_000, "@colors/colors": 9_000,
        "@types/cors": 3_000, "@xtuc/long": 1_000, "@types/node": 8_000,
    }
    idx = TyposquatIndex({
        "semver": 700_000_000, "color": 34_000_000, "cors": 50_000_000,
        "acorn": 211_000_000, "once": 128_000_000, "clone": 69_000_000,
    })
    assert idx.find_all(legit) == []
