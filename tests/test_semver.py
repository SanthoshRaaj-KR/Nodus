"""Semver conformance tests.

Cases are taken from the node-semver documented behaviour, weighted towards
the ones that produce *wrong security findings* when implemented naively:
the 0.x caret rules, partial x-ranges under an operator, and the prerelease
containment rule.
"""

from __future__ import annotations

import pytest

from blastradius.pkg import semver
from blastradius.pkg.semver import (
    InvalidRange,
    InvalidVersion,
    filter_satisfying,
    max_satisfying,
    parse,
    satisfies,
)


# -- parsing ---------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("1.2.3", (1, 2, 3, "")),
        ("v1.2.3", (1, 2, 3, "")),
        (" 1.2.3 ", (1, 2, 3, "")),
        ("=1.2.3", (1, 2, 3, "")),
        ("1.2.3-alpha", (1, 2, 3, "alpha")),
        ("1.2.3-alpha.1", (1, 2, 3, "alpha.1")),
        ("1.2.3-0", (1, 2, 3, "0")),
        ("1.2.3+build.5", (1, 2, 3, "")),
        ("1.2.3-rc.1+build.5", (1, 2, 3, "rc.1")),
        ("0.0.0", (0, 0, 0, "")),
    ],
)
def test_parse_valid(text, expected):
    v = parse(text)
    assert (v.major, v.minor, v.patch, v.prerelease) == expected


@pytest.mark.parametrize(
    "text", ["1.2", "1", "", "1.2.3.4", "a.b.c", "01.2.3", "1.2.3-", "-1.2.3"]
)
def test_parse_invalid(text):
    with pytest.raises(InvalidVersion):
        parse(text)


# -- ordering --------------------------------------------------------------


def test_ordering_basic():
    order = ["1.0.0", "1.0.1", "1.1.0", "2.0.0", "10.0.0"]
    parsed = [parse(v) for v in order]
    assert parsed == sorted(parsed)


def test_prerelease_sorts_below_release():
    assert parse("1.0.0-alpha") < parse("1.0.0")
    assert parse("1.0.0-rc.1") < parse("1.0.0")


def test_prerelease_ordering_spec_example():
    # The canonical ordering from semver.org section 11.
    order = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    ]
    parsed = [parse(v) for v in order]
    assert parsed == sorted(parsed), [str(v) for v in sorted(parsed)]


def test_numeric_identifier_sorts_below_alphanumeric():
    assert parse("1.0.0-1") < parse("1.0.0-alpha")


def test_longer_prerelease_wins_on_equal_prefix():
    assert parse("1.0.0-a") < parse("1.0.0-a.1")


def test_build_metadata_ignored_in_comparison():
    assert not (parse("1.0.0+a") < parse("1.0.0+b"))
    assert not (parse("1.0.0+b") < parse("1.0.0+a"))


# -- caret -----------------------------------------------------------------


@pytest.mark.parametrize(
    "rng,version,ok",
    [
        ("^1.2.3", "1.2.3", True),
        ("^1.2.3", "1.9.9", True),
        ("^1.2.3", "2.0.0", False),
        ("^1.2.3", "1.2.2", False),
        # 0.x: minor is the breaking axis
        ("^0.2.3", "0.2.4", True),
        ("^0.2.3", "0.3.0", False),
        ("^0.2.3", "0.2.2", False),
        # 0.0.x: patch is the breaking axis
        ("^0.0.3", "0.0.3", True),
        ("^0.0.3", "0.0.4", False),
        # partials
        ("^1.2.x", "1.9.0", True),
        ("^1.2.x", "2.0.0", False),
        ("^0.0.x", "0.0.9", True),
        ("^0.0.x", "0.1.0", False),
        ("^0.0", "0.0.9", True),
        ("^0.0", "0.1.0", False),
        ("^1.x", "1.9.9", True),
        ("^1.x", "2.0.0", False),
        ("^0", "0.9.9", True),
        ("^0", "1.0.0", False),
    ],
)
def test_caret(rng, version, ok):
    assert satisfies(version, rng) is ok, f"{version} vs {rng}"


# -- tilde -----------------------------------------------------------------


@pytest.mark.parametrize(
    "rng,version,ok",
    [
        ("~1.2.3", "1.2.3", True),
        ("~1.2.3", "1.2.99", True),
        ("~1.2.3", "1.3.0", False),
        ("~1.2.3", "1.2.2", False),
        ("~1.2", "1.2.0", True),
        ("~1.2", "1.3.0", False),
        ("~1", "1.9.9", True),
        ("~1", "2.0.0", False),
        ("~0.2.3", "0.2.9", True),
        ("~0.2.3", "0.3.0", False),
    ],
)
def test_tilde(rng, version, ok):
    assert satisfies(version, rng) is ok, f"{version} vs {rng}"


# -- x-ranges and operators ------------------------------------------------


@pytest.mark.parametrize(
    "rng,version,ok",
    [
        ("*", "1.2.3", True),
        ("", "1.2.3", True),
        ("x", "9.9.9", True),
        ("1.x", "1.5.0", True),
        ("1.x", "2.0.0", False),
        ("1.2.x", "1.2.9", True),
        ("1.2.x", "1.3.0", False),
        ("1.2.3", "1.2.3", True),
        ("1.2.3", "1.2.4", False),
        (">=1.2.3", "1.2.3", True),
        (">=1.2.3", "9.9.9", True),
        (">1.2.3", "1.2.3", False),
        ("<=1.2.3", "1.2.3", True),
        ("<1.2.3", "1.2.3", False),
        ("<1.2.3", "1.2.2", True),
        # ">1.x" excludes the whole 1 line, not just 1.0.0
        (">1.x", "1.9.9", False),
        (">1.x", "2.0.0", True),
        ("<2.x", "1.9.9", True),
        ("<2.x", "2.0.0", False),
        ("<=1.x", "1.9.9", True),
        ("<=1.x", "2.0.0", False),
    ],
)
def test_xranges_and_operators(rng, version, ok):
    assert satisfies(version, rng) is ok, f"{version} vs {rng}"


# -- compound ranges -------------------------------------------------------


@pytest.mark.parametrize(
    "rng,version,ok",
    [
        (">=1.2.3 <2.0.0", "1.5.0", True),
        (">=1.2.3 <2.0.0", "2.0.0", False),
        ("1.2.3 || 2.3.4", "1.2.3", True),
        ("1.2.3 || 2.3.4", "2.3.4", True),
        ("1.2.3 || 2.3.4", "1.5.0", False),
        ("^1.0.0 || ^2.0.0", "2.5.0", True),
        ("^1.0.0 || ^2.0.0", "3.0.0", False),
        ("<1.0.0 || >=2.0.0", "1.5.0", False),
    ],
)
def test_compound(rng, version, ok):
    assert satisfies(version, rng) is ok, f"{version} vs {rng}"


# -- hyphen ranges ---------------------------------------------------------


@pytest.mark.parametrize(
    "rng,version,ok",
    [
        ("1.2.3 - 2.3.4", "1.2.3", True),
        ("1.2.3 - 2.3.4", "2.3.4", True),
        ("1.2.3 - 2.3.4", "2.3.5", False),
        ("1.2.3 - 2.3.4", "1.2.2", False),
        # partial upper bound widens to the end of its window
        ("1.2.3 - 2.3", "2.3.9", True),
        ("1.2.3 - 2.3", "2.4.0", False),
        ("1.2.3 - 2", "2.9.9", True),
        ("1.2.3 - 2", "3.0.0", False),
        # partial lower bound
        ("1.2 - 2.3.4", "1.2.0", True),
    ],
)
def test_hyphen(rng, version, ok):
    assert satisfies(version, rng) is ok, f"{version} vs {rng}"


# -- the prerelease containment rule --------------------------------------
# This is the block that matters most for false positives.


def test_plain_range_never_admits_prerelease():
    assert satisfies("1.2.3-alpha", "^1.0.0") is False
    assert satisfies("1.2.3-alpha", ">=1.0.0") is False
    assert satisfies("1.2.3-alpha", "*") is False


def test_prerelease_admitted_only_on_matching_tuple():
    # Same tuple as a prerelease comparator -> admitted.
    assert satisfies("1.2.3-beta", ">=1.2.3-alpha <2.0.0") is True
    # Higher tuple, no prerelease comparator at that tuple -> refused, even
    # though it sorts above the lower bound. This is the rule that stops a
    # range from silently over-matching every future prerelease.
    assert satisfies("3.4.5-beta", ">=1.2.3-alpha <9.0.0") is False


def test_prerelease_below_its_release_is_excluded():
    assert satisfies("1.2.3-rc.1", "^1.2.3") is False
    assert satisfies("1.2.3", "^1.2.3") is True


def test_include_prerelease_opt_in():
    assert satisfies("3.4.5-beta", ">=1.2.3-alpha <9.0.0", include_prerelease=True)
    assert satisfies("1.2.3-alpha", "^1.0.0", include_prerelease=True)


# -- non-registry ranges are refused, not guessed --------------------------


@pytest.mark.parametrize(
    "spec",
    [
        "git://github.com/user/repo.git",
        "git+https://github.com/user/repo",
        "file:../local",
        "link:../local",
        "https://example.com/pkg.tgz",
        "workspace:*",
        "user/repo",
    ],
)
def test_non_registry_specs_rejected(spec):
    # Treating these as '*' would attach every version in the graph to the
    # edge, which is the single most damaging over-match available.
    with pytest.raises(InvalidRange):
        semver.parse_range(spec)


# -- the helpers the ingest pipeline uses ---------------------------------


def test_filter_satisfying_sorted_and_exact():
    versions = ["4.17.19", "4.17.20", "4.17.21", "4.17.22", "5.0.0", "3.9.0"]
    got = [str(v) for v in filter_satisfying(versions, "^4.17.20")]
    assert got == ["4.17.20", "4.17.21", "4.17.22"]


def test_filter_satisfying_skips_unparseable_without_raising():
    versions = ["1.0.0", "not-a-version", "1.1.0"]
    got = [str(v) for v in filter_satisfying(versions, "^1.0.0")]
    assert got == ["1.0.0", "1.1.0"]


def test_max_satisfying_picks_what_npm_would():
    versions = ["4.17.19", "4.17.20", "4.17.21", "5.0.0"]
    assert str(max_satisfying(versions, "^4.0.0")) == "4.17.21"
    assert max_satisfying(versions, "^9.0.0") is None


def test_version_awareness_negative_control():
    """The property the whole tool rests on.

    A compromised 4.17.21 must not condemn 4.17.20 or 4.17.22, and a range
    that admits all three must still be reported as admitting all three --
    exposure is decided by resolution, not by the range alone.
    """
    versions = ["4.17.20", "4.17.21", "4.17.22"]
    admitted = {str(v) for v in filter_satisfying(versions, "^4.17.0")}
    assert admitted == {"4.17.20", "4.17.21", "4.17.22"}
    assert satisfies("4.17.20", "=4.17.21") is False
    assert satisfies("4.17.22", "=4.17.21") is False
    assert satisfies("4.17.21", "=4.17.21") is True


@pytest.mark.parametrize("spec", ["!=1.2.3", "!==1.2.3", "===1.2.3"])
def test_unsupported_comparators_refused(spec):
    """node-semver throws `Invalid comparator` on these.

    Accepting them would make us disagree with the resolver that actually
    writes the lockfile, so we refuse rather than invent a meaning.
    """
    with pytest.raises(InvalidRange):
        semver.parse_range(spec)


def test_derived_upper_bound_carries_zero_sentinel():
    """`^1.2.3` must expand to `<2.0.0-0`, not `<2.0.0`.

    The sentinel is what keeps `2.0.0-alpha` -- often the first publish of a
    compromised next major -- outside the range even under includePrerelease.
    """
    rng = semver.parse_range("^1.2.3")
    uppers = [c for group in rng.sets for c in group if c.op == "<"]
    assert len(uppers) == 1
    assert str(uppers[0].version) == "2.0.0-0"
    assert satisfies("2.0.0-alpha", "^1.2.3", include_prerelease=True) is False
