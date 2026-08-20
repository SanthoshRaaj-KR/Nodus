"""PEP 440, checked against the reference implementation where it exists.

`packaging` is not a dependency of this project -- pulling one in to read
version strings would be a poor trade -- so :mod:`blastradius.pkg.pep440` is
written by hand. That makes "is it actually right" the only question worth
asking about it, and the answer is not "the author thought so": when
`packaging` happens to be importable the whole cross-product of a version
corpus is compared against it, and the differential test is what found the two
bugs the hand-written unit tests below did not.

Both were rules that are not derivable from the ordering:

* ``>1.0`` must NOT match ``1.0.post1``. A post-release is the same release
  with corrected packaging, so "greater than 1.0" does not admit it -- even
  though it sorts above. The mirror rule holds for ``<`` and pre-releases.
* A specifier "asks for" pre-releases only when its own operand is one. The
  first version fell back to the version under test when an operand would not
  parse, so ``!=1.0.*`` looked like it wanted pre-releases and ``2.0.dev1``
  passed a specifier that must exclude it.

The unit tests are kept as well as the differential one, because they run
everywhere and they say what the behaviour is meant to be rather than only
that two implementations agree.
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.pkg.pep440 import (  # noqa: E402
    compare,
    latest,
    matches,
    parse,
    satisfies,
    sort_versions,
)


# -- parsing ----------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "1.0", "1.0.0", "v1.0", " 1.0 ", "1!1.0", "1.0rc1", "1.0.post1",
    "1.0.dev1", "1.0a1", "1.0b2", "1.0+local", "1.0.0.0",
])
def test_readable_versions_parse(text):
    assert parse(text) is not None


@pytest.mark.parametrize("text", ["", "not-a-version", "abc", None, "1.0.x"])
def test_unreadable_versions_are_none_not_zero(text):
    """Unknown is not zero. A version we cannot read must not silently sort
    below everything and land in a range it was never assessed against."""
    assert parse(text) is None


def test_pre_release_spellings_are_one_version():
    for text in ("1.0rc1", "1.0.rc.1", "1.0-rc-1", "1.0c1", "1.0preview1"):
        assert compare(text, "1.0rc1") == 0, text


# -- ordering ---------------------------------------------------------------

@pytest.mark.parametrize("a, b, expected", [
    ("1.0", "1.0.0", 0),        # trailing zeros are not a difference
    ("1.0", "1.0.0.0", 0),
    ("1.0", "1.0.1", -1),
    ("1.9", "1.10", -1),        # not string order
    ("1.0.dev1", "1.0", -1),    # dev precedes its release
    ("1.0rc1", "1.0", -1),      # so does a pre-release
    ("1.0", "1.0.post1", -1),   # a post-release follows it
    ("1.0a1", "1.0b2", -1),
    ("1.0b2", "1.0rc1", -1),
    ("1.0rc1.dev1", "1.0rc1", -1),
    ("2.0", "1!1.0", -1),       # an epoch outranks everything below it
])
def test_ordering(a, b, expected):
    assert compare(a, b) == expected
    assert compare(b, a) == -expected


def test_comparing_an_unreadable_version_is_unknown():
    assert compare("junk", "1.0") is None
    assert compare("1.0", "junk") is None


def test_sorting_drops_what_it_cannot_read():
    assert sort_versions(["1.10", "junk", "1.9", "1.0"]) == ["1.0", "1.9", "1.10"]


def test_latest_skips_prereleases():
    assert latest(["1.0", "2.0.dev1", "1.5"]) == "1.5"
    assert latest(["1.0", "2.0.dev1", "1.5"], allow_prerelease=True) == "2.0.dev1"


def test_latest_of_only_prereleases_is_a_prerelease():
    """A package that has only ever shipped alphas still has a newest one."""
    assert latest(["1.0a1", "1.0a2"]) == "1.0a2"


def test_latest_of_nothing_is_none():
    assert latest([]) is None


# -- specifiers -------------------------------------------------------------

@pytest.mark.parametrize("version, spec, expected", [
    ("2.31.0", ">=2.0,<3.0", True),
    ("3.0.0", ">=2.0,<3.0", False),
    ("1.4.5", "~=1.4.2", True),      # compatible release, patch level
    ("1.5.0", "~=1.4.2", False),
    ("1.5.0", "~=1.4", True),        # ...and minor level
    ("2.0.0", "~=1.4", False),
    ("1.4.9", "==1.4.*", True),
    ("1.5.0", "==1.4.*", False),
    ("1.5.0", "!=1.4.*", True),
    ("1.0", "===1.0", True),
    ("1.0.0", "===1.0", False),      # `===` is a string comparison by design
    ("3.9.0", "", True),             # a bare requirement admits anything
])
def test_specifiers(version, spec, expected):
    assert satisfies(version, spec) is expected


def test_a_post_release_is_not_greater_than_its_release():
    """PEP 440's exclusive-comparison rule, and not derivable from ordering:
    1.0.post1 sorts above 1.0, but `>1.0` means "a later release"."""
    assert matches("1.0.post1", ">1.0") is False
    assert matches("1.0.0.post1", ">1.0") is False    # same, more segments
    assert matches("1.0.post1", ">1.0.post0") is True  # operand is a post too


def test_a_prerelease_is_not_less_than_its_release():
    assert matches("1.0rc1", "<1.0") is False
    assert matches("1.0rc1", "<1.0rc2") is True


def test_prereleases_are_excluded_unless_the_specifier_wants_them():
    assert satisfies("2.0.dev1", ">=1.0") is False
    assert satisfies("2.0.dev1", ">=1.0.dev0") is True
    # The bug: a wildcard operand does not parse, and must not be read as
    # "this clause wants pre-releases".
    assert satisfies("2.0.dev1", "!=1.0.*") is False


def test_an_unreadable_clause_is_unknown_not_false():
    """Neither over- nor under-reporting: the caller has to be told the
    difference between "does not match" and "could not be assessed"."""
    assert satisfies("1.0", ">=nonsense") is None
    assert satisfies("junk", ">=1.0") is None
    assert matches("1.0", "?? 1.0") is None


def test_a_wildcard_with_an_ordering_operator_is_not_valid():
    assert matches("1.0", ">=1.4.*") is None


def test_tilde_needs_two_segments():
    """`~=1` has no defined meaning -- there is no segment to hold constant."""
    assert matches("1.5", "~=1") is None


# -- differential, where the reference is available -------------------------

packaging = pytest.importorskip("packaging.version", reason="packaging absent")

CORPUS_BASE = [
    "0.9", "1.0", "1.0.0", "1.0.1", "1.1", "1.4.2", "1.4.9", "1.5.0",
    "1.9", "1.10", "2.0", "2.31.0", "3.15", "0.16.0",
]
CORPUS_SUFFIX = ["", "rc1", "a1", "b2", ".post1", ".post2", ".dev1", "rc1.dev1"]
CORPUS = sorted({b + s for b in CORPUS_BASE for s in CORPUS_SUFFIX})


def test_ordering_matches_packaging_exactly():
    from packaging.version import Version as Ref

    disagreements = []
    for a, b in itertools.combinations(CORPUS, 2):
        mine = compare(a, b)
        ref = (Ref(a) > Ref(b)) - (Ref(a) < Ref(b))
        if mine != ref:
            disagreements.append((a, b, mine, ref))
    assert not disagreements, disagreements[:5]


def test_specifiers_match_packaging_exactly():
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version as Ref

    operators = ["==", "!=", "<=", ">=", "<", ">", "~="]
    specs = [f"{op}{v}" for op in operators for v in CORPUS_BASE]
    specs += ["==1.4.*", "!=1.0.*", ">=1.0,<2.0", ">0.9,<=2.0",
              "~=1.4.2", ">=1.0rc1", "<2.0.dev1"]

    disagreements = []
    for version in CORPUS:
        for spec in specs:
            try:
                ref = Ref(version) in SpecifierSet(spec)
            except Exception:
                continue  # packaging rejects it; we make no claim
            mine = satisfies(version, spec)
            if mine is not None and mine != ref:
                disagreements.append((version, spec, mine, ref))
    assert not disagreements, disagreements[:5]
