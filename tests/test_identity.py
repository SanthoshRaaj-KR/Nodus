"""Identity and normalisation tests.

The property under test throughout: two spellings of the same thing must
produce one key, and two different things must never collide. A failure of the
first splits a blast radius silently; a failure of the second merges unrelated
packages, which is worse.
"""

from __future__ import annotations

import pytest

from blastradius.pkg.identity import (
    InvalidPackageName,
    maintainer_key,
    normalize_name,
    normalize_repo_url,
    organization_key,
    package_key,
    parse_purl,
    repository_key,
    split_scope,
    version_key,
)


# -- names -----------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("lodash", "lodash"),
        ("LoDash", "lodash"),
        ("  lodash  ", "lodash"),
        ("@angular/core", "@angular/core"),
        ("@Angular/Core", "@angular/core"),
        ("node-fetch", "node-fetch"),
        ("a.b.c", "a.b.c"),
        ("under_score", "under_score"),
    ],
)
def test_normalize_name(raw, expected):
    assert normalize_name(raw) == expected


@pytest.mark.parametrize(
    "raw", ["", "   ", ".hidden", "_private", "a/b/c", "has space", "x" * 215]
)
def test_normalize_name_rejects(raw):
    with pytest.raises(InvalidPackageName):
        normalize_name(raw)


def test_case_folding_merges_rather_than_splits():
    # The whole point: these must be one node, not two.
    assert package_key("LoDash") == package_key("lodash")
    assert version_key("LoDash", "4.17.21") == version_key("lodash", "4.17.21")


def test_split_scope():
    assert split_scope("@angular/core") == ("@angular", "core")
    assert split_scope("lodash") == (None, "lodash")


# -- purls -----------------------------------------------------------------


@pytest.mark.parametrize(
    "name,version,expected",
    [
        ("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
        ("@angular/core", "17.0.0", "pkg:npm/%40angular/core@17.0.0"),
        ("node-fetch", "2.6.7", "pkg:npm/node-fetch@2.6.7"),
        ("lodash", "5.0.0-beta.1", "pkg:npm/lodash@5.0.0-beta.1"),
    ],
)
def test_version_key(name, version, expected):
    assert version_key(name, version) == expected


def test_package_key_scoped():
    assert package_key("@angular/core") == "pkg:npm/%40angular/core"


@pytest.mark.parametrize(
    "name,version",
    [
        ("lodash", "4.17.21"),
        ("@angular/core", "17.0.0"),
        ("@types/node", "20.1.0"),
    ],
)
def test_purl_roundtrip(name, version):
    parsed = parse_purl(version_key(name, version))
    assert parsed.ecosystem == "npm"
    assert parsed.name == normalize_name(name)
    assert parsed.version == version


def test_parse_purl_without_version():
    parsed = parse_purl(package_key("@angular/core"))
    assert parsed.name == "@angular/core"
    assert parsed.version is None


def test_version_string_is_not_rewritten():
    # Identity must be the literal published string, or the join back to the
    # registry and the lockfile breaks.
    assert version_key("lodash", "4.17.21+build.7").endswith("@4.17.21+build.7")


def test_empty_version_rejected():
    with pytest.raises(InvalidPackageName):
        version_key("lodash", "")


# -- repositories ----------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "git+https://github.com/lodash/lodash.git",
        "git://github.com/lodash/lodash.git",
        "https://github.com/lodash/lodash",
        "https://github.com/lodash/lodash.git",
        "ssh://git@github.com/lodash/lodash.git",
        "git@github.com:lodash/lodash.git",
        "github:lodash/lodash",
        "lodash/lodash",
        "https://github.com/lodash/lodash/",
        "git+https://github.com/lodash/lodash.git#main",
    ],
)
def test_repo_spellings_collapse_to_one_key(raw):
    """Every way npm spells one repository must reduce to one node.

    This is the shared-infrastructure signal's accuracy: a breached CI pipeline
    publishes several packages whose manifests spell the repo differently.
    """
    assert repository_key(raw) == "repo:github.com/lodash/lodash"


def test_repo_case_folded():
    assert repository_key("https://github.com/LoDash/LoDash") == (
        "repo:github.com/lodash/lodash"
    )


def test_distinct_repos_do_not_collide():
    a = repository_key("https://github.com/expressjs/express")
    b = repository_key("https://github.com/expressjs/body-parser")
    c = repository_key("https://gitlab.com/expressjs/express")
    assert len({a, b, c}) == 3


@pytest.mark.parametrize("raw", [None, "", "   ", "not a url", "https://example.com"])
def test_unresolvable_repo_is_none_not_a_guess(raw):
    assert repository_key(raw) is None


def test_repo_ref_fields():
    ref = normalize_repo_url("git+https://github.com/lodash/lodash.git")
    assert (ref.host, ref.owner, ref.name) == ("github.com", "lodash", "lodash")
    assert ref.url == "https://github.com/lodash/lodash"


# -- people ----------------------------------------------------------------


def test_maintainer_keyed_on_username_not_email():
    """An attacker changing the email on a hijacked account must not become a
    different node."""
    assert maintainer_key("jdalton", "old@example.com") == maintainer_key(
        "jdalton", "new@example.com"
    )


def test_maintainer_case_folded():
    assert maintainer_key("JDalton") == maintainer_key("jdalton")


def test_maintainer_falls_back_to_email():
    assert maintainer_key(None, "a@b.com") == "email:a@b.com"
    assert maintainer_key(None, "not-an-email") is None
    assert maintainer_key(None, None) is None


def test_organization_key_folds_scope_marker():
    assert organization_key("@angular") == organization_key("angular")
