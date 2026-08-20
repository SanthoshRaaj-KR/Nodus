"""What a scan is allowed to treat as this project's code.

The bug behind this module: pointed at its own repository, discovery found
fifteen `package-lock.json` files, twelve of which were a synthetic demo
corpus and one a parser fixture. The graph then reported a fleet of fifteen
services for a project that ships two, and every derived number -- exposure
counts, "N of M threats reach code", blast radius membership -- was denominated
in that wrong fleet.

The subtle half is the CLI, which points *at* the corpus deliberately. A naive
"skip anything called corpus" rule would make that demo silently scan nothing,
which is the same class of failure with the sign flipped. Hence root-relative
patterns, and hence the test below that pins it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.ingest.ignore import (  # noqa: E402
    ALWAYS_IGNORED,
    IGNORE_FILE,
    is_ignored,
    load_ignores,
    split_ignored,
)
from blastradius.ingest.lockfile import find_lockfiles  # noqa: E402


@pytest.fixture
def repo(tmp_path):
    """A repo with a real service, a demo corpus and a fixture."""
    for rel in (
        "svc/package-lock.json",
        "web/package-lock.json",
        "corpus/fleet/a/package-lock.json",
        "corpus/fleet/b/package-lock.json",
        "tests/fixtures/package-lock.json",
        "svc/node_modules/dep/package-lock.json",
    ):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    return tmp_path


def write_ignore(root, text):
    (root / IGNORE_FILE).write_text(text, encoding="utf-8")


# -- loading ----------------------------------------------------------------

def test_missing_file_is_not_an_error(tmp_path):
    """Most repos have never heard of this tool and must still scan."""
    assert load_ignores(tmp_path) == ()


def test_structural_exclusions_apply_without_a_file(tmp_path):
    """`node_modules` and `.git` are not a choice and need no configuration."""
    assert is_ignored(tmp_path / "a" / "node_modules" / "x.json", tmp_path)
    assert is_ignored(tmp_path / ".git" / "x.json", tmp_path)
    assert not is_ignored(tmp_path / "svc" / "x.json", tmp_path)


def test_structural_exclusions_are_not_reported_as_choices(tmp_path):
    """They would bury the entries a human needs under hundreds they do not.

    A real repo with installed dependencies holds a lockfile under every
    package in node_modules. Listing those as "ignored" makes the report
    useless for its one job: explaining why a service is missing.
    """
    assert "node_modules" not in load_ignores(tmp_path)


def test_comments_and_blanks_are_skipped(tmp_path):
    write_ignore(tmp_path, "# a comment\n\n  corpus/  \nvendor  # trailing\n")
    patterns = load_ignores(tmp_path)
    assert "corpus" in patterns
    assert "vendor" in patterns
    assert not any(p.startswith("#") for p in patterns)
    assert "" not in patterns


def test_patterns_are_deduplicated(tmp_path):
    write_ignore(tmp_path, "node_modules\ncorpus/\ncorpus\n")
    patterns = load_ignores(tmp_path)
    assert patterns.count("node_modules") == 1
    assert patterns.count("corpus") == 1


def test_unreadable_file_falls_back_to_defaults(tmp_path):
    # A directory where the file should be: reading raises, and a scan must
    # degrade to the structural defaults rather than refuse to run.
    (tmp_path / IGNORE_FILE).mkdir()
    assert load_ignores(tmp_path) == ()
    assert is_ignored(tmp_path / "node_modules" / "x", tmp_path)


# -- matching ---------------------------------------------------------------

def test_root_relative_pattern_matches_from_the_top(tmp_path):
    patterns = ("corpus",)
    assert is_ignored(tmp_path / "corpus" / "a" / "x.json", tmp_path, patterns)


def test_matching_is_on_components_not_substrings():
    """`corpus` must not hide `corpus-tools/`.

    A substring test would silently drop a real service whose name merely
    began the same way -- the failure would look like the service not existing.
    """
    root = Path("/r")
    assert not is_ignored(Path("/r/corpus-tools/package-lock.json"), root, ("corpus",))
    assert is_ignored(Path("/r/corpus/package-lock.json"), root, ("corpus",))


def test_slashed_pattern_is_anchored_to_the_root():
    root = Path("/r")
    patterns = ("tests/fixtures",)
    assert is_ignored(Path("/r/tests/fixtures/package-lock.json"), root, patterns)
    # The same two components deeper down are a different directory.
    assert not is_ignored(
        Path("/r/pkg/tests/fixtures/package-lock.json"), root, patterns
    )


def test_bare_pattern_matches_at_any_depth():
    root = Path("/r")
    assert is_ignored(Path("/r/a/b/node_modules/c/x.json"), root, ("node_modules",))


def test_a_path_outside_the_root_is_not_judged():
    assert not is_ignored(Path("/elsewhere/x.json"), Path("/r"), ("elsewhere",))


def test_empty_pattern_matches_nothing():
    assert not is_ignored(Path("/r/a/x.json"), Path("/r"), ("",))


# -- the CLI's own demo -----------------------------------------------------

def test_pointing_at_an_ignored_directory_still_scans_it(repo):
    """The inverted failure: a demo that silently scans nothing.

    `blastradius.pkg.cli ingest` points at `corpus/` on purpose. Patterns are
    resolved against the *scan root*, so `corpus/` in the repo-root ignore
    file cannot hide the corpus from a scan whose root IS the corpus.
    """
    write_ignore(repo, "corpus/\ntests/fixtures/\n")
    assert len(find_lockfiles(repo)) == 2                 # svc, web
    assert len(find_lockfiles(repo / "corpus")) == 2      # a, b -- still found


# -- discovery --------------------------------------------------------------

def test_find_lockfiles_applies_the_ignore_file(repo):
    write_ignore(repo, "corpus/\ntests/fixtures/\n")
    found = {p.relative_to(repo).as_posix() for p in find_lockfiles(repo)}
    assert found == {"svc/package-lock.json", "web/package-lock.json"}


def test_find_lockfiles_reports_what_it_skipped(repo):
    """A scan that silently dropped twelve manifests looks like a small repo."""
    write_ignore(repo, "corpus/\ntests/fixtures/\n")
    kept, skipped = find_lockfiles(repo, with_skipped=True)
    assert len(kept) == 2
    # 2 corpus + 1 fixture. node_modules is always excluded and is not
    # reported as a deliberate choice, because nobody chose it.
    assert len(skipped) == 3
    assert all("node_modules" not in p.parts for p in skipped)


def test_node_modules_is_excluded_with_no_ignore_file(repo):
    found = find_lockfiles(repo)
    assert all("node_modules" not in p.parts for p in found)
    # Everything else is still there without a file: ignoring is opt-in.
    assert len(found) == 5


def test_with_skipped_false_returns_a_plain_list(repo):
    assert isinstance(find_lockfiles(repo), list)


def test_split_ignored_drops_structural_from_both_halves(repo):
    """node_modules appears in neither list -- it is not a reported choice."""
    paths = list(repo.rglob("package-lock.json"))
    kept, skipped = split_ignored(paths, repo, ("corpus",))
    assert all("corpus" in p.parts for p in skipped)
    assert all("node_modules" not in p.parts for p in kept + skipped)
    # One of the six on disk is under node_modules and is accounted for by
    # neither half.
    assert len(kept) + len(skipped) == len(paths) - 1


def test_an_ignore_file_that_hides_everything_is_visible_not_silent(repo):
    """Zero lockfiles by configuration must be distinguishable from zero on
    disk -- the caller gets the skipped list to say which happened."""
    write_ignore(repo, "svc/\nweb/\ncorpus/\ntests/\n")
    kept, skipped = find_lockfiles(repo, with_skipped=True)
    assert kept == []
    assert len(skipped) == 5
