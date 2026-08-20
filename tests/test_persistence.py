"""Persistence: the half of the compromise that outlives the package.

The brief's most distinctive detail is that the worm wrote into `.claude/`
and `.vscode/` and therefore **survived `npm uninstall`**. Everything else
this project reports is exposure, and removing the package resolves it. An
artifact on disk is evidence, and removing the package resolves none of it.

The bug these tests were written around: `scan_service` was only ever called
with the *service* directory -- the one holding `package-lock.json`. In any
repository whose lockfile is not at the top, that is `packages/foo/`, while
`.claude/` sits several levels above it at the checkout root. Against this
repository the scan looked in `scanner/` and `ui/web/`, found nothing, and
reported a clean bill of health while a root-level artifact sat unread.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.ingest.persistence import (  # noqa: E402
    WATCHED_DIRS,
    scan_service,
)
from blastradius.query.codereach import Artifact  # noqa: E402


def plant(root: Path, rel: str, body: str = "{}") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# -- detection --------------------------------------------------------------

@pytest.mark.parametrize("watched", WATCHED_DIRS)
def test_every_watched_directory_is_scanned(tmp_path, watched):
    """Each one is named in the brief or is the same trick by another name."""
    plant(tmp_path, f"{watched}/thing.json")
    found = scan_service(tmp_path)
    assert [a.path for a in found] == [f"{watched}/thing.json"]
    assert found[0].kind == "watched-dir"


def test_a_file_outside_a_watched_directory_is_not_reported(tmp_path):
    plant(tmp_path, "src/index.js")
    plant(tmp_path, "package.json")
    assert scan_service(tmp_path) == []


def test_nested_files_are_found(tmp_path):
    plant(tmp_path, ".claude/agents/deep/thing.md")
    assert len(scan_service(tmp_path)) == 1


def test_the_hash_identifies_the_content(tmp_path):
    plant(tmp_path, ".vscode/a.json", "alpha")
    plant(tmp_path, ".vscode/b.json", "alpha")
    plant(tmp_path, ".vscode/c.json", "beta")
    by_path = {a.path: a.sha256 for a in scan_service(tmp_path)}
    assert by_path[".vscode/a.json"] == by_path[".vscode/b.json"]
    assert by_path[".vscode/c.json"] != by_path[".vscode/a.json"]


def test_ioc_path_outranks_a_watched_directory(tmp_path):
    """An advisory naming the file is a different claim from "it is in the
    directory", and the kind has to say which."""
    plant(tmp_path, "tools/hook.js")
    found = scan_service(tmp_path, ioc_paths=["tools/*.js"])
    assert [a.kind for a in found] == ["ioc-path"]


def test_an_empty_repo_reports_nothing_rather_than_failing(tmp_path):
    assert scan_service(tmp_path) == []


def test_a_missing_root_does_not_raise(tmp_path):
    assert scan_service(tmp_path / "does-not-exist") == []


# -- the root-vs-service bug ------------------------------------------------

def test_root_level_persistence_is_invisible_from_the_service_directory(tmp_path):
    """The bug, pinned as a fact about the layout rather than the fix.

    A monorepo puts the lockfile in a subdirectory and `.claude/` at the top.
    Scanning only the service directory cannot see it, which is why the
    ingest scans both.
    """
    plant(tmp_path, "packages/api/package-lock.json")
    plant(tmp_path, ".claude/settings.json")

    service_dir = tmp_path / "packages" / "api"
    assert scan_service(service_dir) == []          # the old behaviour
    assert len(scan_service(tmp_path)) == 1         # what the root sees


def test_scanning_both_does_not_double_report(tmp_path):
    """A lockfile at the root means service dir == root; the ingest
    de-duplicates on the artifact key so it is reported once."""
    plant(tmp_path, "package-lock.json")
    plant(tmp_path, ".claude/settings.json")

    from_service = scan_service(tmp_path)
    from_root = scan_service(tmp_path)
    keys = {a.key for a in from_service} | {a.key for a in from_root}
    assert len(keys) == 1


# -- the query-layer shape --------------------------------------------------

def test_watched_dir_is_derived_from_the_path():
    a = Artifact(path=".claude/agents/x.md", kind="watched-dir",
                 sha256="abc123def456", service="svc", first_seen=1)
    assert a.watched_dir == ".claude"


def test_a_path_that_merely_starts_the_same_is_not_a_watched_dir():
    """`.clauded/` is not `.claude/`, and a prefix test would say it was."""
    a = Artifact(path=".clauded/x.md", kind="watched-dir",
                 sha256="abc", service="svc", first_seen=1)
    assert a.watched_dir == ""


def test_artifact_dict_carries_a_short_hash_for_display():
    a = Artifact(path=".vscode/x", kind="watched-dir",
                 sha256="0123456789abcdef", service="svc", first_seen=7)
    payload = a.to_dict()
    assert payload["short_sha"] == "0123456789ab"
    assert payload["sha256"] == "0123456789abcdef"
    assert payload["watched_dir"] == ".vscode"
