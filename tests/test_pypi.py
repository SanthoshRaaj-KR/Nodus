"""The PyPI tier: discovery, evidence grading, and the key space.

Two things here are worth more than the rest.

**A lockfile is a record; a requirements file is an instruction.** Resolving
`requirements.txt` tells you what pip would choose today, not what is
installed. Writing that as `RESOLVED_IN` with no distinction would promote a
forecast to the standing of an observation, in the one tool whose whole
argument is that a range which admits a version is not a project that
installed it. So the grade is recorded on the edge and asserted here.

**npm's `requests` and PyPI's `requests` are unrelated projects.** Before the
ecosystem reached the key, PyPI advisories were written through npm's name
rules as `pkg:npm/h11@0.9.0` -- a package that does not exist. The finding
could never attach to the real PyPI node, so it sat in the graph with zero
exposed services and read as merely uninteresting rather than as broken.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.pkg.identity import PYPI, package_key, version_key  # noqa: E402
from blastradius.pkg.pypi import (  # noqa: E402
    LOCKFILES,
    _requested_specs,
    find_requirements,
    resolution_kind,
)


def write(root: Path, rel: str, body: str = "") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# -- the key space ----------------------------------------------------------

def test_the_two_ecosystems_cannot_collide():
    """The bug: `h11` written as an npm package that does not exist."""
    assert package_key("requests", PYPI) != package_key("requests")
    assert package_key("requests", PYPI) == "pkg:pypi/requests"
    assert version_key("h11", "0.9.0", PYPI) == "pkg:pypi/h11@0.9.0"


def test_pep503_names_normalise_to_one_project():
    """`Flask_SQLAlchemy`, `flask-sqlalchemy` and `Flask.SQLAlchemy` are one
    project; keying them apart reports three packages for one install."""
    keys = {
        package_key(name, PYPI)
        for name in ("Flask_SQLAlchemy", "flask-sqlalchemy", "Flask.SQLAlchemy")
    }
    assert len(keys) == 1


# -- discovery --------------------------------------------------------------

def test_finds_requirements_and_lockfiles(tmp_path):
    write(tmp_path, "requirements.txt", "fastapi\n")
    write(tmp_path, "svc/poetry.lock", "")
    found = {p.name for p in find_requirements(tmp_path)}
    assert found == {"requirements.txt", "poetry.lock"}


def test_other_projects_manifests_are_not_ours(tmp_path):
    """A vendored virtualenv is full of requirements files belonging to
    somebody else, and none of them describes this repo."""
    write(tmp_path, "requirements.txt", "fastapi\n")
    write(tmp_path, ".venv/lib/site-packages/pkg/requirements.txt", "evil\n")
    write(tmp_path, "venv/requirements.txt", "evil\n")
    found = find_requirements(tmp_path)
    assert len(found) == 1
    assert found[0].parent == tmp_path


def test_discovery_honours_the_ignore_file(tmp_path):
    write(tmp_path, ".blastradiusignore", "fixtures/\n")
    write(tmp_path, "requirements.txt", "fastapi\n")
    write(tmp_path, "fixtures/requirements.txt", "whatever\n")
    kept, skipped = find_requirements(tmp_path, with_skipped=True)
    assert [p.parent for p in kept] == [tmp_path]
    assert len(skipped) == 1


def test_nothing_python_is_not_an_error(tmp_path):
    assert find_requirements(tmp_path) == []


# -- evidence grading -------------------------------------------------------

@pytest.mark.parametrize("name", LOCKFILES)
def test_a_lock_file_is_locked(name):
    assert resolution_kind(Path("/repo") / name) == "locked"


def test_an_exact_pin_is_pinned():
    assert resolution_kind(Path("requirements.txt"), "==2.31.0") == "pinned"


def test_a_range_is_only_resolved():
    """`>=0.115` does not say what is installed. It says what pip would pick,
    and that answer changes with the date."""
    assert resolution_kind(Path("requirements.txt"), ">=0.115") == "resolved"
    assert resolution_kind(Path("requirements.txt"), "") == "resolved"


def test_a_wildcard_pin_is_not_a_pin():
    """`==1.4.*` is a range wearing an equals sign."""
    assert resolution_kind(Path("requirements.txt"), "==1.4.*") == "resolved"


# -- reading the manifest ---------------------------------------------------

def test_specifiers_are_read_off_the_manifest(tmp_path):
    manifest = write(tmp_path, "requirements.txt", """
        # a comment
        fastapi>=0.115
        uvicorn[standard]>=0.32
        requests==2.31.0
        packaging
        -r other.txt
        httpx>=0.27 ; python_version < "3.11"
    """.replace("        ", ""))
    specs = _requested_specs(manifest)
    assert specs["fastapi"] == ">=0.115"
    assert specs["requests"] == "==2.31.0"
    assert specs["uvicorn"] == ">=0.32"      # extras dropped from the name
    assert specs["packaging"] == ""          # bare requirement
    assert specs["httpx"] == ">=0.27"        # environment marker dropped
    assert "-r" not in specs


def test_an_unreadable_manifest_is_not_fatal(tmp_path):
    """The resolution still stands; it is graded `resolved` rather than
    `pinned` because we could not confirm a pin."""
    missing = tmp_path / "nope.txt"
    assert _requested_specs(missing) == {}


def test_a_name_that_cannot_be_keyed_is_skipped_not_guessed(tmp_path):
    manifest = write(tmp_path, "requirements.txt", "===\nfastapi>=1\n")
    specs = _requested_specs(manifest)
    assert "fastapi" in specs
    assert len(specs) == 1
