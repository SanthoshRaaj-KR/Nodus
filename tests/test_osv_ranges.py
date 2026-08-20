"""Which range of an advisory a scanned version actually falls in.

The bug: `_extract_details` read `vuln["affected"][0]` and reported its events
whatever version was installed. An advisory covering a package's 2.x, 5.x and
8.x lines carries one `affected` entry per line, so scanning `vite@5.4.21`
reported *"introduced 8.0.0, fixed 8.0.5"* -- a range 5.4.21 is not in.

`fixed_version` has been in the CSV contract from the beginning and had the
same defect the whole time, which is the part worth pinning: upgrading to the
version it named would not have fixed the vulnerability that was reported.
Adding `introduced_version` is what made it visible, because "introduced
8.0.0" next to an installed 5.4.21 is obviously wrong in a way that a lone
"fixed in 8.0.5" is not.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from osv_scanner_tool.scan import (  # noqa: E402
    _extract_details,
    _range_for_version,
    _version_parts,
)


def rng(introduced=None, fixed=None):
    events = []
    if introduced is not None:
        events.append({"introduced": introduced})
    if fixed is not None:
        events.append({"fixed": fixed})
    return {"events": events}


def affected(*ranges):
    return [{"ranges": [r]} for r in ranges]


# -- ordering ---------------------------------------------------------------

@pytest.mark.parametrize("lower, higher", [
    ("1.0.0", "2.0.0"),
    ("1.9.0", "1.10.0"),      # not string order
    ("1.0.0", "1.0.1"),
    ("2.0.0-rc.1", "2.0.0"),  # a pre-release precedes its release
])
def test_versions_order(lower, higher):
    assert _version_parts(lower) < _version_parts(higher)


def test_build_metadata_is_ignored():
    assert _version_parts("1.2.3+build9") == _version_parts("1.2.3")


def test_an_unparseable_version_is_empty_not_zero():
    """Empty means "cannot place this", which selects the honest fallback.
    Treating it as 0.0.0 would silently match the earliest range."""
    assert _version_parts("") == ()


# -- range selection --------------------------------------------------------

def test_picks_the_range_containing_the_version():
    entries = affected(
        rng("2.0.0", "2.9.9"), rng("5.0.0", "5.9.9"), rng("8.0.0", "8.0.5"))
    picked = _range_for_version(entries, "5.4.21")
    assert picked == [rng("5.0.0", "5.9.9")]


def test_the_real_vite_shape_no_longer_reports_the_8x_range():
    """The exact failure seen on real data."""
    entries = affected(rng("8.0.0", "8.0.5"), rng("5.0.0", "5.4.22"))
    events = [e for r in _range_for_version(entries, "5.4.21")
              for e in r["events"]]
    assert {"introduced": "5.0.0"} in events
    assert {"introduced": "8.0.0"} not in events


def test_zero_introduced_matches_anything_below_the_fix():
    entries = affected(rng("0", "1.2.3"))
    assert _range_for_version(entries, "0.9.0") == [rng("0", "1.2.3")]


def test_a_version_at_the_fix_is_outside_the_range():
    """Ranges are half-open: `fixed` is the first version that is safe."""
    entries = affected(rng("1.0.0", "2.0.0"), rng("3.0.0", "4.0.0"))
    assert _range_for_version(entries, "2.0.0") != [rng("1.0.0", "2.0.0")]


def test_an_open_range_with_no_fix_still_matches():
    entries = affected(rng("1.0.0", None))
    assert _range_for_version(entries, "9.9.9") == [rng("1.0.0", None)]


def test_an_unplaceable_version_falls_back_to_every_range():
    """Reporting all candidates is honest; reporting one arbitrary range is
    the bug this replaced."""
    entries = affected(rng("1.0.0", "2.0.0"), rng("3.0.0", "4.0.0"))
    assert len(_range_for_version(entries, "")) == 2


def test_no_affected_entries_yields_nothing():
    assert _range_for_version([], "1.0.0") == []


# -- end to end through the extractor ---------------------------------------

def test_extract_details_reports_the_matching_range():
    data = {"results": [{
        "source": {"path": "/repo/package-lock.json"},
        "packages": [{
            "package": {"name": "vite", "version": "5.4.21", "ecosystem": "npm"},
            "vulnerabilities": [{
                "id": "GHSA-x",
                "affected": [
                    {"ranges": [rng("8.0.0", "8.0.5")]},
                    {"ranges": [rng("5.0.0", "5.4.22")]},
                ],
            }],
        }],
    }]}
    row = _extract_details(data)[0]
    assert row["introduced_version"] == "5.0.0"
    assert row["fixed_version"] == "5.4.22"


def test_both_engines_emit_the_same_columns():
    """Regression guard: adding a column to one path and not the other makes
    a finding mean different things depending on what is installed."""
    from blastradius.pkg import osvscan
    from osv_scanner_tool.scan import CSV_FIELDS

    record = {
        "id": "GHSA-y",
        "affected": [{"ranges": [rng("0", "1.2.3")]}],
    }
    row = osvscan._row_from_osv_record(record, "npm", "left-pad", "1.0.0")
    assert set(row) == set(CSV_FIELDS)
    assert row["introduced_version"] == "0"
    assert row["fixed_version"] == "1.2.3"
