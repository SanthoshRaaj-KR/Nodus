"""OSV scan reader tests.

The load-bearing property: one vulnerability must be counted once, however
many identifiers the feeds gave it. Over-counting advisories inflates the
exposure of every project holding the package.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from blastradius import schema
from blastradius.pkg.osv import (
    AliasResolver,
    load_osv_csv,
    parse_timestamp,
)

HEADER = (
    "package,version,ecosystem,source_file,osv_id,aliases,summary,cvss_vector,"
    "severity_score,fixed_version,published,modified,details,references"
)


def _csv(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "scan.csv"
    path.write_text(HEADER + "\n" + textwrap.dedent(body).strip() + "\n", encoding="utf-8")
    return path


# -- timestamps ------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("1970-01-01T00:00:01Z", 1),
        ("2025-07-31T21:15:27.320Z", 1753996527),
        # More sub-second digits than fromisoformat accepts on some versions.
        ("2026-05-21T15:00:28.178881228Z", 1779375628),
        ("", schema.UNKNOWN_TS),
        (None, schema.UNKNOWN_TS),
        ("not a date", schema.UNKNOWN_TS),
    ],
)
def test_parse_timestamp(raw, expected):
    assert parse_timestamp(raw) == expected


def test_unknown_timestamp_cannot_fall_inside_a_live_window():
    # The sentinel has to fail safe: an unknown time must never read as
    # "resolved while the bad version was live".
    assert parse_timestamp(None) == 0
    live_from, live_until = 1_700_000_000, 1_800_000_000
    assert not (live_from <= parse_timestamp(None) <= live_until)


# -- alias union-find ------------------------------------------------------


def test_aliases_merge_transitively():
    """A->B and B->C must yield one group even though nothing states A->C.

    This is why union-find is used rather than a single pass over the alias
    column: a pass merges only the pairs it happens to see together.
    """
    r = AliasResolver()
    r.add("CVE-1", ["GHSA-x"])
    r.add("GHSA-x", ["PYSEC-9"])
    assert r.canonical("CVE-1") == r.canonical("PYSEC-9")
    assert len(r.groups()) == 1


def test_canonical_id_is_stable_regardless_of_row_order():
    a = AliasResolver()
    a.add("PYSEC-9", ["CVE-1"])
    a.add("GHSA-x", ["PYSEC-9"])

    b = AliasResolver()
    b.add("GHSA-x", ["PYSEC-9"])
    b.add("PYSEC-9", ["CVE-1"])

    assert a.canonical("GHSA-x") == b.canonical("GHSA-x") == "CVE-1"


def test_cve_preferred_as_canonical():
    r = AliasResolver()
    r.add("GHSA-zzz", ["CVE-2026-1", "PYSEC-2026-2"])
    assert r.canonical("GHSA-zzz") == "CVE-2026-1"


def test_unrelated_advisories_do_not_merge():
    r = AliasResolver()
    r.add("CVE-1", ["GHSA-a"])
    r.add("CVE-2", ["GHSA-b"])
    assert r.canonical("CVE-1") != r.canonical("CVE-2")
    assert len(r.groups()) == 2


# -- parsing ---------------------------------------------------------------


def test_rows_collapse_to_advisories(tmp_path):
    path = _csv(
        tmp_path,
        """
        lodash,4.17.20,npm,/a/package-lock.json,GHSA-aaa,CVE-2026-1,sum,VEC,,4.17.21,,,,
        lodash,4.17.20,npm,/a/package-lock.json,CVE-2026-1,GHSA-aaa,sum,VEC,,4.17.21,,,,
        lodash,4.17.20,npm,/a/package-lock.json,PYSEC-1,CVE-2026-1,sum,VEC,,4.17.21,,,,
        """,
    )
    scan = load_osv_csv(path)
    assert len(scan.findings) == 3
    assert len(scan.advisories) == 1, "three ids for one vulnerability"
    advisory = next(iter(scan.advisories.values()))
    assert advisory.advisory_id == "CVE-2026-1"
    assert set(advisory.all_ids) == {"CVE-2026-1", "GHSA-aaa", "PYSEC-1"}


def test_version_awareness_of_affected_set(tmp_path):
    path = _csv(
        tmp_path,
        """
        lodash,4.17.20,npm,/a,GHSA-a,,sum,VEC,,4.17.21,,,,
        lodash,4.17.21,npm,/a,GHSA-b,,sum,VEC,,4.17.22,,,,
        """,
    )
    scan = load_osv_csv(path)
    affected = {k for adv in scan.advisories.values() for k in adv.affected}
    assert affected == {("lodash", "4.17.20"), ("lodash", "4.17.21")}


def test_npm_names_normalized_but_other_ecosystems_left_alone(tmp_path):
    path = _csv(
        tmp_path,
        """
        LoDash,4.17.20,npm,/a,GHSA-a,,s,V,,,,,,
        My_Package,1.0.0,PyPI,/b,PYSEC-1,,s,V,,,,,,
        """,
    )
    scan = load_osv_csv(path)
    names = {f.package for f in scan.findings}
    # npm folds; PyPI keeps its own spelling because its rules differ.
    assert "lodash" in names
    assert "My_Package" in names


def test_rows_without_a_version_are_skipped_not_guessed(tmp_path):
    path = _csv(
        tmp_path,
        """
        lodash,,npm,/a,GHSA-a,,s,V,,,,,,
        lodash,4.17.21,npm,/a,GHSA-b,,s,V,,,,,,
        """,
    )
    scan = load_osv_csv(path)
    assert len(scan.findings) == 1
    assert len(scan.skipped) == 1
    assert "no version" in scan.skipped[0][1]


def test_empty_severity_score_stays_at_sentinel(tmp_path):
    """The source leaves severity_score blank while filling cvss_vector.

    Deriving the base score from the vector is a TODO; until then the score
    must stay at the sentinel rather than showing a number nobody computed.
    """
    path = _csv(
        tmp_path,
        """
        lodash,4.17.21,npm,/a,GHSA-a,,s,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,,,,,,
        """,
    )
    scan = load_osv_csv(path)
    advisory = next(iter(scan.advisories.values()))
    assert advisory.severity_score == float(schema.UNKNOWN_SCORE)
    assert advisory.cvss_vector.startswith("CVSS:3.1/")


def test_missing_required_column_is_loud(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("package,version\nlodash,4.17.21\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing required column"):
        load_osv_csv(path)


def test_ecosystem_routing(tmp_path):
    path = _csv(
        tmp_path,
        """
        lodash,4.17.21,npm,/a,GHSA-a,,s,V,,,,,,
        requests,2.9.2,PyPI,/b,PYSEC-1,,s,V,,,,,,
        """,
    )
    scan = load_osv_csv(path)
    assert scan.ecosystems() == {"npm": 1, "PyPI": 1}
    assert len(scan.for_ecosystem("npm")) == 1
    assert len(scan.advisories_for_ecosystem("npm")) == 1


# -- against the real supplied file ---------------------------------------


def test_supplied_sample_file_parses_and_dedupes():
    sample = Path(__file__).resolve().parents[2] / "osv_scan_results.csv"
    if not sample.exists():
        pytest.skip("sample osv_scan_results.csv not present")
    scan = load_osv_csv(sample)
    assert len(scan.findings) == 23
    # The merge has to actually do something on real data, or the whole
    # union-find is ceremony.
    assert len(scan.advisories) < len(scan.findings)
    assert len(scan.advisories) == 12
    assert not scan.skipped
