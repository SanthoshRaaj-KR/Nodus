"""The scan -> graph bridge.

The load-bearing property is a round trip: whatever the scanner found has to
come back out the other side as an advisory the query layer can match against
a version it holds. A break anywhere in that chain -- the CSV columns, the
alias merge, the file the UI reads -- shows up as "you are not affected",
which is the one wrong answer this tool must never give quietly.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from blastradius import schema
from blastradius.pkg import osvscan
from blastradius.pkg.osv import load_osv_csv, severity_rank
from blastradius.query.advisory import Advisory

HEADER = (
    "package,version,ecosystem,source_file,osv_id,aliases,summary,cvss_vector,"
    "severity_score,fixed_version,published,modified,details,references"
)


def _csv(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "osv_scan_results.csv"
    path.write_text(
        HEADER + "\n" + textwrap.dedent(body).strip() + "\n", encoding="utf-8"
    )
    return path


# -- severity labels -------------------------------------------------------


def test_word_severity_survives_the_numeric_column(tmp_path):
    """osv-scanner puts a word where the column name promises a number.

    ``database_specific.severity`` is "HIGH" for GHSA imports. Casting it to
    float and giving up left every scanned advisory unrated, which is how a
    critical finding ends up rendered identically to a decade-old low.
    """
    scan = load_osv_csv(_csv(tmp_path, """
        lodash,4.17.20,npm,lock,CVE-1,,Summary,CVSS:3.1/AV:N,HIGH,4.17.21,,,,
    """))
    advisory = scan.advisories["CVE-1"]
    assert advisory.severity_label == "high"
    # The numeric score stays at its sentinel: nothing derived one.
    assert advisory.severity_score == float(schema.UNKNOWN_SCORE)


def test_numeric_severity_still_parses_as_a_number(tmp_path):
    scan = load_osv_csv(_csv(tmp_path, """
        lodash,4.17.20,npm,lock,CVE-1,,Summary,,7.5,4.17.21,,,,
    """))
    advisory = scan.advisories["CVE-1"]
    assert advisory.severity_score == 7.5
    assert advisory.severity_label == ""


def test_unknown_severity_word_is_skipped_not_shown(tmp_path):
    """An unranked word in front of a reader implies a rating nobody gave."""
    scan = load_osv_csv(_csv(tmp_path, """
        lodash,4.17.20,npm,lock,CVE-1,,Summary,,SPICY,4.17.21,,,,
    """))
    assert scan.advisories["CVE-1"].severity_label == ""
    assert any("SPICY" in reason for _line, reason in scan.skipped)


def test_worst_severity_wins_the_merge(tmp_path):
    """Two feeds, one advisory, disagreeing. Under-reporting is the costly way
    to be wrong, so the worse label survives regardless of row order."""
    scan = load_osv_csv(_csv(tmp_path, """
        lodash,4.17.20,npm,lock,CVE-1,GHSA-x,Summary,,LOW,4.17.21,,,,
        lodash,4.17.21,npm,lock,GHSA-x,CVE-1,Summary,,CRITICAL,4.17.22,,,,
    """))
    assert len(scan.advisories) == 1
    assert next(iter(scan.advisories.values())).severity_label == "critical"


def test_moderate_and_medium_are_one_rung():
    assert severity_rank("MODERATE") == severity_rank("medium")
    assert severity_rank("critical") > severity_rank("high") > severity_rank("low")
    assert severity_rank(None) == 0


# -- advisory files --------------------------------------------------------


def test_one_advisory_spanning_two_packages_becomes_two_files(tmp_path):
    """The contract is one package per file. Collapsing to one file would drop
    exposure the scan actually found."""
    scan = load_osv_csv(_csv(tmp_path, """
        lodash,4.17.20,npm,lock,CVE-1,,Shared flaw,,HIGH,4.17.21,,,,
        underscore,1.13.0,npm,lock,CVE-1,,Shared flaw,,HIGH,1.13.1,,,,
    """))
    written = osvscan.write_advisory_files(scan, tmp_path / "generated")
    assert len(written) == 2
    packages = {json.loads(p.read_text(encoding="utf-8"))["package"] for p in written}
    assert packages == {"lodash", "underscore"}


def test_generated_file_round_trips_into_the_query_layer(tmp_path):
    """The whole point: a scanned finding must match the version it was found
    on, through the same Advisory class the hand-written samples use."""
    scan = load_osv_csv(_csv(tmp_path, """
        lodash,4.17.20,npm,lock,CVE-1,,Summary,,HIGH,4.17.21,2021-05-06T00:00:00Z,,,
    """))
    written = osvscan.write_advisory_files(scan, tmp_path / "generated", repo="/repo")
    advisory = Advisory.load(written[0])

    assert advisory.matches("4.17.20")
    assert not advisory.matches("4.17.21")
    assert advisory.severity == "high"
    assert advisory.keys_among(["4.17.19", "4.17.20"]) == ["lodash@4.17.20"]


def test_exact_versions_never_become_a_range(tmp_path):
    """A synthesised range would claim coverage of versions nothing observed."""
    scan = load_osv_csv(_csv(tmp_path, """
        lodash,4.17.20,npm,lock,CVE-1,,Summary,,HIGH,4.17.21,,,,
    """))
    written = osvscan.write_advisory_files(scan, tmp_path / "generated")
    raw = json.loads(written[0].read_text(encoding="utf-8"))
    assert raw["affected_range"] == ""
    assert raw["affected_versions"] == ["4.17.20"]
    assert raw["source"] == "osv-scan"


def test_only_the_named_ecosystem_is_written(tmp_path):
    """PyPI versions matched by npm range semantics is a wrong answer waiting
    to happen, so they do not get a file the npm matcher will read."""
    scan = load_osv_csv(_csv(tmp_path, """
        lodash,4.17.20,npm,lock,CVE-1,,npm flaw,,HIGH,4.17.21,,,,
        jinja2,3.1.2,PyPI,req,CVE-2,,py flaw,,HIGH,3.1.3,,,,
    """))
    written = osvscan.write_advisory_files(scan, tmp_path / "generated")
    assert [json.loads(p.read_text(encoding="utf-8"))["package"] for p in written] == [
        "lodash"
    ]


def test_a_rescan_replaces_the_previous_set(tmp_path):
    """Advisories are a snapshot of one repo. Leaving stale files behind means
    the UI keeps offering a chip for a package that was upgraded away."""
    directory = tmp_path / "generated"
    first = load_osv_csv(_csv(tmp_path, """
        lodash,4.17.20,npm,lock,CVE-OLD,,Summary,,HIGH,4.17.21,,,,
    """))
    osvscan.write_advisory_files(first, directory)

    second = load_osv_csv(_csv(tmp_path, """
        express,4.18.2,npm,lock,CVE-NEW,,Summary,,LOW,4.19.0,,,,
    """))
    written = osvscan.write_advisory_files(second, directory)

    on_disk = sorted(p.name for p in directory.glob("*.json"))
    assert on_disk == [p.name for p in written]
    assert not any("CVE-OLD" in name for name in on_disk)


def test_scoped_package_names_survive_the_filename(tmp_path):
    """`@babel/traverse` has two characters no filesystem wants."""
    scan = load_osv_csv(_csv(tmp_path, """
        @babel/traverse,7.23.0,npm,lock,CVE-1,,Summary,,CRITICAL,7.23.2,,,,
    """))
    written = osvscan.write_advisory_files(scan, tmp_path / "generated")
    assert len(written) == 1
    assert "/" not in written[0].name
    assert json.loads(written[0].read_text(encoding="utf-8"))["package"] == (
        "@babel/traverse"
    )


# -- the API fallback ------------------------------------------------------


def test_osv_record_maps_onto_the_csv_contract():
    """The fallback has to emit the same columns as the binary, or the two
    engines would disagree about what a finding is."""
    record = {
        "id": "GHSA-abcd",
        "aliases": ["CVE-2021-1"],
        "summary": "A flaw",
        "details": "Line one\nline two",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
        "database_specific": {"severity": "HIGH"},
        "published": "2021-05-06T00:00:00Z",
        "modified": "2021-06-06T00:00:00Z",
        "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}],
        "references": [
            {"type": "WEB", "url": "https://example.test/web"},
            {"type": "ADVISORY", "url": "https://example.test/advisory"},
        ],
    }
    row = osvscan._row_from_osv_record(record, "npm", "lodash", "4.17.20")

    from osv_scanner_tool.scan import CSV_FIELDS

    assert set(row) == set(CSV_FIELDS)
    assert row["osv_id"] == "GHSA-abcd"
    assert row["fixed_version"] == "1.2.3"
    assert row["severity_score"] == "HIGH"
    # The ADVISORY reference is preferred over the first one listed.
    assert row["references"] == "https://example.test/advisory"
    # Newlines would end the CSV row early.
    assert "\n" not in row["details"]


def test_a_record_with_nothing_in_it_still_produces_a_row():
    """OSV records are not uniformly populated; a sparse one is data, not a
    crash."""
    row = osvscan._row_from_osv_record({"id": "OSV-1"}, "npm", "left-pad", "1.0.0")
    assert row["osv_id"] == "OSV-1"
    assert row["fixed_version"] == ""
    assert row["references"] == ""


# -- timing ----------------------------------------------------------------


def test_step_shares_are_of_the_wall_clock_not_the_sum():
    """Stages nest -- the scan's own steps are re-listed inside the pipeline --
    so shares are taken against the measured total that was passed in."""
    steps = [osvscan.Step("a", 1.0, "x"), osvscan.Step("b", 3.0, "y")]
    table = osvscan.render_steps(steps, total=8.0)
    assert " 12.5%" in table
    assert " 37.5%" in table
    assert "TOTAL" in table


def test_render_steps_survives_an_empty_run():
    assert osvscan.render_steps([]) == "(no steps recorded)"


# -- concurrent timing -----------------------------------------------------


def test_concurrent_steps_get_a_marker_not_a_share():
    """Three 10s stages inside a 12s phase sum to 250%. A share column that
    adds up to more than the run took is worse than no share column."""
    steps = [
        osvscan.Step("phase A", 12.0, "3 stages"),
        osvscan.Step("  scan", 10.0, "", concurrent=True),
        osvscan.Step("  ingest", 10.0, "", concurrent=True),
        osvscan.Step("  prefetch", 10.0, "", concurrent=True),
        osvscan.Step("verify", 4.0, ""),
    ]
    table = osvscan.render_steps(steps, total=16.0)
    assert table.count("||") >= 3
    # Only the two sequential rows carry a percentage.
    assert " 75.0%" in table  # phase A
    assert " 25.0%" in table  # verify


def test_nested_and_concurrent_are_told_apart():
    """A sequential run whose sub-steps claimed concurrency would teach the
    reader something false about how it executed."""
    steps = [
        osvscan.Step("scan", 5.0, ""),
        osvscan.Step("  write csv", 1.0, "", nested=True),
    ]
    table = osvscan.render_steps(steps, total=5.0)
    assert "||" not in table
    assert ">" in table
    assert "already counted inside" in table


def test_shareless_steps_are_excluded_from_a_derived_total():
    """With no total passed in, one is summed -- and double-counting a nested
    step there would shrink every real share."""
    steps = [
        osvscan.Step("a", 4.0, ""),
        osvscan.Step("  a-part", 3.0, "", nested=True),
        osvscan.Step("b", 4.0, ""),
    ]
    table = osvscan.render_steps(steps)
    assert "TOTAL" in table
    assert "     8.000" in table  # 4 + 4, not 4 + 3 + 4


# -- the silent-skip guard -------------------------------------------------


def test_a_scan_that_read_nothing_is_flagged_blind(tmp_path, monkeypatch):
    """The worst failure this tool has: osv-scanner honours .gitignore, the
    repos under test live in a git-ignored directory, and a scan that opened
    no files reports exactly what a clean repo reports -- zero findings."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {}}), encoding="utf-8"
    )

    import osv_scanner_tool.scan as scanmod

    monkeypatch.setattr(
        scanmod, "scan_repo",
        lambda path, **_kw: {"details": [], "sources": []},
    )
    run = osvscan.scan_repository(
        repo, out_dir=tmp_path / "out", advisory_dir=None,
        engine="binary", verbose=False,
    )
    assert run.findings == 0
    assert run.blind is True
    assert any("NOTHING WAS SCANNED" in note for note in run.notes)


def test_a_scan_that_read_the_manifest_and_found_nothing_is_clean(tmp_path, monkeypatch):
    """The other half of the same distinction: parsed a source, found no
    vulnerabilities. That one really is good news and must not be flagged."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {}}), encoding="utf-8"
    )

    import osv_scanner_tool.scan as scanmod

    monkeypatch.setattr(
        scanmod, "scan_repo",
        lambda path, **_kw: {
            "details": [], "sources": [str(repo / "package-lock.json")],
        },
    )
    run = osvscan.scan_repository(
        repo, out_dir=tmp_path / "out", advisory_dir=None,
        engine="binary", verbose=False,
    )
    assert run.findings == 0
    assert run.blind is False
    assert not any("NOTHING WAS SCANNED" in note for note in run.notes)


def test_no_manifests_at_all_is_not_a_blind_scan(tmp_path, monkeypatch):
    """An empty directory has nothing to scan. Reporting that as a suppressed
    scan would cry wolf on the one case where zero really means zero."""
    repo = tmp_path / "empty"
    repo.mkdir()

    import osv_scanner_tool.scan as scanmod

    monkeypatch.setattr(
        scanmod, "scan_repo", lambda path, **_kw: {"details": [], "sources": []}
    )
    run = osvscan.scan_repository(
        repo, out_dir=tmp_path / "out", advisory_dir=None,
        engine="binary", verbose=False,
    )
    assert run.blind is False


def test_the_scanner_is_invoked_with_no_ignore(monkeypatch):
    """The fix itself, pinned. A .gitignore in the tree being scanned must not
    decide what gets scanned."""
    import osv_scanner_tool.scan as scanmod

    seen = {}

    class _Result:
        returncode = 0
        stdout = json.dumps({"results": []})
        stderr = ""

    def fake_run(command, **_kw):
        seen["command"] = command
        return _Result()

    monkeypatch.setattr(scanmod.subprocess, "run", fake_run)
    scanmod.scan_repo("some/path")
    assert "--no-ignore" in seen["command"]

    scanmod.scan_repo("some/path", respect_gitignore=True)
    assert "--no-ignore" not in seen["command"]


# -- subprocess decoding ---------------------------------------------------


def test_every_text_mode_subprocess_names_its_encoding():
    """Windows decodes subprocess output with the locale codec unless told
    otherwise. osv-scanner, pip and npm all emit UTF-8, and one unmappable
    byte kills subprocess's reader thread -- which surfaces as a stray
    traceback and an empty result, not as an error anyone can act on.

    Asserted across the tree rather than at one call site: this bug arrived
    with a new module that simply did not know the rule, and would arrive
    again the same way.
    """
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    offenders = []
    for path in list((root / "blastradius").rglob("*.py")) + list(
        (root / "osv_scanner_tool").rglob("*.py")
    ):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "attr", getattr(node.func, "id", "")) != "run":
                continue
            kw = {k.arg for k in node.keywords}
            if ("text" in kw or "universal_newlines" in kw) and not {
                "encoding", "errors"
            } <= kw:
                offenders.append(f"{path.relative_to(root)}:{node.lineno}")

    assert not offenders, (
        "text-mode subprocess.run without encoding= and errors=: "
        + ", ".join(offenders)
    )


def test_scan_survives_undecodable_bytes(monkeypatch, tmp_path):
    """The end-to-end shape of the crash: a scanner whose output is not
    decodable by the locale codec must still produce a scan."""
    import osv_scanner_tool.scan as scanmod

    captured = {}

    class _Result:
        returncode = 0
        # A byte cp1252 cannot map (0x90) inside otherwise valid UTF-8 JSON.
        stdout = json.dumps({"results": []})
        stderr = "warning: \ufffd unmappable"

    def fake_run(command, **kw):
        captured.update(kw)
        return _Result()

    monkeypatch.setattr(scanmod.subprocess, "run", fake_run)
    summary = scanmod.scan_repo(str(tmp_path))

    assert captured.get("encoding") == "utf-8"
    assert captured.get("errors") == "replace"
    assert summary["details"] == []
    assert summary["sources"] == []
