import csv
import json
import subprocess
import sys


def _version_parts(text):
    """A comparable tuple for a version string, best effort.

    Deliberately tolerant rather than a full semver or PEP 440 parser. It is
    used only to decide which of an advisory's ranges a version falls in, the
    ranges of one advisory do not overlap, and a wrong answer degrades to
    "report every range" rather than to a wrong range. Pre-release suffixes
    sort below the release they precede, which is the one ordering rule that
    matters here.
    """
    if not text:
        return ()
    head = str(text).split("+", 1)[0]
    head, _, pre = head.partition("-")
    out = []
    for chunk in head.split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        out.append(int(digits) if digits else 0)
    # A release outranks any pre-release of the same number.
    out.append(0 if pre else 1)
    return tuple(out)


def _range_for_version(affected_entries, version):
    """The ranges of the `affected` entry that actually contains `version`.

    The bug this replaces: the extractor read `affected[0]` and reported its
    events regardless of which version was installed. An advisory covering a
    package's 2.x, 5.x and 8.x lines has one `affected` entry per line, so a
    scan of 5.4.21 reported the 8.x range -- "introduced 8.0.0, fixed 8.0.5"
    against a 5.4.21 install. `fixed_version` had the same defect and has been
    wrong in the CSV for as long as it has existed; upgrading to the version
    it named would not have fixed anything.

    Falls back to every entry when the version cannot be placed, because
    reporting all the candidate ranges is honest and reporting one arbitrary
    range is not.
    """
    if not affected_entries:
        return []
    target = _version_parts(version)
    if target:
        for entry in affected_entries:
            for rng in entry.get("ranges") or []:
                low, high = None, None
                for event in rng.get("events") or []:
                    if event.get("introduced") is not None:
                        low = event["introduced"]
                    if event.get("fixed") is not None:
                        high = event["fixed"]
                lo_ok = low in (None, "0") or target >= _version_parts(low)
                hi_ok = high is None or target < _version_parts(high)
                if lo_ok and hi_ok:
                    return [rng]
    return [r for entry in affected_entries for r in (entry.get("ranges") or [])]


def _extract_details(data):
    details = []
    for group in data.get("results", []):
        source = group.get("source", {}).get("path", "")
        for item in group.get("packages", []):
            pkg = item["package"]
            for vuln in item.get("vulnerabilities", []):
                ranges = _range_for_version(
                    vuln.get("affected") or [], pkg.get("version")
                )
                fixed_events = [
                    e.get("fixed")
                    for r in ranges
                    for e in r.get("events", [])
                    if e.get("fixed")
                ]
                # The other half of the same range, and the answer to "which
                # version introduced it". OSV states it explicitly -- an
                # `introduced` event opens every range -- so deriving it by
                # sorting the versions we happen to hold would be guessing at
                # something the advisory already says. `0` is OSV's "from the
                # beginning of time"; it is kept verbatim rather than
                # normalised, because "since the first release" is a real and
                # different answer from a version number.
                introduced_events = [
                    e.get("introduced")
                    for r in ranges
                    for e in r.get("events", [])
                    if e.get("introduced")
                ]
                severity = vuln.get("severity", [])
                cvss = " | ".join(s.get("score", "") for s in severity)
                refs = vuln.get("references", [])
                primary_ref = next(
                    (r["url"] for r in refs if r.get("type") == "ADVISORY"),
                    refs[0]["url"] if refs else "",
                )
                details.append({
                    "package": pkg.get("name"),
                    "version": pkg.get("version"),
                    "ecosystem": pkg.get("ecosystem"),
                    "source_file": source,
                    "osv_id": vuln.get("id"),
                    "aliases": " | ".join(vuln.get("aliases", [])),
                    "summary": vuln.get("summary", ""),
                    "cvss_vector": cvss,
                    "severity_score": vuln.get("database_specific", {}).get("severity", ""),
                    "fixed_version": "; ".join(fixed_events),
                    "introduced_version": "; ".join(introduced_events),
                    "published": vuln.get("published", ""),
                    "modified": vuln.get("modified", ""),
                    "details": vuln.get("details", "").replace("\n", " ").strip(),
                    "references": primary_ref,
                })
    return details


def scan_repo(repo_path, respect_gitignore=False):
    """Scan a repo/folder for known vulnerabilities via osv-scanner.

    ``respect_gitignore`` is off by default, and that default is load-bearing.
    osv-scanner honours ``.gitignore`` when walking a directory, which is the
    right instinct for a tool run inside the project being scanned and the
    wrong one here: the repos under test are checked out into a directory that
    is git-ignored precisely because somebody else's history is not ours to
    commit. "Do not commit this" is not "do not scan this", and the failure is
    silent -- the scanner walks the tree, extracts nothing, and reports a clean
    bill of health for code it never opened.

    Args:
        repo_path (str): Path to a repo or folder.
        respect_gitignore (bool): Skip files the repo's .gitignore excludes.

    Returns:
        dict: Scan summary. ``sources`` names the manifests the scanner
        actually parsed, which is what separates "scanned, nothing found" from
        "never read a thing".
    """
    command = ["osv-scanner", "scan", "--recursive"]
    if not respect_gitignore:
        command.append("--no-ignore")
    command += [repo_path, "--format", "json"]

    # Windows decodes subprocess output with the locale codec (cp1252 here)
    # unless told otherwise, and osv-scanner emits UTF-8. A single byte it
    # cannot map kills the reader thread mid-scan, so the encoding is named
    # explicitly and undecodable bytes are replaced rather than raised --
    # losing one character beats losing the whole scan.
    result = subprocess.run(
        command, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    if result.returncode not in (0, 1):
        if "No package sources found" in result.stderr:
            return {
                "repo_path": repo_path,
                "total_vulnerabilities": 0,
                "affected_packages": 0,
                "sources": [],
                "details": [],
            }
        raise RuntimeError(f"osv-scanner failed: {result.stderr}")

    data = json.loads(result.stdout)
    details = _extract_details(data)
    sources = [
        group.get("source", {}).get("path", "")
        for group in data.get("results", [])
    ]

    return {
        "repo_path": repo_path,
        "total_vulnerabilities": len(details),
        "affected_packages": len({d["package"] for d in details}),
        "sources": [s for s in sources if s],
        "details": details,
    }


CSV_FIELDS = [
    "package", "version", "ecosystem", "source_file", "osv_id",
    "aliases", "summary", "cvss_vector", "severity_score",
    "fixed_version", "introduced_version",
    "published", "modified", "details", "references",
]


def scan_repo_to_csv(repo_path, output_path):
    """Scan a repo and write extracted details to a CSV file.

    Args:
        repo_path (str): Path to a repo or folder.
        output_path (str): Path to the output CSV file.

    Returns:
        dict: Scan summary as returned by scan_repo().
    """
    summary = scan_repo(repo_path)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in summary["details"]:
            writer.writerow({k: row.get(k, "") for k in CSV_FIELDS})
    return summary


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    out = sys.argv[2] if len(sys.argv) > 2 else "osv_scan_results.csv"
    summary = scan_repo_to_csv(path, out)
    print(json.dumps({k: v for k, v in summary.items() if k != "details"}, indent=2))
    print(f"\nCSV written to: {out}")