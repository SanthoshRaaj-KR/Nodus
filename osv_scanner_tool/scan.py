import csv
import json
import subprocess
import sys


def _extract_details(data):
    details = []
    for group in data.get("results", []):
        source = group.get("source", {}).get("path", "")
        for item in group.get("packages", []):
            pkg = item["package"]
            for vuln in item.get("vulnerabilities", []):
                affected = vuln.get("affected", [{}])[0]
                ranges = affected.get("ranges", [])
                fixed_events = [
                    e.get("fixed")
                    for r in ranges
                    for e in r.get("events", [])
                    if e.get("fixed")
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
    "fixed_version", "published", "modified", "details", "references",
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