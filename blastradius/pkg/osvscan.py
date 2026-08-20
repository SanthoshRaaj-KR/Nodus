"""Live OSV scan of a repository -> the two inputs the graph already eats.

Until now the vulnerable half of the graph was static: three hand-written
files in ``advisories/`` and a ``simulate`` command that marks a version by
name. Both are fine for a demo and neither says anything about *your* code.
This module is the bridge to :mod:`osv_scanner_tool`, so the vulnerabilities
in the graph come from scanning a real repository instead.

It produces exactly what the pipeline already consumes, and nothing new:

* **``osv_scan_results.csv``** -- the column contract :mod:`blastradius.pkg.osv`
  parses, which the package tier turns into ``Advisory`` nodes and ``AFFECTS``
  edges.
* **``advisories/generated/*.json``** -- the teammate contract
  :class:`blastradius.query.advisory.Advisory` parses, which drives the CLI's
  ``advisory`` command and the one-click chips in both UIs.

Writing both is the point. They feed different tiers -- the CSV reaches the
macro/package graph, the JSON reaches the micro/reachability side -- and a
scan that populated only one would leave half the tool still hardcoded.

Two scanners, one output
------------------------

The preferred engine is Google's ``osv-scanner`` binary, driven through
``osv_scanner_tool.scan``. It is not a Python package, so a machine without
the Go toolchain has no way to install it, and a checkout that dies on a
missing binary is not much of a pipeline. The fallback resolves the
repository's manifests locally (``osv_scanner_tool.deps``) and asks
`api.osv.dev` about the exact resolved versions over HTTP. Both paths emit the
same rows, and :attr:`ScanRun.engine` records which one answered, because a
result whose provenance is unstated is a result nobody can check.

Every stage is timed. ``ScanRun.render()`` prints the table and
``ScanRun.write_log()`` puts it on disk next to the CSV, so a slow run can be
attributed to a stage rather than guessed at.
"""

from __future__ import annotations

import json
import re
import shutil
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .. import schema
from ..ingest.ignore import IGNORE_FILE
from .osv import OsvScan, load_osv_csv

__all__ = [
    "Step",
    "ScanRun",
    "scan_repository",
    "write_advisory_files",
    "clear_generated_advisories",
    "osv_scanner_available",
    "render_steps",
    "GENERATED_DIRNAME",
]

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "data" / "osv"

#: Generated advisories live in their own subdirectory so a regeneration can
#: clear them wholesale without touching the hand-written samples beside them.
GENERATED_DIRNAME = "generated"
DEFAULT_ADVISORY_DIR = ROOT / "advisories" / GENERATED_DIRNAME

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"

_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


# --------------------------------------------------------------------------
# Timing
# --------------------------------------------------------------------------


@dataclass
class Step:
    """One timed stage of the scan."""

    name: str
    seconds: float
    detail: str = ""
    #: True when this ran alongside other steps. Such a step has no meaningful
    #: share of the wall clock -- three 10 s stages inside a 12 s phase would
    #: sum to 250% -- so the table prints a marker where the share goes.
    concurrent: bool = False
    #: True when this step's time is already counted inside its parent's row.
    #: Same suppression, different reason, and worth telling apart: a reader
    #: who sees the concurrency marker on a run that was sequential learns
    #: something false about how it executed.
    nested: bool = False

    @property
    def shareless(self) -> bool:
        """Steps whose duration must not be given a share of the total."""
        return self.concurrent or self.nested

    @property
    def ms(self) -> float:
        return self.seconds * 1000.0


class _Timer:
    """Accumulates :class:`Step` records and echoes progress as it goes."""

    def __init__(self, verbose: bool = True) -> None:
        self.steps: list[Step] = []
        self.verbose = verbose
        self._started = time.perf_counter()

    def run(self, name: str, fn):
        """Time ``fn()``, record it, return its value.

        ``fn`` returns ``(value, detail)`` so the detail column can report
        something only the step itself knows -- row counts, file sizes --
        without the caller having to time it a second time.
        """
        if self.verbose:
            print(f"  {name:26} ...", end="", flush=True)
        start = time.perf_counter()
        try:
            value, detail = fn()
        except BaseException:
            elapsed = time.perf_counter() - start
            self.steps.append(Step(name, elapsed, "FAILED"))
            if self.verbose:
                print(f" failed after {elapsed:.2f}s")
            raise
        elapsed = time.perf_counter() - start
        self.steps.append(Step(name, elapsed, detail or ""))
        if self.verbose:
            print(f" {elapsed:8.2f}s  {detail}")
        return value

    def record(self, name: str, seconds: float, detail: str = "") -> None:
        """Record a stage timed somewhere else (a subprocess, another module)."""
        self.steps.append(Step(name, seconds, detail))

    @property
    def total(self) -> float:
        return time.perf_counter() - self._started


def render_steps(steps: list[Step], total: float | None = None) -> str:
    """A timing table against the wall clock.

    Sequential shares sum to 100%. Concurrent steps get a ``||`` marker rather
    than a share, because their durations overlap: printing a percentage for
    each would produce a column that adds up to more than the run took, which
    is worse than printing nothing.
    """
    if not steps:
        return "(no steps recorded)"
    width = max(max(len(s.name) for s in steps), len("TOTAL"))
    total = total if total is not None else sum(
        s.seconds for s in steps if not s.shareless
    )
    lines = [
        f"{'step'.ljust(width)}  {'seconds':>9}  {'share':>6}  detail",
        f"{'-' * width}  {'-' * 9}  {'-' * 6}  {'-' * 44}",
    ]
    for step in steps:
        if step.concurrent:
            share = "    ||"
        elif step.nested:
            share = "     >"
        else:
            pct = (step.seconds / total * 100) if total else 0.0
            share = f"{pct:5.1f}%"
        lines.append(
            f"{step.name.ljust(width)}  {step.seconds:9.3f}  {share}  {step.detail}"
        )
    lines.append(f"{'-' * width}  {'-' * 9}  {'-' * 6}")
    lines.append(f"{'TOTAL'.ljust(width)}  {total:9.3f}  100.0%")
    notes = []
    if any(s.concurrent for s in steps):
        notes.append("||  ran alongside the steps beside it, inside the phase "
                     "above them")
    if any(s.nested for s in steps):
        notes.append(">   already counted inside the step above it")
    if notes:
        lines.append("")
        lines.extend(notes)
    return "\n".join(lines)


# --------------------------------------------------------------------------
# The run
# --------------------------------------------------------------------------


@dataclass
class ScanRun:
    """Everything one scan produced, plus how long each part of it took."""

    repo: str
    engine: str = "unknown"
    csv_path: Path | None = None
    advisory_dir: Path | None = None
    advisory_files: list[Path] = field(default_factory=list)
    manifests: dict[str, list[str]] = field(default_factory=dict)
    findings: int = 0
    advisories: int = 0
    packages: int = 0
    ecosystems: dict[str, int] = field(default_factory=dict)
    top: list[tuple[str, int]] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    elapsed_s: float = 0.0
    started_at: float = 0.0
    scan: OsvScan | None = None
    notes: list[str] = field(default_factory=list)
    #: The manifests the scanner actually parsed. Empty while manifests exist
    #: on disk is the silent-skip case, and it is why this is recorded rather
    #: than inferred from the finding count.
    sources: list[str] = field(default_factory=list)
    #: True when the scan read nothing at all. Zero findings from a blind scan
    #: is not a clean bill of health, and callers must be able to tell.
    blind: bool = False
    #: Manifests skipped by `.blastradiusignore`, and the rows dropped with
    #: them. Recorded rather than discarded: silently narrowing a scan is the
    #: same failure as silently widening it, told backwards.
    ignored_manifests: list[str] = field(default_factory=list)
    ignored_rows: int = 0

    def render(self) -> str:
        eco = ", ".join(f"{k}={v}" for k, v in sorted(self.ecosystems.items()))
        manifests = ", ".join(
            f"{k}={len(v)}" for k, v in sorted(self.manifests.items()) if v
        )
        lines = [
            f"repo            {self.repo}",
            f"engine          {self.engine}",
            f"manifests       {manifests or 'none found'}",
            f"findings        {self.findings:,}",
            f"advisories      {self.advisories:,}  (after alias merge)",
            f"vulnerable pkgs {self.packages:,}",
            f"sources parsed  {len(self.sources)}"
            + ("   <-- NOTHING WAS SCANNED" if self.blind else ""),
            f"ecosystems      {eco or '(none)'}",
        ]
        if self.csv_path:
            lines.append(f"csv             {self.csv_path}")
        if self.advisory_dir:
            lines.append(
                f"advisory json   {len(self.advisory_files)} file(s) in {self.advisory_dir}"
            )
        if self.top:
            lines.append("")
            lines.append("most-affected versions")
            for name, count in self.top:
                lines.append(f"    {name:40} {count} advisory row(s)")
        for note in self.notes:
            lines.append("")
            lines.append(note)
        lines.append("")
        lines.append(render_steps(self.steps, self.elapsed_s))
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "repo": self.repo,
            "engine": self.engine,
            "started_at": self.started_at,
            "elapsed_s": round(self.elapsed_s, 3),
            "csv_path": str(self.csv_path) if self.csv_path else None,
            "advisory_dir": str(self.advisory_dir) if self.advisory_dir else None,
            "advisory_files": [p.name for p in self.advisory_files],
            "manifests": self.manifests,
            "findings": self.findings,
            "advisories": self.advisories,
            "vulnerable_packages": self.packages,
            "sources_parsed": self.sources,
            "blind": self.blind,
            "ecosystems": self.ecosystems,
            "top_versions": [{"spec": n, "rows": c} for n, c in self.top],
            "steps": [
                {"name": s.name, "seconds": round(s.seconds, 4), "detail": s.detail}
                for s in self.steps
            ],
            "notes": self.notes,
        }

    def write_log(self, path: Path | str) -> Path:
        """Write the human table and the machine JSON side by side."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started_at))
        path.write_text(
            f"# OSV scan log\n\ngenerated {stamp}\n\n```\n{self.render()}\n```\n",
            encoding="utf-8",
        )
        path.with_suffix(".json").write_text(
            json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
        return path


# --------------------------------------------------------------------------
# Engine selection
# --------------------------------------------------------------------------


def osv_scanner_available() -> str | None:
    """Path to the ``osv-scanner`` binary, or None if it is not installed."""
    return shutil.which("osv-scanner")


def _scan_with_binary(repo: Path) -> tuple[list[dict], str, list[str]]:
    """Drive the real scanner through the teammate's wrapper."""
    from osv_scanner_tool.scan import scan_repo

    summary = scan_repo(str(repo))
    return summary["details"], "osv-scanner", summary.get("sources", [])


def _http_json(url: str, payload: dict | None = None, timeout: int = 30) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=body, method="POST" if body else "GET")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", "blastradius-osvscan/1.0")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode())


def _resolved_versions(repo: Path, include_python: bool) -> list[tuple[str, str, str]]:
    """(ecosystem, name, version) for every version the repo actually resolves.

    npm comes straight out of ``package-lock.json`` -- it already is a
    resolved graph. Python needs pip to resolve it, which is slow enough to be
    opt-in: an unpinned ``requirements.txt`` does not name the versions that
    would be installed, so reading versions off the manifest would scan
    something the repo never installs.
    """
    from osv_scanner_tool import deps

    manifests = deps.find_manifests(repo)
    out: list[tuple[str, str, str]] = []
    for lock in manifests["package-lock"]:
        graph = deps.resolve_npm(lock)
        for node in graph["nodes"].values():
            if node["name"] and node["version"]:
                out.append(("npm", node["name"], node["version"]))
    if include_python and manifests["requirements"]:
        graph = deps.resolve_python(manifests["requirements"])
        for node in graph["nodes"].values():
            if "unresolved" not in node["version"]:
                out.append(("PyPI", node["name"], node["version"]))
    # One row per distinct version: a package hoisted into twenty places in the
    # tree is still one thing to ask OSV about.
    return sorted(set(out))


def _scan_with_api(
    repo: Path, include_python: bool, batch: int = 500
) -> tuple[list[dict], str, list[str]]:
    """Fallback: resolve locally, ask api.osv.dev about the exact versions.

    ``querybatch`` returns ids only, so each distinct id is then fetched once
    for the prose, severity and fixed version the CSV contract carries. Ids
    are fetched once and shared, because one advisory routinely covers many
    packages and the per-id endpoint is the expensive half of this path.
    """
    triples = _resolved_versions(repo, include_python)
    if not triples:
        return [], "osv-api", []
    # This path resolves the manifests itself, so "what did it actually read"
    # is the set of packages it resolved rather than a list of files.
    sources = sorted({f"{eco}:{name}" for eco, name, _v in triples})

    queries = [
        {"package": {"name": name, "ecosystem": eco}, "version": version}
        for eco, name, version in triples
    ]
    id_lists: list[list[str]] = []
    for start in range(0, len(queries), batch):
        chunk = queries[start : start + batch]
        response = _http_json(OSV_QUERYBATCH, {"queries": chunk})
        results = response.get("results", [])
        # The API answers positionally. A short reply would shift every
        # advisory onto the wrong package, so pad instead of zipping blind.
        results = results + [{}] * (len(chunk) - len(results))
        for result in results[: len(chunk)]:
            id_lists.append(
                [v.get("id") for v in (result.get("vulns") or []) if v.get("id")]
            )

    wanted = {vuln_id for ids in id_lists for vuln_id in ids}
    records: dict[str, dict] = {}
    for vuln_id in sorted(wanted):
        try:
            records[vuln_id] = _http_json(OSV_VULN + vuln_id)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError):
            continue

    details: list[dict] = []
    for (eco, name, version), vuln_ids in zip(triples, id_lists):
        for vuln_id in vuln_ids:
            record = records.get(vuln_id)
            if record is None:
                continue
            details.append(_row_from_osv_record(record, eco, name, version))
    return details, "osv-api", sources


def _row_from_osv_record(record: dict, ecosystem: str, name: str, version: str) -> dict:
    """One OSV record -> one CSV row, in the same shape ``scan.py`` emits."""
    # Same range selection as the binary path, and shared rather than
    # reimplemented: the two engines have to agree on what a finding is, or a
    # result means something different depending on whether osv-scanner
    # happened to be installed. A test pins the column set; this keeps the
    # values honest too.
    from osv_scanner_tool.scan import _range_for_version

    affected = record.get("affected") or [{}]
    ranges = _range_for_version(affected, version)
    fixed = [
        event.get("fixed")
        for rng in ranges
        for event in (rng.get("events") or [])
        if event.get("fixed")
    ]
    introduced = [
        event.get("introduced")
        for rng in ranges
        for event in (rng.get("events") or [])
        if event.get("introduced")
    ]
    severity = record.get("severity") or []
    references = record.get("references") or []
    primary = next(
        (r.get("url", "") for r in references if r.get("type") == "ADVISORY"),
        references[0].get("url", "") if references else "",
    )
    return {
        "package": name,
        "version": version,
        "ecosystem": ecosystem,
        "source_file": "",
        "osv_id": record.get("id", ""),
        "aliases": " | ".join(record.get("aliases") or []),
        "summary": record.get("summary", ""),
        "cvss_vector": " | ".join(s.get("score", "") for s in severity),
        "severity_score": (record.get("database_specific") or {}).get("severity", ""),
        "fixed_version": "; ".join(dict.fromkeys(fixed)),
        "introduced_version": "; ".join(dict.fromkeys(introduced)),
        "published": record.get("published", ""),
        "modified": record.get("modified", ""),
        "details": (record.get("details") or "").replace("\n", " ").strip(),
        "references": primary,
    }


# --------------------------------------------------------------------------
# Advisory JSON
# --------------------------------------------------------------------------


def _safe_filename(text: str) -> str:
    return _UNSAFE_FILENAME.sub("-", text).strip("-") or "advisory"


def clear_generated_advisories(directory: Path | str) -> int:
    """Delete previously generated advisory files. Returns how many went."""
    directory = Path(directory)
    if not directory.is_dir():
        return 0
    removed = 0
    for path in directory.glob("*.json"):
        path.unlink()
        removed += 1
    return removed


def write_advisory_files(
    scan: OsvScan,
    directory: Path | str,
    repo: str = "",
    ecosystem: str = "npm",
    clean: bool = True,
) -> list[Path]:
    """Merged advisories -> the advisory-contract JSON both UIs read.

    The contract is one *package* per file while an OSV advisory can name
    several, so an advisory spanning three packages becomes three files. The
    alternative -- one file per advisory, naming one package -- would silently
    drop exposure the scan actually found.

    Only ``ecosystem`` is emitted. Versions on the far side of the contract
    are matched with npm range semantics, so writing a PyPI advisory into a
    file the npm matcher reads is a wrong answer waiting to happen.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    if clean:
        clear_generated_advisories(directory)

    want = ecosystem.strip().lower()
    in_ecosystem = {
        (f.package, f.version)
        for f in scan.findings
        if f.ecosystem.strip().lower() == want
    }

    written: list[Path] = []
    for advisory in scan.advisories.values():
        by_package: dict[str, list[str]] = {}
        fixes: dict[str, set[str]] = {}
        for (name, version), fixed in sorted(advisory.affected.items()):
            if (name, version) not in in_ecosystem:
                continue
            by_package.setdefault(name, []).append(version)
            if fixed:
                fixes.setdefault(name, set()).add(fixed)

        for name, versions in by_package.items():
            payload = {
                "advisory_id": advisory.advisory_id,
                "ecosystem": ecosystem,
                "package": name,
                "affected_versions": sorted(set(versions)),
                # Exact versions, so no range. The scan reports what the repo
                # actually resolved; a range synthesised around it would claim
                # coverage of versions nothing here observed.
                "affected_range": "",
                "published_at": advisory.published or schema.UNKNOWN_TS,
                "withdrawn_at": schema.STILL_LIVE,
                "severity": advisory.severity_label or "unknown",
                "summary": advisory.summary or advisory.details[:200],
                "cvss_vector": advisory.cvss_vector,
                "aliases": sorted(advisory.aliases),
                "fixed_versions": sorted(fixes.get(name, ())),
                "references": sorted(advisory.references)[:5],
                # Provenance, so a reader can tell a scanned advisory from a
                # hand-written sample without diffing the directory.
                "source": "osv-scan",
                "scanned_repo": repo,
                "generated_at": int(time.time()),
                "iocs": {"paths": [], "sha256": [], "content_markers": []},
            }
            path = directory / (
                f"{_safe_filename(advisory.advisory_id)}__{_safe_filename(name)}.json"
            )
            path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            written.append(path)
    return sorted(written)


# --------------------------------------------------------------------------
# The pipeline
# --------------------------------------------------------------------------


def scan_repository(
    repo: Path | str,
    out_dir: Path | str | None = None,
    advisory_dir: Path | str | None = DEFAULT_ADVISORY_DIR,
    engine: str = "auto",
    include_python: bool = False,
    ecosystem: str = "npm",
    verbose: bool = True,
) -> ScanRun:
    """Scan ``repo`` and write both graph inputs, timing every stage.

    Args:
        repo: the repository -- or fleet directory -- to scan.
        out_dir: where ``osv_scan_results.csv`` lands. Defaults to
            ``data/osv/<repo name>/``.
        advisory_dir: where the advisory JSON files land, or None to skip them
            and produce the CSV alone.
        engine: ``auto`` (binary if installed, API otherwise), ``binary`` or
            ``api``.
        include_python: also resolve ``requirements.txt`` with pip on the API
            path. Off by default: a cold pip resolution is minutes, not
            seconds, and the binary path reads those manifests itself.
        ecosystem: which ecosystem the advisory JSON files cover.
    """
    from osv_scanner_tool import deps
    from osv_scanner_tool.scan import CSV_FIELDS

    repo = Path(repo)
    if not repo.is_dir():
        raise FileNotFoundError(f"no such directory: {repo}")
    repo = repo.resolve()

    out_dir = Path(out_dir) if out_dir else DEFAULT_OUT / _safe_filename(repo.name)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "osv_scan_results.csv"

    run = ScanRun(repo=str(repo), started_at=time.time())
    timer = _Timer(verbose=verbose)

    if verbose:
        print(f"\nscanning {repo}")

    # -- 1. what is there to scan -----------------------------------------

    def discover():
        from ..ingest.ignore import load_ignores, split_ignored

        patterns = load_ignores(repo)
        manifests = deps.find_manifests(repo)
        found: dict[str, list[str]] = {}
        dropped: list[Path] = []
        for kind, paths in manifests.items():
            kept, skipped = split_ignored(paths, repo, patterns)
            found[kind] = [str(p) for p in kept]
            dropped.extend(skipped)
        run.ignored_manifests = [str(p) for p in dropped]
        counts = ", ".join(f"{k}={len(v)}" for k, v in sorted(found.items()))
        if dropped:
            counts += f", {len(dropped)} ignored"
        return found, counts

    run.manifests = timer.run("discover manifests", discover)
    if not any(run.manifests.values()):
        run.notes.append(
            "No package-lock.json or requirements.txt found under this path. "
            "Nothing to scan -- point at a directory holding a resolved manifest."
        )

    # -- 2. the scan itself ------------------------------------------------

    binary = osv_scanner_available()
    if engine == "binary" and not binary:
        raise RuntimeError(
            "osv-scanner is not on PATH. Install it with\n"
            "  go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest\n"
            "or run with --engine api."
        )
    use_binary = engine == "binary" or (engine == "auto" and binary)

    def do_scan():
        if use_binary:
            rows, name, sources = _scan_with_binary(repo)
        else:
            rows, name, sources = _scan_with_api(repo, include_python)
        return (rows, name, sources), (
            f"{len(rows)} row(s) from {len(sources)} source(s) via {name}"
        )

    rows, run.engine, run.sources = timer.run(
        "osv scan (binary)" if use_binary else "osv scan (api)", do_scan
    )

    # The distinction that matters more than any other here. A scanner that
    # walked the tree and opened nothing reports exactly what a clean repo
    # reports -- zero findings -- and "you have no vulnerabilities" is the one
    # wrong answer this tool must never give quietly. osv-scanner honours
    # .gitignore by default, and the repos under test live in a directory that
    # is git-ignored on purpose, so this is not a hypothetical.
    manifest_count = sum(len(v) for v in run.manifests.values())
    if manifest_count and not run.sources:
        run.blind = True
        run.notes.append(
            f"NOTHING WAS SCANNED. {manifest_count} manifest(s) are on disk but "
            f"the scanner parsed none of them, so 'no findings' here means "
            f"'no answer', not 'no vulnerabilities'. The usual cause is that "
            f"the path is excluded by a .gitignore -- osv-scanner honours one "
            f"unless it is run with --no-ignore."
        )
    if not use_binary and engine == "auto":
        run.notes.append(
            "osv-scanner is not installed, so this ran against api.osv.dev over "
            "the versions the lockfiles resolve. Same advisories, one network "
            "hop; install the binary for the path that works offline."
        )

    # -- 2b. drop findings from directories this repo disowns ---------------
    #
    # Filtering discovery is not enough. `osv-scanner scan --recursive` walks
    # the tree itself and has no idea about `.blastradiusignore`, so a demo
    # corpus or a test fixture still comes back with findings attached. Left
    # in, those advisories materialise PackageVersion nodes for packages no
    # service resolved -- findings against code the repository does not ship,
    # which is exactly what the ignore file was added to prevent.
    #
    # Rows are matched on their `source_file`. A row without one is kept: an
    # unattributable finding is not evidence that it came from an ignored
    # place, and dropping it would be the silent narrowing this guards against.

    def filter_ignored():
        from ..ingest.ignore import is_ignored, load_ignores

        patterns = load_ignores(repo)
        kept, dropped = [], 0
        for row in rows:
            source = row.get("source_file") or ""
            if source and is_ignored(Path(source), repo, patterns):
                dropped += 1
                continue
            kept.append(row)
        return (kept, dropped), (
            f"{dropped} row(s) from ignored paths dropped" if dropped
            else "nothing ignored"
        )

    (rows, run.ignored_rows) = timer.run("apply .blastradiusignore", filter_ignored)
    if run.ignored_manifests or run.ignored_rows:
        run.notes.append(
            f"{len(run.ignored_manifests)} manifest(s) and {run.ignored_rows} "
            f"finding(s) were excluded by {IGNORE_FILE} at the scan root. They "
            f"are on disk and were deliberately not treated as this project's "
            f"code."
        )

    # -- 3. the CSV contract -----------------------------------------------

    def write_csv():
        import csv as _csv

        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = _csv.DictWriter(handle, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: row.get(k, "") for k in CSV_FIELDS})
        return csv_path, f"{csv_path.name} ({csv_path.stat().st_size:,} bytes)"

    run.csv_path = timer.run("write csv", write_csv)

    # -- 4. alias merge ----------------------------------------------------

    def merge():
        parsed = load_osv_csv(csv_path)
        return parsed, parsed.summary()

    scan = timer.run("merge aliases", merge)
    run.scan = scan
    run.findings = len(scan.findings)
    run.advisories = len(scan.advisories)
    run.ecosystems = scan.ecosystems()
    run.packages = len({f.package for f in scan.findings})

    counts: dict[str, int] = {}
    for finding in scan.findings:
        spec = f"{finding.package}@{finding.version}"
        counts[spec] = counts.get(spec, 0) + 1
    run.top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:8]

    # -- 5. advisory JSON --------------------------------------------------

    if advisory_dir is not None:

        def emit():
            files = write_advisory_files(
                scan, advisory_dir, repo=str(repo), ecosystem=ecosystem
            )
            return files, f"{len(files)} file(s)"

        run.advisory_dir = Path(advisory_dir)
        run.advisory_files = timer.run("write advisory json", emit)

    run.steps = timer.steps
    run.elapsed_s = timer.total
    return run
