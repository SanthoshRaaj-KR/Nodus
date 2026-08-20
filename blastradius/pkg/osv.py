"""Reader for OSV scan results (``osv_scan_results.csv``).

This is the system's input contract. The columns are what matter; the rows in
any particular file are not, so the reader routes on the ``ecosystem`` column
rather than assuming npm, and reports what it skipped instead of dropping it
silently.

Two properties of the real data drive the design:

**Rows are advisory-package-version triples, not advisories.** One vulnerable
package produces one row per advisory that touches it, so counting rows counts
findings, never distinct vulnerabilities.

**The same vulnerability arrives repeatedly under different identifiers.** OSV,
GHSA, CVE and the ecosystem-specific feeds each mint an id and cross-reference
the others through the pipe-separated ``aliases`` column. In the sample file,
``pyjwt@2.9.0`` carries thirteen rows that collapse to far fewer real
advisories. Reporting thirteen would overstate the exposure of every project
that holds that package, so aliases are resolved transitively -- if A lists B
and B lists C, all three are one advisory even when A never mentions C. That is
a connected-components problem, and it is solved here with union-find rather
than a single pass, because a single pass over a sparse alias list merges only
the pairs it happens to see first.
"""

from __future__ import annotations

import csv
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .. import schema

__all__ = [
    "Finding",
    "Advisory",
    "OsvScan",
    "load_osv_csv",
    "parse_timestamp",
    "AliasResolver",
    "SEVERITY_RANK",
    "severity_rank",
]


# --------------------------------------------------------------------------
# Severity labels
# --------------------------------------------------------------------------

#: The vocabulary OSV actually uses, ranked so two rows describing the same
#: advisory can be merged without a tie-break argument. "medium" and
#: "moderate" are the same rung under two names -- GHSA says one, several CVE
#: mirrors say the other.
SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "moderate": 2,
    "medium": 2,
    "low": 1,
    "": 0,
}


def severity_rank(label: str | None) -> int:
    """Rank a severity word. Anything unrecognised ranks below "low"."""
    return SEVERITY_RANK.get((label or "").strip().lower(), 0)


# --------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------

def parse_timestamp(raw: str | None) -> int:
    """ISO-8601 to epoch seconds, or the unknown sentinel.

    HydraDB's sum/avg are unsigned-int only and there is no date type, so every
    time in the graph is an epoch-second integer. Unknown becomes 0, which can
    never fall inside a live window -- so a missing timestamp reports as
    unknown rather than as exposure.
    """
    if not raw or not isinstance(raw, str) or not raw.strip():
        return schema.UNKNOWN_TS
    text = raw.strip().replace("Z", "+00:00")
    # Feeds emit more sub-second digits than fromisoformat accepts on some
    # versions; clamp the fraction to microseconds.
    text = re.sub(r"\.(\d{6})\d+", r".\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return schema.UNKNOWN_TS
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


# --------------------------------------------------------------------------
# Alias resolution
# --------------------------------------------------------------------------

#: Preference order when choosing which id represents a merged advisory. CVE is
#: first because it is the identifier a reader is most likely to recognise and
#: to find elsewhere; the rest are kept and reported as aliases.
_ID_RANK = {"CVE": 0, "GHSA": 1, "OSV": 2}


def _id_rank(advisory_id: str) -> tuple[int, str]:
    prefix = advisory_id.split("-", 1)[0].upper()
    return (_ID_RANK.get(prefix, 3), advisory_id)


class AliasResolver:
    """Union-find over advisory identifiers.

    Transitivity is the reason this is not a dict lookup: a feed may publish
    A->B and, separately, B->C, without anything ever stating A->C. Treating
    those as two advisories double-counts the same vulnerability.
    """

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def _find(self, item: str) -> str:
        self._parent.setdefault(item, item)
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        # Path compression, so repeated lookups during ingest stay flat.
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self._find(a), self._find(b)
        if ra != rb:
            # Keep the better-ranked id as the root so canonical() is stable
            # regardless of the order rows arrive in.
            winner, loser = sorted((ra, rb), key=_id_rank)
            self._parent[loser] = winner

    def add(self, advisory_id: str, aliases: list[str]) -> None:
        self._find(advisory_id)
        for alias in aliases:
            self.union(advisory_id, alias)

    def canonical(self, advisory_id: str) -> str:
        return self._find(advisory_id)

    def groups(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = defaultdict(set)
        for item in self._parent:
            out[self._find(item)].add(item)
        return dict(out)


def _split_aliases(raw: str | None) -> list[str]:
    """``"CVE-2026-32597 | GHSA-752w-5fwx-jx9f"`` -> both ids."""
    if not raw:
        return []
    return [part.strip() for part in re.split(r"[|,]", raw) if part.strip()]


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    """One row: this advisory affects this package at this version."""

    package: str
    version: str
    ecosystem: str
    source_file: str
    osv_id: str
    aliases: tuple[str, ...]
    summary: str
    cvss_vector: str
    severity_score: float | None
    #: The qualitative label OSV carries in ``database_specific.severity``
    #: ("HIGH", "MODERATE", ...). It arrives in the ``severity_score`` column,
    #: which is numeric for some feeds and a label for others; the reader keeps
    #: whichever form it got rather than discarding the one it cannot cast.
    severity_label: str
    fixed_version: str
    #: Where the vulnerable range opens. OSV states it as an `introduced`
    #: event, so this is what the advisory says rather than the earliest
    #: affected version we happen to hold -- the two differ whenever the
    #: graph does not materialise a package's whole history, which is
    #: always. OSV writes "0" for "since the first release"; that is kept
    #: verbatim, because it is a real answer and not a missing one.
    introduced_version: str
    published: int
    modified: int
    details: str
    references: tuple[str, ...]

    @property
    def is_npm(self) -> bool:
        return self.ecosystem.strip().lower() == "npm"


@dataclass
class Advisory:
    """A vulnerability, after aliases have been merged.

    Distinct from an Incident by design. An advisory says a version has a
    known flaw; an incident says a version was tampered with. Scoring them the
    same would let a decade-old low-severity CVE outrank an active compromise.
    """

    advisory_id: str
    aliases: set[str] = field(default_factory=set)
    summary: str = ""
    details: str = ""
    cvss_vector: str = ""
    #: Deriving the base score from the vector is a TODO -- the source data
    #: leaves severity_score empty while populating cvss_vector, so anything
    #: shown today would be invented. Until then this stays at the sentinel and
    #: the UI shows the vector rather than a number nobody computed.
    severity_score: float = float(schema.UNKNOWN_SCORE)
    #: Worst label seen across the merged rows. Empty when no feed gave one.
    severity_label: str = ""
    published: int = schema.UNKNOWN_TS
    modified: int = schema.UNKNOWN_TS
    references: set[str] = field(default_factory=set)
    #: (normalized package name, version) -> fixed_version or ""
    affected: dict[tuple[str, str], str] = field(default_factory=dict)
    #: normalized package name -> the version the vulnerable range opens at.
    #: Per package, not per (package, version): "which version introduced it"
    #: is a fact about the package's history, and every affected version of
    #: one package shares the same answer.
    introduced: dict[str, str] = field(default_factory=dict)

    @property
    def all_ids(self) -> list[str]:
        return sorted({self.advisory_id, *self.aliases})

    def merge(self, finding: Finding) -> None:
        self.aliases.update({finding.osv_id, *finding.aliases})
        self.aliases.discard(self.advisory_id)
        # Keep the longest prose seen: feeds vary in how much they carry, and
        # the fuller text is the more useful one to show.
        if len(finding.summary) > len(self.summary):
            self.summary = finding.summary
        if len(finding.details) > len(self.details):
            self.details = finding.details
        if finding.cvss_vector and not self.cvss_vector:
            self.cvss_vector = finding.cvss_vector
        if finding.severity_score is not None:
            self.severity_score = finding.severity_score
        # Worst wins. Two rows for one advisory can disagree when they came
        # from different feeds, and under-reporting severity is the direction
        # that costs someone an incident.
        if severity_rank(finding.severity_label) > severity_rank(self.severity_label):
            self.severity_label = finding.severity_label
        if finding.published and self.published in (schema.UNKNOWN_TS,):
            self.published = finding.published
        # Newest modification wins; there is no max() aggregate downstream, so
        # this is settled here.
        if finding.modified > self.modified:
            self.modified = finding.modified
        self.references.update(finding.references)
        key = (finding.package, finding.version)
        if finding.fixed_version or key not in self.affected:
            self.affected[key] = finding.fixed_version
        # First non-empty wins rather than last. Rows for one advisory repeat
        # the same range once per affected version, so they agree; when a feed
        # omits it on some rows, keeping the first real answer beats letting a
        # later blank overwrite it.
        if finding.introduced_version and not self.introduced.get(finding.package):
            self.introduced[finding.package] = finding.introduced_version


@dataclass
class OsvScan:
    """The parsed scan: raw findings plus alias-merged advisories."""

    findings: list[Finding] = field(default_factory=list)
    advisories: dict[str, Advisory] = field(default_factory=dict)
    skipped: list[tuple[int, str]] = field(default_factory=list)
    source_path: str = ""

    def for_ecosystem(self, ecosystem: str) -> list[Finding]:
        want = ecosystem.strip().lower()
        return [f for f in self.findings if f.ecosystem.strip().lower() == want]

    def ecosystems(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for finding in self.findings:
            counts[finding.ecosystem] += 1
        return dict(counts)

    def advisories_for_ecosystem(self, ecosystem: str) -> list[Advisory]:
        want = ecosystem.strip().lower()
        keep = {
            (f.package, f.version)
            for f in self.findings
            if f.ecosystem.strip().lower() == want
        }
        return [
            adv
            for adv in self.advisories.values()
            if any(k in keep for k in adv.affected)
        ]

    def summary(self) -> str:
        eco = ", ".join(f"{k}={v}" for k, v in sorted(self.ecosystems().items()))
        return (
            f"{len(self.findings)} findings -> {len(self.advisories)} advisories "
            f"after alias merge ({eco or 'no rows'}"
            + (f", {len(self.skipped)} skipped" if self.skipped else "")
            + ")"
        )


_REQUIRED_COLUMNS = {"package", "version", "ecosystem", "osv_id"}


def load_osv_csv(path: str | Path, normalize_npm_names: bool = True) -> OsvScan:
    """Parse an OSV scan CSV into findings and alias-merged advisories.

    ``normalize_npm_names`` folds npm package names to their canonical form so
    they join to the graph. Names from other ecosystems are left verbatim,
    because their normalisation rules differ (PyPI, for one, also folds
    underscores against hyphens) and applying npm's rules to them would be
    quietly wrong.
    """
    path = Path(path)
    scan = OsvScan(source_path=str(path))

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = _REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"{path} is missing required column(s): {sorted(missing)}; "
                f"found {reader.fieldnames}"
            )

        resolver = AliasResolver()
        rows: list[Finding] = []

        for line_no, row in enumerate(reader, start=2):
            package = (row.get("package") or "").strip()
            version = (row.get("version") or "").strip()
            osv_id = (row.get("osv_id") or "").strip()
            ecosystem = (row.get("ecosystem") or "").strip()

            if not package or not osv_id:
                scan.skipped.append((line_no, "missing package or osv_id"))
                continue
            if not version:
                # Without a version there is nothing to attach security state
                # to -- the whole point is that a package is not compromised,
                # a version is.
                scan.skipped.append((line_no, f"{package}: no version"))
                continue

            if normalize_npm_names and ecosystem.strip().lower() == "npm":
                from .identity import InvalidPackageName, normalize_name

                try:
                    package = normalize_name(package)
                except InvalidPackageName as exc:
                    scan.skipped.append((line_no, f"{package}: {exc}"))
                    continue

            # One column, two shapes. osv-scanner copies
            # ``database_specific.severity`` here, which is a number for some
            # feeds and a word ("HIGH") for GHSA imports. Casting blind threw
            # the label away and left every scanned advisory unrated.
            raw_score = (row.get("severity_score") or "").strip()
            try:
                score = float(raw_score) if raw_score else None
            except ValueError:
                score = None
            label = "" if score is not None else raw_score.strip().lower()
            if label and label not in SEVERITY_RANK:
                # An unrecognised word is not a severity; keeping it would put
                # an unranked string in front of a reader as though it meant
                # something.
                scan.skipped.append((line_no, f"{package}: unknown severity {raw_score!r}"))
                label = ""

            aliases = _split_aliases(row.get("aliases"))
            finding = Finding(
                package=package,
                version=version,
                ecosystem=ecosystem,
                source_file=(row.get("source_file") or "").strip(),
                osv_id=osv_id,
                aliases=tuple(aliases),
                summary=(row.get("summary") or "").strip(),
                cvss_vector=(row.get("cvss_vector") or "").strip(),
                severity_score=score,
                severity_label=label,
                fixed_version=(row.get("fixed_version") or "").strip(),
                introduced_version=(row.get("introduced_version") or "").strip(),
                published=parse_timestamp(row.get("published")),
                modified=parse_timestamp(row.get("modified")),
                details=(row.get("details") or "").strip(),
                references=tuple(_split_aliases(row.get("references"))),
            )
            rows.append(finding)
            resolver.add(osv_id, aliases)

    scan.findings = rows

    # Second pass: now that every alias link is known, fold rows into
    # advisories. This cannot be done during the first pass, because the link
    # that merges two ids may appear on a later row than either of them.
    for finding in rows:
        canonical = resolver.canonical(finding.osv_id)
        advisory = scan.advisories.get(canonical)
        if advisory is None:
            advisory = Advisory(advisory_id=canonical)
            scan.advisories[canonical] = advisory
        advisory.merge(finding)

    return scan
