"""The teammate contract: an advisory in, exact PackageVersion keys out.

Version-range matching happens here rather than in Cypher because HydraDB's
`WHERE` has no string functions -- there is no way to compare "5.62.3" against
">=5.62.3 <5.62.5" in the query language. So Python resolves the range against
the versions we actually hold and hands the graph exact ids. That is the
general pattern in this codebase: precompute, then let the graph do the join.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import schema

_VERSION = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: tuple = field(default=())

    @classmethod
    def parse(cls, text: str) -> "Version | None":
        match = _VERSION.match(text.strip())
        if not match:
            return None
        major, minor, patch, pre = match.groups()
        parts: tuple = ()
        if pre:
            parts = tuple(int(p) if p.isdigit() else p for p in pre.split("."))
        return cls(int(major), int(minor or 0), int(patch or 0), parts)

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return f"{base}-{'.'.join(str(p) for p in self.prerelease)}" if self.prerelease else base

    def _cmp_key(self):
        # A release outranks any prerelease of the same version, so an absent
        # prerelease sorts high. Mixed int/str parts compare by type tag first
        # to stay orderable.
        return (
            self.major,
            self.minor,
            self.patch,
            1 if not self.prerelease else 0,
            tuple((0, p, "") if isinstance(p, int) else (1, 0, p) for p in self.prerelease),
        )

    def __lt__(self, other: "Version") -> bool:
        return self._cmp_key() < other._cmp_key()

    def __le__(self, other: "Version") -> bool:
        return self._cmp_key() <= other._cmp_key()

    def __gt__(self, other: "Version") -> bool:
        return self._cmp_key() > other._cmp_key()

    def __ge__(self, other: "Version") -> bool:
        return self._cmp_key() >= other._cmp_key()


def _upper_bound_caret(v: Version) -> Version:
    """npm's caret: compatible within the leftmost non-zero component."""
    if v.major > 0:
        return Version(v.major + 1, 0, 0)
    if v.minor > 0:
        return Version(0, v.minor + 1, 0)
    return Version(0, 0, v.patch + 1)


def _satisfies_comparator(version: Version, comparator: str) -> bool:
    comparator = comparator.strip()
    if not comparator or comparator in ("*", "x", "X", ""):
        return True

    match = re.match(r"^(>=|<=|>|<|=|\^|~)?\s*(.+)$", comparator)
    if not match:
        return False
    operator, raw = match.groups()
    target = Version.parse(raw)
    if target is None:
        return False

    if operator == ">=":
        return version >= target
    if operator == "<=":
        return version <= target
    if operator == ">":
        return version > target
    if operator == "<":
        return version < target
    if operator == "^":
        return target <= version < _upper_bound_caret(target)
    if operator == "~":
        return target <= version < Version(target.major, target.minor + 1, 0)
    return version == target


def satisfies(version_text: str, range_text: str) -> bool:
    """Does ``version_text`` fall inside the npm range ``range_text``?

    Supports the forms advisories actually use: comparators, ``^``, ``~``,
    hyphen ranges, space-separated AND, and ``||`` OR. Anything more exotic is
    rejected loudly by the caller rather than quietly matching nothing.
    """
    version = Version.parse(version_text)
    if version is None:
        return False

    for clause in range_text.split("||"):
        clause = clause.strip()
        if not clause:
            continue
        hyphen = re.match(r"^(\S+)\s+-\s+(\S+)$", clause)
        if hyphen:
            low, high = (Version.parse(g) for g in hyphen.groups())
            if low and high and low <= version <= high:
                return True
            continue
        if all(_satisfies_comparator(version, c) for c in clause.split()):
            return True
    return False


@dataclass
class Advisory:
    """One compromised package, as produced by the advisory-discovery half."""

    advisory_id: str
    package: str
    ecosystem: str = "npm"
    affected_versions: list[str] = field(default_factory=list)
    affected_range: str = ""
    published_at: int = schema.UNKNOWN_TS
    withdrawn_at: int = schema.STILL_LIVE
    severity: str = "unknown"
    ioc_paths: list[str] = field(default_factory=list)
    content_markers: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict) -> "Advisory":
        iocs = raw.get("iocs") or {}
        return cls(
            advisory_id=raw.get("advisory_id", "UNKNOWN"),
            package=raw["package"],
            ecosystem=raw.get("ecosystem", "npm"),
            affected_versions=list(raw.get("affected_versions") or []),
            affected_range=raw.get("affected_range", ""),
            published_at=int(raw.get("published_at") or schema.UNKNOWN_TS),
            withdrawn_at=int(raw.get("withdrawn_at") or schema.STILL_LIVE),
            severity=raw.get("severity", "unknown"),
            ioc_paths=list(iocs.get("paths") or []),
            content_markers=list(iocs.get("content_markers") or []),
        )

    @classmethod
    def load(cls, path: Path | str) -> "Advisory":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def matches(self, version: str) -> bool:
        """Is this exact version affected?"""
        if self.affected_versions:
            return version in self.affected_versions
        if self.affected_range:
            return satisfies(version, self.affected_range)
        return False

    def keys_among(self, held_versions: list[str]) -> list[str]:
        """``name@version`` keys, from the versions we hold, that are affected.

        ``held_versions`` is every version of this package present anywhere in
        the corpus. Restricting to what we hold keeps the id list small and
        means an advisory covering 400 versions costs the same as one covering
        two.
        """
        return [
            f"{self.package}@{v}" for v in held_versions if self.matches(v)
        ]
