"""npm semver: version parsing, comparison, and range satisfaction.

This module is the accuracy core of the whole system. HydraDB has no string
functions and no regex, so a semver range can never be evaluated inside a
query -- every "does this range admit this version" decision is made here, in
Python, at ingest time, and the answer is frozen into a ``SATISFIED_BY`` edge.
A bug here is not a slow query, it is a wrong security finding.

Written against the node-semver grammar rather than pulled from a library, so
the prerelease rule below is auditable. That rule is the one most often gotten
wrong, and getting it wrong produces exactly the failure this tool exists to
avoid: a package flagged as exposed when it never could have resolved the bad
version.

    A version carrying a prerelease tag satisfies a comparator set only when
    some comparator in that set has the *same* (major, minor, patch) tuple and
    also carries a prerelease tag.

So ``>=1.2.3-alpha`` does not admit ``3.4.5-beta``, even though 3.4.5-beta
sorts higher: nobody asking for a 1.2.3 prerelease wants to be handed an
unrelated 3.4.5 prerelease. Without this rule every range with a prerelease
bound quietly over-matches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Iterable, Sequence

__all__ = [
    "Version",
    "Range",
    "InvalidVersion",
    "InvalidRange",
    "parse",
    "satisfies",
    "filter_satisfying",
    "max_satisfying",
]


class InvalidVersion(ValueError):
    """A version string that is not valid semver."""


class InvalidRange(ValueError):
    """A range expression that could not be parsed."""


# A leading 'v' and surrounding space are tolerated because real package.json
# files contain both. Everything else must be well-formed.
_VERSION_RE = re.compile(
    r"^[v=\s]*"
    r"(?P<major>0|[1-9]\d*)"
    r"\.(?P<minor>0|[1-9]\d*)"
    r"\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+(?P<build>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?"
    r"\s*$"
)

_NUMERIC_RE = re.compile(r"^(0|[1-9]\d*)$")


def _prerelease_parts(raw: str | None) -> tuple:
    """Split a prerelease tag into comparable identifiers.

    Numeric identifiers compare numerically, alphanumeric ones compare by
    ASCII. They are tagged (0, n) and (1, s) so a numeric identifier always
    sorts below an alphanumeric one, which is what the spec requires.
    """
    if not raw:
        return ()
    parts = []
    for item in raw.split("."):
        if _NUMERIC_RE.match(item):
            parts.append((0, int(item), ""))
        else:
            parts.append((1, 0, item))
    return tuple(parts)


@dataclass(frozen=True)
class Version:
    """A parsed semver version.

    Build metadata is retained for display but ignored in comparison, per the
    spec -- ``1.0.0+build.1`` and ``1.0.0+build.2`` are the same version.
    """

    major: int
    minor: int
    patch: int
    prerelease: str = ""
    build: str = ""
    raw: str = ""

    _key: tuple = field(default=(), compare=False, repr=False)

    def __post_init__(self):
        # Precomputed sort key. Versions are compared in the innermost loop of
        # range expansion, so this is worth caching on the instance.
        pre = _prerelease_parts(self.prerelease)
        # A version with no prerelease outranks one that has any, so tag the
        # absence as 1 and the presence as 0.
        object.__setattr__(
            self, "_key", (self.major, self.minor, self.patch, 0 if pre else 1, pre)
        )

    # -- ordering ---------------------------------------------------------

    def __lt__(self, other: "Version") -> bool:
        return self._compare(other) < 0

    def __le__(self, other: "Version") -> bool:
        return self._compare(other) <= 0

    def __gt__(self, other: "Version") -> bool:
        return self._compare(other) > 0

    def __ge__(self, other: "Version") -> bool:
        return self._compare(other) >= 0

    def _compare(self, other: "Version") -> int:
        a, b = self._key, other._key
        if a[:4] != b[:4]:
            return -1 if a[:4] < b[:4] else 1
        # Prerelease identifiers: compare pairwise, then by count. A longer
        # prerelease with an equal prefix is the greater one (1.0.0-a.1 beats
        # 1.0.0-a), so length is the tiebreak.
        pa, pb = a[4], b[4]
        for x, y in zip(pa, pb):
            if x != y:
                return -1 if x < y else 1
        if len(pa) != len(pb):
            return -1 if len(pa) < len(pb) else 1
        return 0

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    @property
    def tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __str__(self) -> str:
        out = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            out += f"-{self.prerelease}"
        if self.build:
            out += f"+{self.build}"
        return out


@lru_cache(maxsize=100_000)
def parse(text: str) -> Version:
    """Parse a version string. Cached -- the same versions recur constantly."""
    if not isinstance(text, str):
        raise InvalidVersion(f"expected a string, got {type(text).__name__}")
    match = _VERSION_RE.match(text)
    if not match:
        raise InvalidVersion(f"not a valid semver version: {text!r}")
    g = match.groupdict()
    return Version(
        major=int(g["major"]),
        minor=int(g["minor"]),
        patch=int(g["patch"]),
        prerelease=g["prerelease"] or "",
        build=g["build"] or "",
        raw=text.strip(),
    )


def try_parse(text: str) -> Version | None:
    """Parse, or None. For source data we do not control."""
    try:
        return parse(text)
    except (InvalidVersion, TypeError):
        return None


# --------------------------------------------------------------------------
# Comparators
# --------------------------------------------------------------------------

#: npm supports only these comparators. `!=` is deliberately absent:
#: node-semver throws `Invalid comparator: !=1.2.3`, so accepting it would
#: make us disagree with the resolver that actually builds the lockfile.
_OPS = (">=", "<=", "==", ">", "<", "=")


@dataclass(frozen=True)
class Comparator:
    """A single bound, e.g. ``>=1.2.3``.

    ``ANY`` (from ``*`` or an empty range) is represented by op ``*`` with no
    version, and admits everything except -- per the prerelease rule -- a
    prerelease version, unless prereleases were explicitly allowed.

    ``derived_lower`` marks a lower bound that npm *inferred* rather than one
    the author wrote: the ``1.0.0`` in ``1.x``, not the ``1.2.3`` in
    ``^1.2.3``. Under ``includePrerelease`` npm lowers exactly those to
    ``1.0.0-0`` so that prereleases of the floor are admitted. Recording the
    provenance here keeps a single parsed range usable in both modes, instead
    of parsing (and caching) each range twice.
    """

    op: str
    version: Version | None
    derived_lower: bool = False

    def allows(self, v: Version) -> bool:
        if self.op == "*" or self.version is None:
            return True
        c = v._compare(self.version)
        if self.op == ">=":
            return c >= 0
        if self.op == ">":
            return c > 0
        if self.op == "<=":
            return c <= 0
        if self.op == "<":
            return c < 0
        if self.op in ("=", "=="):
            return c == 0
        raise InvalidRange(f"unknown operator {self.op!r}")

    def allows_with_prerelease_floor(self, v: Version) -> bool:
        """:meth:`allows`, with a derived floor lowered to its ``-0`` form."""
        if self.derived_lower and self.version is not None and not self.version.is_prerelease:
            floor = Version(
                self.version.major, self.version.minor, self.version.patch, "0"
            )
            return Comparator(self.op, floor).allows(v)
        return self.allows(v)

    def __str__(self) -> str:
        return "*" if self.version is None else f"{self.op}{self.version}"


def _split_partial(text: str) -> tuple[int | None, int | None, int | None, str, str]:
    """Parse a possibly-partial version like ``1``, ``1.2``, ``1.2.x``.

    Returns (major, minor, patch, prerelease, build) where a wildcard or an
    absent component is None.
    """
    text = text.strip().lstrip("v=").strip()
    if text in ("", "*", "x", "X"):
        return (None, None, None, "", "")

    pre = build = ""
    if "+" in text:
        text, build = text.split("+", 1)
    if "-" in text:
        head, pre = text.split("-", 1)
        text = head

    parts = text.split(".")
    nums: list[int | None] = []
    for part in parts[:3]:
        if part in ("x", "X", "*", ""):
            nums.append(None)
        elif _NUMERIC_RE.match(part):
            nums.append(int(part))
        else:
            raise InvalidRange(f"not a valid version component: {part!r} in {text!r}")
    while len(nums) < 3:
        nums.append(None)
    return (nums[0], nums[1], nums[2], pre, build)


def _v(major: int, minor: int, patch: int, pre: str = "") -> Version:
    return Version(major, minor, patch, pre)


def _upper(major: int, minor: int, patch: int) -> Version:
    """A derived exclusive upper bound.

    npm always emits these with a ``-0`` prerelease -- ``^1.2.3`` becomes
    ``>=1.2.3 <2.0.0-0``, never ``<2.0.0``. The sentinel sorts below every
    real prerelease of that version, so ``2.0.0-alpha`` falls outside the
    range. Without it, an "includePrerelease" scan would sweep in the first
    prerelease of the next major -- precisely the version most likely to be a
    freshly published malicious release.
    """
    return Version(major, minor, patch, "0")


def _expand_caret(text: str) -> list[Comparator]:
    """``^1.2.3`` -- compatible within the leftmost non-zero component.

    The 0.x rules are the subtle part and the reason this is spelled out:
    ``^0.2.3`` is >=0.2.3 <0.3.0 and ``^0.0.3`` is >=0.0.3 <0.0.4, because
    below 1.0.0 npm treats every release as potentially breaking.
    """
    major, minor, patch, pre, _ = _split_partial(text)
    if major is None:
        return [Comparator("*", None)]
    derived = minor is None or patch is None
    lo = _v(major, minor or 0, patch or 0, pre)
    if major != 0:
        hi = _upper(major + 1, 0, 0)
    elif minor is None:
        # ^0 and ^0.x -> >=0.0.0 <1.0.0
        hi = _upper(1, 0, 0)
    elif minor != 0 or patch is None:
        # ^0.2.3 -> <0.3.0 ; ^0.0.x -> <0.1.0
        hi = _upper(0, minor + 1, 0)
    else:
        # ^0.0.3 -> <0.0.4
        hi = _upper(0, 0, patch + 1)
    return [Comparator(">=", lo, derived), Comparator("<", hi)]


def _expand_tilde(text: str) -> list[Comparator]:
    """``~1.2.3`` -- patch-level changes if a minor is given, else minor-level."""
    major, minor, patch, pre, _ = _split_partial(text)
    if major is None:
        return [Comparator("*", None)]
    derived = minor is None or patch is None
    lo = _v(major, minor or 0, patch or 0, pre)
    if minor is None:
        hi = _upper(major + 1, 0, 0)  # ~1 -> >=1.0.0 <2.0.0
    else:
        hi = _upper(major, minor + 1, 0)  # ~1.2 and ~1.2.3 -> <1.3.0
    return [Comparator(">=", lo, derived), Comparator("<", hi)]


def _expand_xrange(op: str, text: str) -> list[Comparator]:
    """A partial or wildcard version, with an optional comparison operator.

    ``1.x`` is >=1.0.0 <2.0.0. ``>1.x`` is >=2.0.0, because "greater than any
    1.x" means the whole 1 line is excluded -- a detail that trips up naive
    implementations.
    """
    major, minor, patch, pre, _ = _split_partial(text)

    if major is None:
        # '*' with an operator is still everything, except '<' which is nothing.
        if op == "<":
            return [Comparator("<", _v(0, 0, 0))]
        return [Comparator("*", None)]

    complete = minor is not None and patch is not None

    if complete:
        return [Comparator(op or "=", _v(major, minor, patch, pre))]

    # Partial: derive the covered window. Both ends are inferred, so the upper
    # bound takes the -0 sentinel and the lower bound is marked derived.
    if minor is None:
        lo, hi = _v(major, 0, 0), _upper(major + 1, 0, 0)
    else:
        lo, hi = _v(major, minor, 0), _upper(major, minor + 1, 0)

    if op in ("", "=", "=="):
        return [Comparator(">=", lo, True), Comparator("<", hi)]
    if op == ">":
        # ">1.x" excludes the whole 1 line, so the floor is the next window.
        return [Comparator(">=", _v(hi.major, hi.minor, hi.patch), True)]
    if op == ">=":
        return [Comparator(">=", lo, True)]
    if op == "<":
        return [Comparator("<", _upper(lo.major, lo.minor, lo.patch))]
    if op == "<=":
        return [Comparator("<", hi)]
    raise InvalidRange(f"unknown operator {op!r}")


def _expand_hyphen(low: str, high: str) -> list[Comparator]:
    """``1.2.3 - 2.3.4`` is an inclusive window.

    A partial upper bound widens to the end of its window: ``1.2.3 - 2.3``
    means <2.4.0, not <=2.3.0.
    """
    lo_major, lo_minor, lo_patch, lo_pre, _ = _split_partial(low)
    hi_major, hi_minor, hi_patch, hi_pre, _ = _split_partial(high)

    out: list[Comparator] = []
    if lo_major is None:
        out.append(Comparator("*", None))
    else:
        # npm lowers a hyphen floor to its -0 form under includePrerelease even
        # when it was written in full, unlike a caret floor. Marked derived to
        # reproduce that.
        out.append(
            Comparator(">=", _v(lo_major, lo_minor or 0, lo_patch or 0, lo_pre), True)
        )

    if hi_major is None:
        pass  # open upper bound
    elif hi_minor is None:
        out.append(Comparator("<", _upper(hi_major + 1, 0, 0)))
    elif hi_patch is None:
        out.append(Comparator("<", _upper(hi_major, hi_minor + 1, 0)))
    else:
        out.append(Comparator("<=", _v(hi_major, hi_minor, hi_patch, hi_pre)))
    return out


_HYPHEN_RE = re.compile(r"^\s*(?P<low>[^\s]+)\s+-\s+(?P<high>[^\s]+)\s*$")


def _parse_comparator_set(text: str) -> list[Comparator]:
    """One AND-joined group, e.g. ``>=1.2.3 <2.0.0``."""
    text = text.strip()
    if not text or text in ("*", "x", "X", "latest"):
        return [Comparator("*", None)]

    hyphen = _HYPHEN_RE.match(text)
    if hyphen:
        return _expand_hyphen(hyphen.group("low"), hyphen.group("high"))

    out: list[Comparator] = []
    for token in text.split():
        if not token:
            continue
        if token.startswith(("!=", "!==", "===")):
            # node-semver throws `Invalid comparator` on these. Refusing keeps
            # us aligned with the resolver; guessing a meaning would put edges
            # in the graph that npm would never create.
            raise InvalidRange(
                f"npm does not support the {token[:2]!r} comparator: {token!r}"
            )
        if token.startswith("^"):
            out.extend(_expand_caret(token[1:]))
            continue
        if token.startswith("~"):
            # ~> is an alias for ~ in some manifests.
            out.extend(_expand_tilde(token.lstrip("~>")))
            continue
        op = ""
        for candidate in _OPS:
            if token.startswith(candidate):
                op = candidate
                token = token[len(candidate) :]
                break
        out.extend(_expand_xrange(op, token))
    return out or [Comparator("*", None)]


@dataclass(frozen=True)
class Range:
    """A parsed npm range: an OR of AND-groups of comparators."""

    sets: tuple[tuple[Comparator, ...], ...]
    raw: str = ""

    def satisfied_by(self, v: Version, include_prerelease: bool = False) -> bool:
        return any(
            _set_allows(group, v, include_prerelease) for group in self.sets
        )

    def __str__(self) -> str:
        return self.raw or " || ".join(
            " ".join(str(c) for c in group) for group in self.sets
        )


def _set_allows(
    group: Sequence[Comparator], v: Version, include_prerelease: bool
) -> bool:
    """Does one AND-group admit this version?

    The prerelease rule lives here rather than in Comparator.allows, because
    it is a property of the *set*: a prerelease version is admitted only if
    some comparator in this same group pins the same (major, minor, patch) and
    is itself a prerelease. See the module docstring.
    """
    if include_prerelease:
        # Derived floors drop to their -0 form, matching how npm rebuilds the
        # range under this option.
        return all(c.allows_with_prerelease_floor(v) for c in group)

    for comparator in group:
        if not comparator.allows(v):
            return False

    if not v.is_prerelease:
        return True

    for comparator in group:
        if comparator.version is None:
            # A bare '*' never licenses a prerelease.
            continue
        if comparator.version.is_prerelease and comparator.version.tuple == v.tuple:
            return True
    return False


@lru_cache(maxsize=50_000)
def parse_range(expression: str) -> Range:
    """Parse an npm range expression. Cached -- ranges repeat heavily."""
    if expression is None:
        raise InvalidRange("range is None")
    text = str(expression).strip()

    # Ranges we deliberately do not attempt. Returning a wrong answer for these
    # would be worse than refusing: a git or file dependency is not resolvable
    # from registry metadata at all, and silently treating it as '*' would
    # attach every version in the graph to it.
    lowered = text.lower()
    for prefix in ("git:", "git+", "file:", "link:", "http:", "https:", "workspace:"):
        if lowered.startswith(prefix):
            raise InvalidRange(f"non-registry dependency, not a semver range: {text!r}")
    if "/" in text and not text.startswith(("<", ">", "=", "~", "^")):
        raise InvalidRange(f"looks like a shorthand git dependency: {text!r}")

    if text in ("", "*", "x", "X", "latest", "any"):
        return Range(((Comparator("*", None),),), text)

    groups = []
    for part in re.split(r"\s*\|\|\s*", text):
        groups.append(tuple(_parse_comparator_set(part)))
    if not groups:
        raise InvalidRange(f"empty range: {text!r}")
    return Range(tuple(groups), text)


# --------------------------------------------------------------------------
# Public helpers -- the surface the ingest pipeline actually calls
# --------------------------------------------------------------------------


def satisfies(version: str | Version, expression: str, include_prerelease: bool = False) -> bool:
    """Does ``version`` satisfy ``expression``?"""
    v = version if isinstance(version, Version) else parse(version)
    return parse_range(expression).satisfied_by(v, include_prerelease)


def filter_satisfying(
    versions: Iterable[str | Version],
    expression: str,
    include_prerelease: bool = False,
) -> list[Version]:
    """Every version admitted by the range, ascending.

    This is the hot path: called once per REQUIRES edge against every version
    the graph holds for that package. The range is parsed once and reused.
    """
    rng = parse_range(expression)
    out = []
    for item in versions:
        v = item if isinstance(item, Version) else try_parse(item)
        if v is not None and rng.satisfied_by(v, include_prerelease):
            out.append(v)
    out.sort()
    return out


def max_satisfying(
    versions: Iterable[str | Version],
    expression: str,
    include_prerelease: bool = False,
) -> Version | None:
    """The version npm would pick: the highest that satisfies."""
    admitted = filter_satisfying(versions, expression, include_prerelease)
    return admitted[-1] if admitted else None
