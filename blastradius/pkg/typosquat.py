"""Typosquat neighbourhood detection over npm package names.

HydraDB has no string functions, so none of this can run in a query. It is a
precompute that writes ``TYPOSQUAT_OF`` edges at ingest, and the query side
just follows them.

Two things decide whether this feature is useful or noise.

**Candidate generation has to be cheap.** Comparing every package against every
popular name is quadratic and pointless -- almost every pair is obviously
unrelated. A deletion-variant index (the SymSpell idea) reduces it to a dict
lookup: two strings within edit distance 2 always share at least one variant
formed by deleting up to 2 characters. We build that index once over the
popular set and probe it per candidate, so the expensive distance function runs
on a handful of pairs rather than millions.

**The popularity guard decides correctness.** Name similarity alone is a bad
signal. ``lodash.merge`` and ``lodash.debounce`` are official packages by the
lodash author; ``@types/lodash`` is the DefinitelyTyped stub. All three sit
within a trivial edit distance of ``lodash`` and none is a squat. A typosquat
is characterised by *asymmetry* -- someone unknown sitting next to someone
popular -- so an edge is written only when the target is materially more
depended-upon than the candidate, and never when the pair looks like a
namespace convention.

We label results INVESTIGATE and publish the evidence. Nothing here asserts
that a package is malicious.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations
from typing import Iterable, Mapping, Sequence

from .identity import normalize_name, split_scope

__all__ = [
    "Technique",
    "TyposquatFinding",
    "TyposquatIndex",
    "damerau_levenshtein",
    "skeleton",
]


class Technique:
    """How a name resembles its target. Recorded, never collapsed to a score."""

    EDIT_DISTANCE = "edit_distance"        # insertion / deletion / substitution
    TRANSPOSITION = "transposition"        # lodahs vs lodash
    HOMOGLYPH = "homoglyph"                # visually confusable characters
    SEPARATOR = "separator"                # node-fetch vs nodefetch vs node_fetch
    SCOPE_CONFUSION = "scope_confusion"    # @types/lodash vs @typos/lodash
    REPEATED_CHAR = "repeated_char"        # lodashh vs lodash


#: Characters that read alike in a terminal or a browser address bar. The
#: `rn`/`m` pair is the classic one and is why this is not just a distance
#: check: `rn` -> `m` is two edits, so a distance-2 threshold would rank it
#: alongside far less convincing pairs.
_HOMOGLYPHS = [
    ("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"),
    ("1", "l"), ("1", "i"), ("l", "i"), ("0", "o"), ("5", "s"),
    ("2", "z"), ("8", "b"), ("6", "b"), ("9", "g"),
]

_SEPARATORS = re.compile(r"[-._]")


def skeleton(name: str) -> str:
    """Fold a name to a form where confusable spellings collide.

    Separators are dropped and homoglyph families are mapped to one
    representative, so ``node-fetch``, ``node_fetch``, ``nodefetch`` and
    ``n0defetch`` all reduce to the same skeleton.
    """
    _, bare = split_scope(name) if name.startswith("@") else (None, name)
    text = _SEPARATORS.sub("", bare.lower())
    # Longest patterns first so `rn` is folded before the single-char rules.
    for pattern, replacement in sorted(_HOMOGLYPHS, key=lambda p: -len(p[0])):
        text = text.replace(pattern, replacement)
    return text


def damerau_levenshtein(a: str, b: str, max_distance: int = 2) -> int:
    """Optimal string alignment distance, bounded.

    Bounded because we only ever care whether the distance is small: giving up
    early once every cell in a row exceeds the threshold turns the worst case
    from O(len(a) * len(b)) into something proportional to the band we care
    about. Returns ``max_distance + 1`` to mean "further than that".
    """
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    if not a:
        return len(b) if len(b) <= max_distance else max_distance + 1
    if not b:
        return len(a) if len(a) <= max_distance else max_distance + 1

    previous_previous: list[int] = []
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i] + [0] * len(b)
        best_in_row = current[0]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            value = min(
                previous[j] + 1,          # deletion
                current[j - 1] + 1,       # insertion
                previous[j - 1] + cost,   # substitution
            )
            if (
                i > 1
                and j > 1
                and ca == b[j - 2]
                and a[i - 2] == cb
            ):
                value = min(value, previous_previous[j - 2] + 1)  # transposition
            current[j] = value
            if value < best_in_row:
                best_in_row = value
        if best_in_row > max_distance:
            return max_distance + 1
        previous_previous, previous = previous, current
    return previous[-1] if previous[-1] <= max_distance else max_distance + 1


def _deletion_variants(text: str, max_deletions: int = 2) -> set[str]:
    """Every string formed by deleting up to N characters.

    Two strings within edit distance N always share at least one such variant,
    which is what makes the index a sound filter rather than a heuristic: it
    can over-generate candidates but never miss a true pair.
    """
    out = {text}
    n = len(text)
    limit = min(max_deletions, max(0, n - 1))
    for k in range(1, limit + 1):
        for positions in combinations(range(n), k):
            drop = set(positions)
            out.add("".join(c for i, c in enumerate(text) if i not in drop))
    return out


@dataclass(frozen=True)
class TyposquatFinding:
    """One suspected imitation, with the evidence that produced it."""

    candidate: str            # the suspected imitator
    target: str               # the popular package being imitated
    technique: str
    distance: int
    candidate_popularity: int
    target_popularity: int

    @property
    def popularity_ratio(self) -> float:
        return self.target_popularity / max(1, self.candidate_popularity)

    @property
    def candidate_popularity_known(self) -> bool:
        return self.candidate_popularity >= 0

    def explain(self) -> str:
        return (
            f"{self.candidate!r} resembles {self.target!r} "
            f"({self.technique}, distance {self.distance}); "
            f"target is {self.popularity_ratio:.0f}x more depended-upon"
        )


class TyposquatIndex:
    """Deletion-variant index over a set of popular package names.

    Build once over the popular set, then probe per candidate. Construction is
    O(P * L^2) for P popular names of length L, which is trivial at the few
    thousand names that matter, and each probe is a handful of dict lookups.
    """

    #: A target must be at least this much more popular than the candidate
    #: before we will call the pair a suspected squat. Set from the observation
    #: that real squats are unknown packages beside famous ones; a pair of
    #: comparably-popular neighbours is far more likely to be two legitimate
    #: siblings.
    MIN_POPULARITY_RATIO = 10.0

    def __init__(
        self,
        popular: Mapping[str, int],
        max_distance: int = 2,
        min_length: int = 4,
    ):
        """``popular`` maps package name to a popularity figure (downloads)."""
        self.max_distance = max_distance
        #: Very short names are excluded: at 3 characters almost everything is
        #: within distance 2 of everything else, so the signal is meaningless.
        self.min_length = min_length
        self.popular: dict[str, int] = {}
        self._variants: dict[str, set[str]] = defaultdict(set)
        self._by_skeleton: dict[str, set[str]] = defaultdict(set)
        self._by_bare: dict[str, set[str]] = defaultdict(set)

        for raw, downloads in popular.items():
            name = normalize_name(raw)
            self.popular[name] = int(downloads)
            _, bare = split_scope(name)
            self._by_bare[bare].add(name)
            self._by_skeleton[skeleton(name)].add(name)
            if len(bare) >= self.min_length:
                for variant in _deletion_variants(bare, max_distance):
                    self._variants[variant].add(name)

    # -- candidate generation ---------------------------------------------

    def _candidates(self, name: str) -> set[str]:
        _, bare = split_scope(name)
        found: set[str] = set()
        found |= self._by_skeleton.get(skeleton(name), set())
        found |= self._by_bare.get(bare, set())
        if len(bare) >= self.min_length:
            for variant in _deletion_variants(bare, self.max_distance):
                found |= self._variants.get(variant, set())
        found.discard(name)
        return found

    # -- guards ------------------------------------------------------------

    @staticmethod
    def _is_namespace_convention(candidate: str, target: str) -> bool:
        """Is this pair a naming convention rather than an imitation?

        ``lodash.merge`` and ``lodash/fp`` are published by the lodash author;
        ``@types/lodash`` is the DefinitelyTyped stub. In every case the target
        name appears whole, followed by a separator -- that is a family, not a
        forgery, and flagging it would bury the real findings.
        """
        c_scope, c_bare = split_scope(candidate)
        t_scope, t_bare = split_scope(target)

        # A scoped package whose bare name equals an unscoped target's is a
        # stub or a fork, e.g. @types/lodash beside lodash.
        if bool(c_scope) != bool(t_scope) and c_bare == t_bare:
            return True

        # Two scoped packages sharing a bare name are only an imitation when
        # the *scopes* are confusable: @typos/lodash against @types/lodash is
        # an attack, whereas @types/lodash against @nestjs/lodash is two
        # unrelated projects that happen to wrap the same library.
        if c_scope and t_scope and c_bare == t_bare:
            scope_distance = damerau_levenshtein(
                c_scope.lstrip("@"), t_scope.lstrip("@"), 2
            )
            return scope_distance > 2 or scope_distance == 0

        for sep in (".", "-", "/", "_"):
            if c_bare.startswith(t_bare + sep) or t_bare.startswith(c_bare + sep):
                return True
        return False

    def _classify(self, candidate: str, target: str, distance: int) -> str | None:
        _, c_bare = split_scope(candidate)
        _, t_bare = split_scope(target)
        c_scope, _ = split_scope(candidate)
        t_scope, _ = split_scope(target)

        if c_bare == t_bare and c_scope != t_scope:
            return Technique.SCOPE_CONFUSION
        if _SEPARATORS.sub("", c_bare) == _SEPARATORS.sub("", t_bare):
            return Technique.SEPARATOR
        if skeleton(candidate) == skeleton(target):
            return Technique.HOMOGLYPH
        if distance == 0:
            return None
        if len(c_bare) == len(t_bare) and distance == 1:
            # A single swap of adjacent characters reads as a transposition.
            diffs = [i for i, (x, y) in enumerate(zip(c_bare, t_bare)) if x != y]
            if len(diffs) == 2 and diffs[1] - diffs[0] == 1:
                return Technique.TRANSPOSITION
        if len(c_bare) == len(t_bare) + 1 and _has_doubled_char(c_bare, t_bare):
            return Technique.REPEATED_CHAR
        if distance <= self.max_distance:
            return Technique.EDIT_DISTANCE
        return None

    # -- the public call ---------------------------------------------------

    @staticmethod
    def _scopes_comparable(candidate: str, target: str) -> bool:
        """May these two names be compared at all?

        A scope is an account boundary, not decoration. ``@webpack-cli/serve``
        is published under the webpack-cli organisation and is not pretending
        to be ``semver``, however close the bare names look -- so names in
        different scopes are only comparable when the bare names are
        *identical*, which is the genuine scope-confusion attack
        (``@types/lodash`` beside a hostile ``@typos/lodash``).

        Without this rule every scoped package in a corpus matches some
        unrelated popular name and the output is pure noise.
        """
        c_scope, c_bare = split_scope(candidate)
        t_scope, t_bare = split_scope(target)
        if c_scope == t_scope:
            return True
        return c_bare == t_bare

    def find(
        self, name: str, popularity: int | None = None
    ) -> list[TyposquatFinding]:
        """Suspected targets for one package name, strongest first.

        ``popularity`` of None means *unknown*, which is not the same as zero.
        Asymmetry cannot be established against an unknown, so nothing is
        emitted rather than everything -- the npm bulk download endpoint
        declines scoped packages, and reading that silence as "zero downloads"
        made every scoped package look like a squat of something famous.
        """
        try:
            name = normalize_name(name)
        except Exception:  # noqa: BLE001 - source data we do not control
            return []

        _, bare = split_scope(name)
        if len(bare) < self.min_length:
            return []
        if popularity is None:
            return []

        findings: list[TyposquatFinding] = []
        for target in self._candidates(name):
            target_popularity = self.popular.get(target, 0)

            if not self._scopes_comparable(name, target):
                continue
            # The asymmetry guard. Without it every legitimate sibling and
            # fork in the ecosystem shows up as a squat.
            if target_popularity < max(1, popularity) * self.MIN_POPULARITY_RATIO:
                continue
            if self._is_namespace_convention(name, target):
                continue

            _, t_bare = split_scope(target)
            distance = damerau_levenshtein(bare, t_bare, self.max_distance)
            if distance > self.max_distance and skeleton(name) != skeleton(target):
                continue

            technique = self._classify(name, target, distance)
            if technique is None:
                continue

            findings.append(
                TyposquatFinding(
                    candidate=name,
                    target=target,
                    technique=technique,
                    distance=distance,
                    candidate_popularity=popularity,
                    target_popularity=target_popularity,
                )
            )

        # Closest first, then most popular target -- the ordering a responder
        # would want to read.
        findings.sort(key=lambda f: (f.distance, -f.target_popularity))
        return findings

    def find_all(
        self, candidates: Iterable[str] | Mapping[str, int | None]
    ) -> list[TyposquatFinding]:
        """Run :meth:`find` across many candidates.

        Given a bare iterable the popularity of each is unknown, so nothing is
        emitted; pass a mapping to supply it.
        """
        if isinstance(candidates, Mapping):
            items: Sequence[tuple[str, int | None]] = list(candidates.items())
        else:
            items = [(name, None) for name in candidates]
        out: list[TyposquatFinding] = []
        for name, popularity in items:
            out.extend(self.find(name, popularity))
        return out


def _has_doubled_char(longer: str, shorter: str) -> bool:
    """Is ``longer`` ``shorter`` with one character repeated? (lodashh/lodash)"""
    for i in range(len(longer)):
        if longer[:i] + longer[i + 1 :] == shorter:
            if i > 0 and longer[i] == longer[i - 1]:
                return True
            if i + 1 < len(longer) and longer[i] == longer[i + 1]:
                return True
    return False
