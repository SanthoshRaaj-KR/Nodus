"""PEP 440 versions and specifiers -- PyPI's answer to :mod:`.semver`.

The package tier is built on two operations: decide whether a declared range
admits a version, and order versions so "newest" means something. npm gets
both from :mod:`.semver`. PyPI needs its own, because the two schemes disagree
about nearly everything that matters:

* **Ordering.** ``1.0`` and ``1.0.0`` are the *same* version in PEP 440 and
  different strings in semver. Release segments are compared as a
  zero-extended tuple, so ``1.0`` == ``1.0.0`` == ``1.0.0.0``.
* **Pre-releases.** semver spells them ``1.0.0-rc.1``; PEP 440 spells the same
  thing ``1.0rc1``, ``1.0.rc.1``, ``1.0-c-1`` and ``1.0preview1``, all of
  which normalise to one version.
* **Post- and dev-releases.** ``1.0.post1`` is *newer* than ``1.0``, and
  ``1.0.dev1`` is *older*. semver has no equivalent of either.
* **Epochs.** ``1!1.0`` outranks ``2.0``, which exists so a project that
  changed versioning scheme can still sort forwards.
* **``~=``.** The compatible-release operator, whose meaning depends on how
  many segments it was written with: ``~=1.4.2`` means ``>=1.4.2, ==1.4.*``
  while ``~=1.4`` means ``>=1.4, ==1.*``.

**No third-party parser.** `packaging` would do this properly and is not a
dependency of this project; adding one to read version strings would be a poor
trade. This implements the subset the graph actually needs and is explicit
about the edge it does not handle -- see :func:`matches` on local versions.

**Unparseable is not zero.** Every function here refuses to guess. A version
it cannot read returns ``None`` rather than a default, and a specifier it
cannot read does not silently match everything -- the same discipline the
npm side applies, and for the same reason: a range that quietly matched
nothing would report a clean bill of health for a package nobody assessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "Version",
    "parse",
    "compare",
    "satisfies",
    "matches",
    "sort_versions",
    "latest",
]

#: PEP 440's own grammar, minus the parts the graph never sees. `v` prefixes
#: and surrounding whitespace are permitted because real requirements files
#: contain both.
_VERSION_RE = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?:
        (?:-(?P<post_n1>[0-9]+))
        |
        (?:[-_.]?(?:post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)
    )?
    (?:[-_.]?dev[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)

#: Spellings that mean the same pre-release phase.
_PRE_ALIASES = {
    "alpha": "a", "a": "a",
    "beta": "b", "b": "b",
    "c": "rc", "pre": "rc", "preview": "rc", "rc": "rc",
}

def _trimmed(release: tuple[int, ...]) -> tuple[int, ...]:
    """Release segments with trailing zeros dropped.

    ``1.0`` and ``1.0.0`` are the same version, so any comparison of "is this
    the same release" has to normalise first. Comparing the raw tuples made
    `>1.0` match `1.0.0.post1` while correctly rejecting `1.0.post1` -- the
    same bug wearing a different number of segments.
    """
    out = list(release)
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return tuple(out)


#: Sort order for the phases. A dev release precedes everything, a pre-release
#: precedes its own release, and a post-release follows it.
_PHASE = {"dev": -1, "a": 0, "b": 1, "rc": 2, "release": 3, "post": 4}


@dataclass(frozen=True)
class Version:
    """One PEP 440 version, in comparable form."""

    epoch: int
    release: tuple[int, ...]
    pre: tuple[str, int] | None
    post: int | None
    dev: int | None
    local: str
    raw: str

    @property
    def is_prerelease(self) -> bool:
        """Pre- and dev-releases are excluded from ranges unless asked for.

        This is the rule that keeps `>=1.0` from resolving to `2.0.dev1`, and
        it is why "latest" on a package mid-release-cycle is not simply the
        highest string.
        """
        return self.pre is not None or self.dev is not None

    def key(self) -> tuple:
        """A tuple that sorts exactly as PEP 440 says versions sort.

        The release tuple is compared with trailing zeros stripped, which is
        what makes ``1.0`` and ``1.0.0`` equal rather than adjacent.
        """
        release = _trimmed(self.release)

        if self.dev is not None and self.pre is None and self.post is None:
            phase, number = _PHASE["dev"], self.dev
        elif self.pre is not None:
            phase, number = _PHASE[self.pre[0]], self.pre[1]
        elif self.post is not None:
            phase, number = _PHASE["post"], self.post
        else:
            phase, number = _PHASE["release"], 0

        # A dev suffix on a pre- or post-release sorts *below* the same
        # version without it: 1.0rc1.dev1 < 1.0rc1.
        dev_rank = 0 if self.dev is None else -1
        return (self.epoch, release, phase, number, dev_rank,
                0 if self.dev is None else self.dev)

    def __str__(self) -> str:
        return self.raw


def parse(text: str) -> Version | None:
    """A :class:`Version`, or ``None`` for anything unreadable."""
    if not isinstance(text, str):
        return None
    match = _VERSION_RE.match(text)
    if match is None:
        return None

    pre = None
    if match.group("pre_l"):
        label = _PRE_ALIASES.get(match.group("pre_l").lower())
        if label is None:
            return None
        pre = (label, int(match.group("pre_n") or 0))

    post = None
    if match.group("post_n1") is not None:
        post = int(match.group("post_n1"))
    elif match.group("post_n2") is not None:
        post = int(match.group("post_n2"))
    elif "post" in text.lower() or re.search(r"[-_.]r(ev)?[-_.]?\d*$", text, re.I):
        post = 0

    dev = None
    if match.group("dev_n") is not None:
        dev = int(match.group("dev_n"))
    elif re.search(r"[-_.]?dev", text, re.IGNORECASE):
        dev = 0

    return Version(
        epoch=int(match.group("epoch") or 0),
        release=tuple(int(p) for p in match.group("release").split(".")),
        pre=pre,
        post=post,
        dev=dev,
        local=(match.group("local") or "").lower(),
        raw=text.strip(),
    )


def compare(a: str, b: str) -> int | None:
    """``-1 | 0 | 1``, or ``None`` if either side is unreadable."""
    left, right = parse(a), parse(b)
    if left is None or right is None:
        return None
    lk, rk = left.key(), right.key()
    return (lk > rk) - (lk < rk)


def sort_versions(versions) -> list[str]:
    """Readable versions in ascending order. Unreadable ones are dropped."""
    parsed = [(v.key(), v.raw) for v in (parse(x) for x in versions) if v]
    return [raw for _, raw in sorted(parsed)]


def latest(versions, allow_prerelease: bool = False) -> str | None:
    """The newest version, skipping pre-releases unless asked."""
    parsed = [v for v in (parse(x) for x in versions) if v]
    if not allow_prerelease:
        stable = [v for v in parsed if not v.is_prerelease]
        # Only fall back to pre-releases when there is nothing else; a package
        # with only alphas has a newest version and it is an alpha.
        parsed = stable or parsed
    if not parsed:
        return None
    return max(parsed, key=lambda v: v.key()).raw


# --------------------------------------------------------------------------
# Specifiers
# --------------------------------------------------------------------------

_CLAUSE_RE = re.compile(r"^\s*(===|==|!=|~=|<=|>=|<|>)\s*(.+?)\s*$")


def _release_prefix_match(version: Version, prefix: str) -> bool:
    """``==1.4.*``: compare only the segments the prefix names."""
    wanted = prefix[:-2] if prefix.endswith(".*") else prefix
    target = parse(wanted)
    if target is None:
        return False
    depth = len(target.release)
    if version.epoch != target.epoch:
        return False
    padded = version.release + (0,) * max(0, depth - len(version.release))
    return padded[:depth] == target.release[:depth]


def matches(version: str, clause: str) -> bool | None:
    """Does ``version`` satisfy one clause such as ``>=1.4.2``?

    ``None`` means "cannot tell" -- an unreadable version or operator -- and
    callers must treat that as unknown rather than as False. Reporting a
    package as unaffected because its version string could not be parsed is
    the failure mode this return value exists to prevent.

    **Local versions** (``1.0+ubuntu1``) are compared on their public part
    only. PEP 440 gives them an ordering; nothing in this graph publishes
    them, and implementing it untested would be worse than declaring it.
    """
    parsed = parse(version)
    if parsed is None:
        return None

    match = _CLAUSE_RE.match(clause)
    if match is None:
        return None
    op, operand = match.group(1), match.group(2)

    # `===` is a literal string comparison by definition, not a version one.
    if op == "===":
        return version.strip() == operand.strip()

    if operand.endswith(".*"):
        if op == "==":
            return _release_prefix_match(parsed, operand)
        if op == "!=":
            return not _release_prefix_match(parsed, operand)
        # A wildcard with an ordering operator is not valid PEP 440.
        return None

    other = parse(operand)
    if other is None:
        return None

    if op == "~=":
        # Compatible release: >= the operand, and equal on every segment but
        # the last one it named. `~=1.4.2` is `>=1.4.2, ==1.4.*`.
        if len(other.release) < 2:
            return None
        floor = compare(version, operand)
        if floor is None:
            return None
        prefix = ".".join(str(p) for p in other.release[:-1]) + ".*"
        return floor >= 0 and _release_prefix_match(parsed, prefix)

    result = compare(version, operand)
    if result is None:
        return None

    # PEP 440's exclusive-comparison rule, and it is not derivable from the
    # ordering. `>1.0` must NOT match `1.0.post1`, even though 1.0.post1 sorts
    # above 1.0 -- the intent of "greater than 1.0" is "a later release", and
    # a post-release is the same release with corrected packaging. The mirror
    # rule holds for `<`: `<1.0` must not match `1.0rc1`.
    #
    # Caught by cross-checking every clause against `packaging`; it was the
    # single disagreement in 230 cases, and it would have quietly widened
    # every `>` range in a requirements file.
    same_release = (
        other.epoch == parsed.epoch
        and _trimmed(other.release) == _trimmed(parsed.release)
    )
    if op == ">" and same_release and parsed.post is not None and other.post is None:
        return False
    if op == "<" and same_release and parsed.is_prerelease and not other.is_prerelease:
        return False

    return {
        "==": result == 0,
        "!=": result != 0,
        "<=": result <= 0,
        ">=": result >= 0,
        "<": result < 0,
        ">": result > 0,
    }[op]


def satisfies(version: str, specifier: str) -> bool | None:
    """Does ``version`` satisfy a whole comma-separated specifier?

    Every clause must hold. An empty specifier admits anything, which is what
    a bare ``requests`` in a requirements file means.

    Pre-releases are excluded unless the specifier itself mentions one --
    PEP 440's rule, and the reason ``>=1.0`` does not resolve to ``2.0.dev1``.
    """
    parsed = parse(version)
    if parsed is None:
        return None
    text = (specifier or "").strip()
    if not text:
        return True

    clauses = [c for c in (part.strip() for part in text.split(",")) if c]
    if not clauses:
        return True

    if parsed.is_prerelease:
        # A clause "asks for" pre-releases only when its own operand is one.
        # The first version of this fell back to the *version being tested*
        # when the operand would not parse -- so `!=1.0.*` (whose operand is a
        # wildcard and never parses) looked like it wanted pre-releases, and
        # `2.0.dev1` passed a specifier that should exclude it. Caught against
        # `packaging`: two disagreements in 425 clauses, both this shape.
        wants_pre = False
        for clause in clauses:
            match = _CLAUSE_RE.match(clause)
            if match is None:
                continue
            operand = parse(match.group(2))
            if operand is not None and operand.is_prerelease:
                wants_pre = True
                break
        if not wants_pre:
            return False

    for clause in clauses:
        verdict = matches(version, clause)
        if verdict is None:
            # One unreadable clause makes the whole answer unknown. Treating
            # it as satisfied would over-report; as unsatisfied, under-report.
            return None
        if not verdict:
            return False
    return True
