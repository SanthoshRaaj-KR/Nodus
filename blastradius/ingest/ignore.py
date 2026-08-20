"""Which directories under a scan root are not the code you are scanning.

Discovery is a recursive walk for `package-lock.json`, and a walk cannot tell
a service you deploy from a fixture somebody committed to exercise the parser.
Both are a resolved manifest in a directory. Pointed at this repository the
walk found fifteen, of which twelve are a synthetic demo corpus and one is a
test fixture -- so the graph reported a fleet of fifteen services for a project
that ships two.

That is not a cosmetic problem. Every downstream number is denominated in it:
"2 of 13 threats reach code" is a different sentence when eleven of the
findings belong to fixtures, and a blast radius that names `legacy-pinned-older`
is naming something nobody can patch because nobody deployed it.

So a repository gets to say what is not its own code, in a `.blastradiusignore`
at the scan root:

    # dirs no scan should treat as this project's code
    corpus/
    tests/fixtures/

**Two pattern shapes, and the difference matters.** A pattern containing a
slash is a path *relative to the scan root*: `corpus/` hides `<root>/corpus`
and nothing else. A bare name matches any path component at any depth, which
is how `node_modules` and `.git` have always behaved.

Root-relative is what makes this safe to combine with the CLI, which points
*at* `corpus/` on purpose. If `corpus` were a bare name it would match its own
root and the demo would silently scan nothing -- the exact failure mode this
module exists to prevent, inverted. Resolving against the root means the
pattern only fires when `corpus` is genuinely a subdirectory of what you asked
for.

**Ignoring is never silent.** Callers get the list back so they can report it.
A scan that skipped twelve manifests and said nothing is indistinguishable
from a scan that found three, and "you have no other services" is the kind of
quiet wrong answer this project keeps refusing to give.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "IGNORE_FILE",
    "ALWAYS_IGNORED",
    "load_ignores",
    "is_ignored",
    "split_ignored",
]

IGNORE_FILE = ".blastradiusignore"

#: Never scanned, with or without an ignore file. `node_modules` is installed
#: output rather than source, and `.git` is history; a lockfile in either is
#: not a service anyone runs.
ALWAYS_IGNORED = ("node_modules", ".git")


def load_ignores(root: Path | str) -> tuple[str, ...]:
    """Patterns the repository *chose*, from ``<root>/.blastradiusignore``.

    Deliberately does **not** include :data:`ALWAYS_IGNORED`. The two are
    different in kind and only one is worth reporting: skipping `node_modules`
    is structural and nobody decided it, so listing every lockfile under it as
    "ignored" would bury the twelve entries a human actually needs to see under
    several hundred they do not. :func:`is_ignored` applies both; only these
    come back in the skipped list.

    A missing or unreadable file is not an error: the overwhelmingly common
    case is a repository that has never heard of this tool, and it should scan
    cleanly rather than demand configuration first.
    """
    patterns: list[str] = []
    path = Path(root) / IGNORE_FILE
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, IsADirectoryError):
        return ()

    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if entry:
            patterns.append(entry.strip("/"))
    return tuple(dict.fromkeys(patterns))


def _matches(path: Path, root: Path, patterns) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        # Outside the root entirely: not ours to judge, so not ignored.
        return False
    for pattern in patterns:
        if not pattern:
            continue
        if "/" in pattern:
            # Root-relative: must match from the top, component by component.
            wanted = tuple(p for p in Path(pattern).parts if p not in (".", ""))
            if wanted and parts[: len(wanted)] == wanted:
                return True
        elif pattern in parts:
            return True
    return False


def is_ignored(path: Path | str, root: Path | str, patterns=()) -> bool:
    """Should ``path`` be left out of a scan, for any reason?

    Applies :data:`ALWAYS_IGNORED` as well as ``patterns``, so a caller with
    only the configured list still gets `node_modules` excluded.

    Compared on path *components*, never on the string. A substring test would
    make ``corpus`` hide ``corpus-tools/`` too, and a user who excluded their
    fixtures would silently lose a real service whose name began the same way.
    """
    path, root = Path(path), Path(root)
    return _matches(path, root, ALWAYS_IGNORED) or _matches(path, root, patterns)


def split_ignored(paths, root: Path | str, patterns=None) -> tuple[list[Path], list[Path]]:
    """``(kept, skipped)``, where ``skipped`` is only what was *configured*.

    Structural exclusions are dropped from both halves. They are not a choice
    anyone made and not news to anyone reading the report; the second half
    exists to answer "why is my service missing", and the answer is never
    "because it was inside node_modules".
    """
    root = Path(root)
    patterns = load_ignores(root) if patterns is None else patterns
    kept: list[Path] = []
    skipped: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if _matches(path, root, ALWAYS_IGNORED):
            continue
        (skipped if _matches(path, root, patterns) else kept).append(path)
    return kept, skipped
