"""Scan a service for worm persistence artifacts.

The TanStack-class worm persisted into ``.claude/`` and ``.vscode/`` so that it
survived ``npm uninstall``. Removing the package therefore does not clear the
compromise, which is why an artifact on disk is a different severity tier from
"the bad version is in your lockfile": one is exposure, the other is evidence.

Detection is IOC-driven -- paths and content markers come from the advisory
that our teammates produce, so nothing here is hardcoded to one incident.
"""

from __future__ import annotations

import fnmatch
import hashlib
import time
from dataclasses import dataclass
from pathlib import Path

#: Directories a worm can hide in that survive a package uninstall. Scanned
#: even when an advisory names no paths, because their mere presence alongside
#: a compromised package is worth surfacing.
WATCHED_DIRS = (".claude", ".vscode", ".github/workflows", ".husky")

#: Cap per file so a scan cannot be stalled by a huge binary.
MAX_READ_BYTES = 512_000


@dataclass(frozen=True)
class Artifact:
    path: str
    kind: str  # "ioc-path" | "ioc-content" | "watched-dir"
    sha256: str
    first_seen: int

    @property
    def key(self) -> str:
        return f"{self.path}::{self.sha256[:12]}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            digest.update(handle.read(MAX_READ_BYTES))
    except OSError:
        return ""
    return digest.hexdigest()


def scan_service(
    root: Path | str,
    ioc_paths: list[str] | None = None,
    content_markers: list[str] | None = None,
) -> list[Artifact]:
    """Find persistence artifacts under ``root``.

    ``ioc_paths`` are glob patterns relative to the service root; matches are
    reported as ``ioc-path``. Files under :data:`WATCHED_DIRS` are reported as
    ``watched-dir`` even without a matching IOC, so a human can eyeball them.
    """
    root = Path(root)
    ioc_paths = ioc_paths or []
    content_markers = content_markers or []
    now = int(time.time())
    found: dict[str, Artifact] = {}

    candidates: list[Path] = []
    for watched in WATCHED_DIRS:
        directory = root / watched
        if directory.is_dir():
            candidates.extend(p for p in directory.rglob("*") if p.is_file())

    for pattern in ioc_paths:
        candidates.extend(p for p in root.glob(pattern) if p.is_file())

    for path in candidates:
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        if rel in found:
            continue

        kind = "watched-dir"
        if any(fnmatch.fnmatch(rel, pattern) for pattern in ioc_paths):
            kind = "ioc-path"

        if content_markers and kind != "ioc-path":
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")[:MAX_READ_BYTES]
            except OSError:
                text = ""
            if any(marker in text for marker in content_markers):
                kind = "ioc-content"

        found[rel] = Artifact(rel, kind, _sha256(path), now)

    return sorted(found.values(), key=lambda a: a.path)
