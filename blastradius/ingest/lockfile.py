"""Parse a package-lock.json into the macro graph.

A lockfile is already a fully-resolved dependency graph, which is the whole
reason this project does not crawl the npm registry. Every entry under
``packages`` names its own resolved dependencies, so the transitive closure is
read off disk rather than re-resolved from semver ranges.

The one genuinely tricky part is node's nested resolution. A dependency named
by ``node_modules/express`` may be satisfied by ``node_modules/express/node_modules/debug``
or by a hoisted ``node_modules/debug``, and the two can be *different versions*
in the same tree. Getting this wrong silently attributes a vulnerable version
to the wrong parent, so :func:`resolve_dep` implements the real walk-up rule.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class PackageVersion:
    """One resolved ``name@version`` in the tree."""

    name: str
    version: str
    dev: bool = False
    integrity: str = ""
    resolved: str = ""

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class ParsedLock:
    """Everything one lockfile contributes to the macro graph."""

    repo: str
    lock_path: str
    lock_version: int
    #: workspace-relative path -> service name. A single-package repo has one.
    services: dict[str, str] = field(default_factory=dict)
    #: "name@version" -> PackageVersion
    packages: dict[str, PackageVersion] = field(default_factory=dict)
    #: (service name, "name@version", dev) -- the repo's direct dependencies
    direct: set[tuple[str, str, bool]] = field(default_factory=set)
    #: (parent "name@version", child "name@version") -- transitive edges
    edges: set[tuple[str, str]] = field(default_factory=set)
    #: dependency names that no entry satisfied, for the ingest report
    unresolved: set[str] = field(default_factory=set)

    def summary(self) -> str:
        return (
            f"{self.repo}: {len(self.services)} service(s), "
            f"{len(self.packages)} package versions, "
            f"{len(self.direct)} direct + {len(self.edges)} transitive edges"
            + (f", {len(self.unresolved)} unresolved" if self.unresolved else "")
        )


def name_from_path(path: str) -> str:
    """``node_modules/@scope/pkg/node_modules/debug`` -> ``debug``."""
    marker = "node_modules/"
    idx = path.rfind(marker)
    return path[idx + len(marker) :] if idx >= 0 else path


def resolve_dep(from_path: str, dep_name: str, packages: dict) -> str | None:
    """Find the entry that satisfies ``dep_name`` as required by ``from_path``.

    Implements node's resolution: look in the requiring package's own
    ``node_modules`` first, then walk up the tree one nesting level at a time
    until a hoisted copy is found. Returns the winning entry's path, or None.
    """
    parts = from_path.split("/") if from_path else []
    while True:
        prefix = "/".join(parts)
        candidate = f"{prefix}/node_modules/{dep_name}" if prefix else f"node_modules/{dep_name}"
        if candidate in packages:
            return candidate
        if not parts:
            return None
        # Step out of the innermost node_modules/<pkg> pair and try again.
        try:
            idx = len(parts) - 1 - parts[::-1].index("node_modules")
        except ValueError:
            return None
        parts = parts[:idx]


def parse_package_lock(path: Path | str, repo: str | None = None) -> ParsedLock:
    """Parse a package-lock.json (v2 or v3) into a :class:`ParsedLock`."""
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    repo = repo or path.parent.name

    lock_version = int(raw.get("lockfileVersion", 1))
    packages = raw.get("packages")
    if not packages:
        # v1 has no `packages` map, only a nested `dependencies` tree. It is
        # rare enough now that we flag it rather than silently returning an
        # empty graph, which would read as "this repo is clean".
        raise ValueError(
            f"{path} is lockfileVersion {lock_version} with no `packages` map. "
            f"v1 lockfiles are not supported -- run `npm install` with npm 7+ to upgrade it."
        )

    parsed = ParsedLock(repo=repo, lock_path=str(path), lock_version=lock_version)

    # Pass 1: identify services (the root plus any workspace packages) and
    # register every real package version. Entries with `link: true` are
    # symlinks into the workspace, not installed packages.
    for entry_path, entry in packages.items():
        if entry.get("link"):
            continue
        if entry_path == "":
            parsed.services[""] = entry.get("name") or repo
        elif not entry_path.startswith("node_modules/"):
            # A workspace package: its own deployable unit.
            parsed.services[entry_path] = entry.get("name") or entry_path
        else:
            version = entry.get("version")
            if not version:
                continue  # nothing resolved here; nothing to attribute
            pv = PackageVersion(
                name=entry.get("name") or name_from_path(entry_path),
                version=version,
                dev=bool(entry.get("dev", False)),
                integrity=entry.get("integrity", ""),
                resolved=entry.get("resolved", ""),
            )
            parsed.packages[pv.key] = pv

    # Pass 2: walk every entry's declared dependencies and resolve each one to
    # the exact tree entry that satisfies it.
    for entry_path, entry in packages.items():
        if entry.get("link"):
            continue

        declared: dict[str, str] = {}
        for field_name in ("dependencies", "optionalDependencies", "peerDependencies"):
            declared.update(entry.get(field_name) or {})
        dev_declared = entry.get("devDependencies") or {}
        declared.update(dev_declared)

        is_service = entry_path == "" or not entry_path.startswith("node_modules/")

        for dep_name in declared:
            target_path = resolve_dep(entry_path, dep_name, packages)
            if target_path is None:
                parsed.unresolved.add(dep_name)
                continue
            target = packages[target_path]
            if target.get("link"):
                continue  # workspace-to-workspace edge, not a package version
            version = target.get("version")
            if not version:
                continue
            child_key = f"{target.get('name') or name_from_path(target_path)}@{version}"
            if child_key not in parsed.packages:
                continue

            if is_service:
                service = parsed.services.get(entry_path)
                if service:
                    parsed.direct.add(
                        (service, child_key, dep_name in dev_declared)
                    )
            else:
                parent = entry.get("name") or name_from_path(entry_path)
                parent_key = f"{parent}@{entry.get('version')}"
                if parent_key in parsed.packages and parent_key != child_key:
                    parsed.edges.add((parent_key, child_key))

    return parsed


def find_lockfiles(root: Path | str) -> list[Path]:
    """Every package-lock.json under root, ignoring installed dependencies."""
    root = Path(root)
    return [
        p
        for p in root.rglob("package-lock.json")
        if "node_modules" not in p.parts and ".git" not in p.parts
    ]
