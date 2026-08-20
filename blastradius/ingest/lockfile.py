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

from ..pkg.identity import InvalidPackageName, version_key
from .ignore import load_ignores, split_ignored


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
        """Canonical purl, e.g. ``pkg:npm/vite@6.3.6``.

        This is the *same* function the package tier keys on
        (:func:`blastradius.pkg.identity.version_key`), and it must stay that
        way. Ids are allocated per ``(label, natural_key)``, so the moment the
        two tiers disagree about the key for one package version, the graph
        grows a second unconnected ``PackageVersion`` node for it: advisories
        land on one copy, the dependency tree and the code-graph bridge on the
        other, and no query can cross between them. See
        ``tests/test_identity.py::test_both_tiers_key_alike``.
        """
        return version_key(self.name, self.version)


@dataclass
class ParsedLock:
    """Everything one lockfile contributes to the macro graph."""

    repo: str
    lock_path: str
    lock_version: int
    #: workspace-relative path -> service name. A single-package repo has one.
    services: dict[str, str] = field(default_factory=dict)
    #: purl -> PackageVersion
    packages: dict[str, PackageVersion] = field(default_factory=dict)
    #: (service name, purl, dev) -- the repo's direct dependencies
    direct: set[tuple[str, str, bool]] = field(default_factory=set)
    #: (parent purl, child purl) -- transitive edges
    edges: set[tuple[str, str]] = field(default_factory=set)
    #: package name -> purl for the hoisted top-level copy. A
    #: service's own source resolves from the repo root, so this is the version
    #: an `import "lodash"` in application code actually loads -- which is not
    #: necessarily the version some nested dependency sees.
    root_level: dict[str, str] = field(default_factory=dict)
    #: dependency names that no entry satisfied, for the ingest report
    unresolved: set[str] = field(default_factory=set)
    #: entries whose name could not be normalised into a key, for the report
    unkeyable: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{self.repo}: {len(self.services)} service(s), "
            f"{len(self.packages)} package versions, "
            f"{len(self.direct)} direct + {len(self.edges)} transitive edges"
            + (f", {len(self.unresolved)} unresolved" if self.unresolved else "")
            + (f", {len(self.unkeyable)} unkeyable" if self.unkeyable else "")
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
            try:
                pv_key = pv.key
            except InvalidPackageName as exc:
                # The key is the identity, so an entry we cannot key cannot be
                # a node. Record it rather than dropping it silently -- the
                # package tier skips the same rows, and a name that both tiers
                # reject is worth seeing in the ingest report.
                parsed.unkeyable.append(f"{entry_path}: {exc}")
                continue
            parsed.packages[pv_key] = pv
            if entry_path == f"node_modules/{pv.name}":
                parsed.root_level[pv.name] = pv_key

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
            # Both keys go through `version_key`, never an inline f-string.
            # `parsed.packages` is keyed by purl, so a hand-built
            # "name@version" here matches nothing and every edge is silently
            # dropped -- the lockfile parses, the counts look plausible, and
            # the dependency tree simply does not exist.
            child_name = target.get("name") or name_from_path(target_path)
            try:
                child_key = version_key(child_name, version)
            except InvalidPackageName:
                continue
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
                parent_version = entry.get("version")
                if not parent_version:
                    continue
                try:
                    parent_key = version_key(parent, parent_version)
                except InvalidPackageName:
                    continue
                if parent_key in parsed.packages and parent_key != child_key:
                    parsed.edges.add((parent_key, child_key))

    return parsed


def find_lockfiles(root: Path | str, with_skipped: bool = False):
    """Every package-lock.json under root that is this project's own code.

    Installed output (`node_modules`) and history (`.git`) are always skipped.
    Anything else the repository disowns is listed in `.blastradiusignore` at
    the scan root -- see :mod:`blastradius.ingest.ignore` for why a walk cannot
    work this out for itself, and why the patterns are root-relative.

    ``with_skipped=True`` returns ``(kept, skipped)`` instead of just the kept
    list. Callers that report to a human should use it: a scan that quietly
    dropped twelve manifests looks exactly like a project that only had three.
    """
    root = Path(root)
    patterns = load_ignores(root)
    kept, skipped = split_ignored(root.rglob("package-lock.json"), root, patterns)
    return (kept, skipped) if with_skipped else kept
