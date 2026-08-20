"""The PyPI half of the package tier.

npm and PyPI are the same graph shape and very different evidence, and the
difference is the only thing in this module worth being careful about.

**A `package-lock.json` is a record. A `requirements.txt` is an instruction.**
The lockfile says *this exact version is installed*, observed, with an
integrity hash. A requirements file says *anything matching `>=0.115`*, and
the version you get depends on when you ran pip. So resolving a requirements
file does not tell you what is installed; it tells you what pip would choose
today. Measured on this repository, `requirements.txt` asks for `uvicorn` and
resolves `h11@0.16.0` -- while the OSV scan reports an advisory against
`h11@0.9.0`, a version nothing here would install now but which an older
environment may well be running.

Reporting both as `RESOLVED_IN` with no distinction would quietly promote a
guess to the same standing as a lockfile, in the one tool whose whole argument
is that a range which admits a version is not a project that installed it. So
the resolution kind is recorded on every edge:

    locked     a lock file named the exact version      (poetry.lock, uv.lock)
    pinned     the manifest pinned it with `==`         (requirements.txt)
    resolved   pip chose it from a range, just now      (requirements.txt)

Only the first two are evidence about the deployed environment. The third is
a forecast, and the UI is expected to say so.

**What PyPI does not give us.** npm's packument carries the maintainer list
and the publishing account for every version, which is what the blast frontier
is built from. PyPI's JSON API carries an `author` string and no publish
identity at all, so the frontier's maintainer and publisher routes have no
PyPI equivalent. That is a property of the registry, not an omission here, and
it is stated rather than papered over with a weaker signal.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import schema
from ..ingest.ignore import load_ignores, split_ignored
from .identity import (
    PYPI,
    InvalidPackageName,
    normalize_pypi_name,
    package_key,
    service_key,
    version_key,
)
from .pep440 import latest as pep_latest

__all__ = [
    "PyPIReport",
    "find_requirements",
    "resolution_kind",
    "ingest_pypi",
    "MANIFESTS",
    "LOCKFILES",
]

#: Files that declare Python dependencies. A lock file is listed separately
#: because what it means is different, not because it parses differently.
MANIFESTS = ("requirements.txt", "requirements.lock", "requirements-dev.txt")
LOCKFILES = ("poetry.lock", "uv.lock", "Pipfile.lock", "requirements.lock")


@dataclass
class PyPIReport:
    services: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    ignored: list[str] = field(default_factory=list)
    packages: int = 0
    versions: int = 0
    resolved_edges: int = 0
    depends_edges: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    unreadable: list[str] = field(default_factory=list)
    seconds: float = 0.0

    def render(self) -> str:
        kinds = ", ".join(f"{k}={v}" for k, v in sorted(self.by_kind.items()))
        return (
            f"PyPI: {len(self.manifests)} manifest(s) -> {self.versions:,} version(s), "
            f"{self.resolved_edges:,} resolution(s) [{kinds or 'none'}], "
            f"{self.depends_edges:,} dependency edge(s) in {self.seconds:.1f}s"
        )


def find_requirements(root: Path | str, with_skipped: bool = False):
    """Every Python manifest under ``root`` this project owns.

    Honours `.blastradiusignore` for the same reason the npm discovery does:
    a walk cannot tell a service you deploy from a fixture, and a vendored
    virtualenv is full of requirements files belonging to somebody else.
    """
    root = Path(root)
    patterns = load_ignores(root)
    found: list[Path] = []
    for name in MANIFESTS + LOCKFILES:
        found.extend(root.rglob(name))
    # `.venv` and `site-packages` hold other projects' manifests. They are
    # structural rather than configured, so they are dropped silently.
    found = [
        p for p in found
        if not {".venv", "venv", "site-packages", "__pypackages__"} & set(p.parts)
    ]
    kept, skipped = split_ignored(sorted(set(found)), root, patterns)
    return (kept, skipped) if with_skipped else kept


def resolution_kind(manifest: Path | str, requested: str = "") -> str:
    """How much a resolution from this manifest is worth as evidence.

    See the module docstring: only `locked` and `pinned` say anything about
    what is deployed. `resolved` is pip's opinion as of a moment ago.
    """
    name = Path(manifest).name
    if name in LOCKFILES:
        return "locked"
    if requested and "==" in requested and "*" not in requested:
        return "pinned"
    return "resolved"


def _requested_specs(manifest: Path) -> dict[str, str]:
    """name -> the specifier the manifest asked for, best effort.

    Only used to tell a pin from a range, so an unreadable line is skipped
    rather than failing the manifest: the resolution still stands, it is just
    graded `resolved` instead of `pinned`.
    """
    out: dict[str, str] = {}
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry or entry.startswith("-"):
            continue
        entry = entry.split(";", 1)[0].strip()      # drop environment markers
        for index, char in enumerate(entry):
            if char in "=<>!~":
                name, spec = entry[:index], entry[index:]
                break
        else:
            name, spec = entry, ""
        name = name.split("[", 1)[0].strip()        # drop extras
        try:
            out[normalize_pypi_name(name)] = spec.strip()
        except InvalidPackageName:
            continue
    return out


def ingest_pypi(
    repo: Path | str,
    client,
    ids,
    writer=None,
    verbose: bool = True,
) -> PyPIReport:
    """Resolve every Python manifest under ``repo`` into the package tier."""
    from osv_scanner_tool import deps

    from .writer import PackageGraphWriter

    started = time.perf_counter()
    repo = Path(repo)
    report = PyPIReport()
    owns_writer = writer is None
    writer = writer or PackageGraphWriter(
        client, ids, source="pypi", verbose=False
    )

    manifests, ignored = find_requirements(repo, with_skipped=True)
    report.manifests = [str(p.relative_to(repo)) for p in manifests]
    report.ignored = [str(p.relative_to(repo)) for p in ignored]
    if not manifests:
        report.seconds = time.perf_counter() - started
        return report

    now = int(time.time())

    for manifest in manifests:
        # One service per manifest directory, matching the npm side: a repo
        # with both a package-lock.json and a requirements.txt beside it is
        # one deployable thing with dependencies in two ecosystems.
        directory = manifest.parent
        service_name = directory.name if directory != repo else repo.name
        # Written, not merely registered. `register` teaches the writer a
        # node's label without staging a row, which is right when something
        # else already created the node -- and nothing had. A requirements
        # file at the repo root belongs to no npm service, so its Service node
        # may be the only one describing this checkout.
        service_id = writer.node(
            schema.SERVICE, service_key(service_name),
            name=service_name,
            repo=repo.name,
            path=str(directory.relative_to(repo)) or ".",
        )
        if service_name not in report.services:
            report.services.append(service_name)

        try:
            graph = deps.resolve_python([str(manifest)])
        except Exception as exc:  # noqa: BLE001 - a manifest is data, not a bug
            report.unreadable.append(f"{manifest}: {type(exc).__name__}: {exc}")
            continue

        requested = _requested_specs(manifest)
        node_ids: dict[str, int] = {}

        for key, node in (graph.get("nodes") or {}).items():
            raw_name, version = node.get("name"), node.get("version")
            if not raw_name or not version or "unresolved" in str(version):
                # pip could not place it. Recorded as unreadable rather than
                # written as a version that does not exist.
                report.unreadable.append(f"{manifest}: {key} unresolved")
                continue
            try:
                name = normalize_pypi_name(raw_name)
            except InvalidPackageName:
                report.unreadable.append(f"{manifest}: {raw_name!r} unkeyable")
                continue

            package_id = writer.node(
                schema.PACKAGE, package_key(name, PYPI),
                name=name, ecosystem=PYPI,
                latest_version=version, source="pypi", ingested_at=now,
            )
            version_id = writer.node(
                schema.PACKAGE_VERSION, version_key(name, version, PYPI),
                name=name, version=version, ecosystem=PYPI,
                license=node.get("license") or "",
                source="pypi", ingested_at=now,
            )
            writer.edge(schema.HAS_VERSION, package_id, version_id, source="pypi")
            node_ids[key] = version_id
            report.versions += 1
            report.packages += 1

            kind = resolution_kind(manifest, requested.get(name, ""))
            report.by_kind[kind] = report.by_kind.get(kind, 0) + 1
            # `source` carries the evidence grade so a reader can tell a
            # lockfile record from pip's opinion of five seconds ago.
            writer.edge(
                schema.RESOLVED_IN, version_id, service_id,
                depth=schema.NO_DEPTH, via_direct="", dev_only=False,
                first_seen=now, last_seen=schema.STILL_LIVE,
                source=f"pypi-{kind}",
            )
            report.resolved_edges += 1

        for parent, child in graph.get("edges") or ():
            src, dst = node_ids.get(parent), node_ids.get(child)
            if src is not None and dst is not None:
                writer.edge(schema.DEPENDS_ON, src, dst, source="pypi")
                report.depends_edges += 1

    if owns_writer:
        writer.flush()

    report.seconds = time.perf_counter() - started
    if verbose:
        print(f"  {report.render()}")
    return report
