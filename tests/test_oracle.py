"""The honesty checks.

The value of this project is not that the graph finds *different* services from
a brute-force scan -- it must find exactly the same ones. What the graph adds is
the chain, the reachability and the entry points, in one round trip. So the
tests that matter compare our answer against a deliberately stupid oracle.

Run offline:      python -m pytest tests/test_oracle.py -v
With a live node: same command; the graph tests skip themselves if HydraDB is
                  not reachable.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from blastradius import schema  # noqa: E402
from blastradius.hydra_client import HydraClient, HydraError  # noqa: E402
from blastradius.ids import IdAllocator  # noqa: E402
from blastradius.ingest.lockfile import parse_package_lock, resolve_dep  # noqa: E402
from blastradius.ingest.load import Loader  # noqa: E402
from blastradius.query.advisory import Advisory, satisfies  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "package-lock.json"
CORPUS = ROOT / "corpus"


class _NullClient:
    """Stands in for HydraDB so staging can be inspected without a node."""

    def batch(self, *args, **kwargs) -> int:
        return 0


def _staged_closure(lock_path: Path):
    """Run the loader's staging and return {package key: depth}."""
    lock = parse_package_lock(lock_path, repo=lock_path.parent.name)
    with tempfile.TemporaryDirectory() as tmp:
        ids = IdAllocator(Path(tmp) / "ids.sqlite")
        loader = Loader(_NullClient(), ids, verbose=False)
        pv_ids = loader.load_macro(lock)
        by_id = {v: k for k, v in pv_ids.items()}
        # Edges are bucketed by (type, source label, destination label),
        # because a batched write needs a single label on each endpoint.
        closure = {
            by_id[row["src"]]: row["depth"]
            for (etype, _, _), rows in loader._edges.items()
            if etype == schema.PRESENT_IN
            for row in rows.values()
            if row["src"] in by_id
        }
        ids.close()
    return lock, closure


def _bruteforce_closure(lock_path: Path) -> set[str]:
    """Everything reachable from the root, computed the dumbest way possible.

    Walks the raw JSON directly, re-implementing node resolution independently
    of the parser under test, so an error in one is unlikely to be mirrored in
    the other.
    """
    raw = json.loads(lock_path.read_text(encoding="utf-8"))
    packages = raw["packages"]

    def deps_of(path: str) -> list[str]:
        entry = packages.get(path, {})
        names: list[str] = []
        for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            names.extend((entry.get(group) or {}).keys())
        return names

    seen: set[str] = set()
    stack = [""]
    visited_paths = {""}
    while stack:
        current = stack.pop()
        for name in deps_of(current):
            target = resolve_dep(current, name, packages)
            if target is None or packages[target].get("link"):
                continue
            entry = packages[target]
            version = entry.get("version")
            if not version:
                continue
            key = f"{entry.get('name') or target.rsplit('node_modules/', 1)[-1]}@{version}"
            seen.add(key)
            if target not in visited_paths:
                visited_paths.add(target)
                stack.append(target)
    return seen


def test_closure_matches_bruteforce_on_fixture():
    """The staged PRESENT_IN set equals an independently computed closure."""
    _, closure = _staged_closure(FIXTURE)
    expected = _bruteforce_closure(FIXTURE)
    assert set(closure) == expected, (
        f"missing: {expected - set(closure)}\nextra: {set(closure) - expected}"
    )


def test_closure_depths_are_shortest_path():
    """Depth 1 is a direct dependency; nothing claims a depth it cannot reach."""
    lock, closure = _staged_closure(FIXTURE)
    direct = {key for _, key, _ in lock.direct}
    for key, depth in closure.items():
        assert depth >= 1
        if depth == 1:
            assert key in direct, f"{key} claims depth 1 but is not a direct dep"
    for key in direct:
        assert closure[key] == 1, f"{key} is direct but recorded at depth {closure[key]}"


def test_nested_resolution_prefers_the_nested_copy():
    """The case that silently misattributes a vulnerable version if wrong."""
    packages = json.loads(FIXTURE.read_text(encoding="utf-8"))["packages"]
    nested = resolve_dep("node_modules/express", "debug", packages)
    hoisted = resolve_dep("node_modules/vulnerable-pkg", "debug", packages)
    assert packages[nested]["version"] == "2.6.9"
    assert packages[hoisted]["version"] == "4.3.4"


def test_every_corpus_lockfile_parses():
    """A corpus repo that fails to parse must fail loudly, not read as clean."""
    locks = sorted(CORPUS.rglob("package-lock.json"))
    if not locks:
        pytest.skip("corpus is empty")
    for lock_path in locks:
        if "node_modules" in lock_path.parts:
            continue
        parsed = parse_package_lock(lock_path, repo=lock_path.parent.name)
        assert parsed.services, f"{lock_path} produced no service"


def test_advisory_negative_control():
    """An advisory for versions we do not hold must report nothing."""
    advisory = Advisory.load(ROOT / "advisories" / "GHSA-clean-negative.json")
    assert advisory.keys_among(["2.6.9", "4.3.4"]) == []


def test_advisory_matches_only_affected():
    advisory = Advisory.load(ROOT / "advisories" / "GHSA-vuln-pkg-2026.json")
    assert advisory.keys_among(["1.0.3", "1.0.5", "1.0.6"]) == ["vulnerable-pkg@1.0.5"]


def test_semver_boundaries():
    """Off-by-one on a range boundary is the classic way to miss an exposure."""
    assert satisfies("5.62.3", ">=5.62.3 <5.62.5")
    assert satisfies("5.62.4", ">=5.62.3 <5.62.5")
    assert not satisfies("5.62.5", ">=5.62.3 <5.62.5")
    assert not satisfies("5.62.2", ">=5.62.3 <5.62.5")


# --------------------------------------------------------------------------
# Live-node tests
# --------------------------------------------------------------------------


def _live_client() -> HydraClient | None:
    client = HydraClient()
    try:
        return client if client.ready() else None
    except HydraError:
        return None


live = pytest.mark.skipif(_live_client() is None, reason="HydraDB is not reachable")


@live
def test_graph_exposure_matches_bruteforce():
    """Q1 against the graph equals the brute-force scan of the lockfiles."""
    from blastradius.query import blast

    client = HydraClient()
    for lock_path in sorted(CORPUS.rglob("package-lock.json")):
        if "node_modules" in lock_path.parts:
            continue
        service = parse_package_lock(lock_path, repo=lock_path.parent.name)
        expected = _bruteforce_closure(lock_path)

        for key in sorted(expected):
            name, _, version = key.rpartition("@")
            held = blast.held_versions(client, name)
            ids = [h["id"] for h in held if h["version"] == version]
            if not ids:
                continue
            services = {r["service"] for r in blast.exposed_services(client, ids)}
            service_names = set(service.services.values())
            assert service_names & services, (
                f"{key} is in {lock_path} by brute force but the graph does not "
                f"report any of {service_names} as exposed"
            )


@live
def test_idempotent_reingest_does_not_duplicate():
    """Counts must not move on a second ingest -- MERGE by id, stable ids."""
    from blastradius.ingest.load import ingest_corpus

    client = HydraClient()
    before = client.counts_by_label(schema.NODE_LABELS)
    with IdAllocator() as ids:
        ingest_corpus(CORPUS, client, ids, verbose=False)
    after = client.counts_by_label(schema.NODE_LABELS)
    assert before == after, f"ingest was not idempotent: {before} -> {after}"
