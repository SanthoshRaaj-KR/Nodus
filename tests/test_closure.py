"""Closure correctness, against an independently written oracle.

The transitive closure is the single most load-bearing computation in the
system: it is what makes the exposure query one hop, and if it under-reports
nobody finds out, because a missing exposure looks exactly like safety.

So it is checked against a deliberately naive oracle that recomputes
reachability a different way -- repeated relaxation to a fixed point rather
than breadth-first with a visited set. Two implementations built on different
principles are unlikely to be wrong identically, which is the only argument for
correctness worth making here.

The lockfiles under test were produced by npm itself, not by us, so the input
is ground truth we did not generate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from blastradius import schema
from blastradius.ingest.lockfile import find_lockfiles, parse_package_lock
from blastradius.pkg.ingest import compute_closure

CORPUS = Path(__file__).resolve().parents[1] / "corpus" / "fleet"


def _locks():
    if not CORPUS.exists():
        pytest.skip("generated corpus not present; run `cli corpus` first")
    paths = find_lockfiles(CORPUS)
    if not paths:
        pytest.skip("no lockfiles in corpus")
    return [parse_package_lock(p) for p in paths]


def brute_force_reachable(lock, service: str) -> dict[str, int]:
    """Oracle: every reachable version and its minimum depth.

    Relaxes depths to a fixed point instead of walking breadth-first. Slower
    and dumber on purpose -- it shares no structure with the implementation it
    checks.
    """
    children: dict[str, list[str]] = {}
    for parent, child in lock.edges:
        children.setdefault(parent, []).append(child)

    depth: dict[str, int] = {}
    for svc, key, _dev in lock.direct:
        if svc == service:
            depth[key] = min(depth.get(key, 99), schema.DIRECT_DEPTH)

    changed = True
    while changed:
        changed = False
        for parent, kids in children.items():
            if parent not in depth:
                continue
            for kid in kids:
                candidate = depth[parent] + 1
                if candidate < depth.get(kid, 10**6):
                    depth[kid] = candidate
                    changed = True
    return depth


def _services(lock):
    return list(lock.services.values())


def test_closure_matches_oracle_exactly():
    """Same set of reachable versions, and the same minimum depth for each."""
    checked = 0
    for lock in _locks():
        for service in _services(lock):
            ours = compute_closure(lock, service)
            theirs = brute_force_reachable(lock, service)

            assert set(ours) == set(theirs), (
                f"{service}: reachable set differs; "
                f"missing={set(theirs) - set(ours)} "
                f"extra={set(ours) - set(theirs)}"
            )
            for key, exposure in ours.items():
                assert exposure.depth == theirs[key], (
                    f"{service}: {key} depth {exposure.depth} != {theirs[key]}"
                )
            checked += 1
    assert checked, "no services checked"


def test_closure_is_not_empty():
    total = sum(
        len(compute_closure(lock, service))
        for lock in _locks()
        for service in _services(lock)
    )
    assert total > 100, f"only {total} closure entries; corpus looks wrong"


def test_direct_dependencies_are_depth_one():
    for lock in _locks():
        for service in _services(lock):
            closure = compute_closure(lock, service)
            for svc, key, _dev in lock.direct:
                if svc != service:
                    continue
                assert closure[key].depth == schema.DIRECT_DEPTH


def test_via_direct_names_a_real_direct_dependency():
    """The witness has to be a dependency the project actually declares,
    otherwise the explanation points at something the reader cannot act on."""
    for lock in _locks():
        for service in _services(lock):
            direct = {k for s, k, _ in lock.direct if s == service}
            for key, exposure in compute_closure(lock, service).items():
                assert exposure.via_direct in direct, (
                    f"{service}: {key} claims via {exposure.via_direct}, "
                    f"which is not a declared dependency"
                )


def test_hoisting_does_not_make_a_transitive_dependency_look_direct():
    """npm hoists, so path depth lies.

    In this corpus cli-tool has lodash at top-level node_modules but declares
    only chalk, commander and inquirer. Counting path segments would report
    lodash as a direct dependency; walking declared relations reports it at
    depth 2 through inquirer, which is the truth.
    """
    lock_path = CORPUS / "cli-tool" / "package-lock.json"
    if not lock_path.exists():
        pytest.skip("cli-tool not generated")
    lock = parse_package_lock(lock_path)
    closure = compute_closure(lock, "cli-tool")
    lodash = [k for k in closure if k.startswith("lodash@")]
    assert lodash, "cli-tool should reach lodash"
    exposure = closure[lodash[0]]
    assert exposure.depth > schema.DIRECT_DEPTH, (
        "lodash is hoisted to top level but is not a declared dependency"
    )
    assert exposure.via_direct.startswith("inquirer@")


def test_production_path_beats_dev_only_path():
    """A version reachable both ways must be recorded as production.

    Telling someone a production exposure is dev-only is the dangerous
    direction to be wrong in, so the stronger claim wins.
    """
    for lock in _locks():
        for service in _services(lock):
            closure = compute_closure(lock, service)
            prod_direct = {
                k for s, k, dev in lock.direct if s == service and not dev
            }
            for key in prod_direct:
                assert not closure[key].dev_only


def test_every_lockfile_entry_is_reachable_or_explained():
    """Entries the closure does not reach should be rare and attributable.

    An unreachable entry means the lockfile holds something nothing depends
    on, which happens with optional or peer trees. It must not be common; a
    large gap would mean the walk is broken.
    """
    for lock in _locks():
        reachable: set[str] = set()
        for service in _services(lock):
            reachable |= set(compute_closure(lock, service))
        orphans = set(lock.packages) - reachable
        assert len(orphans) <= len(lock.packages) * 0.25, (
            f"{lock.repo}: {len(orphans)}/{len(lock.packages)} entries "
            f"unreachable: {sorted(orphans)[:8]}"
        )
