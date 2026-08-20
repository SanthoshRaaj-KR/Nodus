"""Ingest a fixed set of repositories, so a deployment starts with content.

Runtime ingest through the picker is the wrong shape for a hosted demo: a
scan takes tens of seconds against local disk and materially longer against
the S3 backend, and it holds the one global ingest slot the whole time. This
seeds the graph once, out of band, and the UI then only ever *chooses* among
what is already there.

Run it where the environment already points at the right HydraDB -- which on
a compose deployment means inside the api container, so `HYDRA_HTTP` resolves
to the `hydradb` service rather than to localhost:

    docker compose exec blastradius-api python -m blastradius.seed

Nothing here needs AWS credentials. This process talks to HydraDB over HTTP;
HydraDB is the one that talks to the bucket.

**This never resets the graph.** `run_pipeline(reset=True)` destroys and
recreates the HydraDB *container* via `blastradius.node`, which assumes the
local-filesystem configuration -- on a compose deployment that either fails
outright (no docker socket in the container) or replaces a correctly
configured S3 node with a local one. Seeding is therefore additive, and the
repositories below are merged into whatever the graph already holds. Re-running
is safe: every write is a MERGE by id, so a second run updates rather than
duplicates.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .hydra_client import (
    DEFAULT_GRAPH,
    DEFAULT_HTTP,
    DEFAULT_NAMESPACE,
    DEFAULT_TOKEN,
    HydraClient,
    HydraError,
)

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"

#: The repositories a fresh deployment offers. Ordinary GitHub URLs, cloned
#: into corpus/ like any other checkout -- there is nothing special about
#: them beyond being the set somebody chose to ship.
REPOS = [
    "https://github.com/SanthoshRaaj-KR/BackendGenReal",
    "https://github.com/SanthoshRaaj-KR/Nodus",
    "https://github.com/SanthoshRaaj-KR/GenRealAi-LandingPage",
]


def _client() -> HydraClient:
    """The same environment-driven client the server builds."""
    return HydraClient(
        base_url=os.environ.get("HYDRA_HTTP", DEFAULT_HTTP),
        token=os.environ.get("HYDRA_TOKEN", DEFAULT_TOKEN),
        namespace=os.environ.get("HYDRA_NAMESPACE", DEFAULT_NAMESPACE),
        graph=os.environ.get("HYDRA_GRAPH", DEFAULT_GRAPH),
        # Held just under HydraDB's `client_query_runtime_ms` admission limit,
        # for the reason spelled out in ui/live.py: a request that *declares*
        # more than the server's ceiling is rejected before it runs, so a
        # bigger number here fails everything rather than buying patience.
        timeout_ms=29_000,
    )


def slug_for(url: str) -> str:
    """`https://github.com/owner/repo` -> `owner-repo`, the checkout name."""
    parts = url.rstrip("/").removesuffix(".git").split("/")
    return f"{parts[-2]}-{parts[-1]}"


def clone(url: str, target: Path, force: bool = False) -> None:
    """Shallow-clone `url` to `target`, reusing an existing checkout."""
    if target.exists():
        if not force:
            print(f"  reusing existing checkout at {target}")
            return
        shutil.rmtree(target)

    CORPUS.mkdir(parents=True, exist_ok=True)
    print(f"  cloning {url}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", url, str(target)],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "git clone failed").strip())


def service_names(repo: Path) -> list[str]:
    """Service names this repository's lockfiles would create.

    Uses the ingest's own discovery and naming rule -- the root workspace
    entry of each lockfile, falling back to the folder name -- so a workspace
    names exactly what the scan just wrote.
    """
    from .ingest.load import discover_services
    from .ingest.lockfile import parse_package_lock

    names: list[str] = []
    for project in discover_services(repo):
        try:
            lock = parse_package_lock(project / "package-lock.json", repo=project.name)
            names.append(lock.services.get("", project.name))
        except (OSError, ValueError, KeyError):
            names.append(project.name)
    return sorted({n for n in names if n})


def seed_one(url: str, client: HydraClient, force: bool = False) -> bool:
    """Clone, scan and register one repository. True when it lands."""
    from .chat.workspaces import WorkspaceRegistry
    from .pipeline import run_pipeline

    name = slug_for(url)
    target = CORPUS / name
    print(f"\n=== {name} ===")

    try:
        clone(url, target, force=force)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"  FAILED to clone: {exc}", file=sys.stderr)
        return False

    started = time.perf_counter()
    try:
        report = run_pipeline(
            target,
            client=client,
            reset=False,          # never; see the module docstring
            verbose=False,
            on_stage=lambda stage: print(f"  {stage}"),
        )
    except Exception as exc:  # noqa: BLE001 - one repo must not stop the rest
        print(f"  FAILED to scan: {type(exc).__name__}: {exc}", file=sys.stderr)
        return False

    if report.failures:
        for stage, err in report.failures.items():
            print(f"  FAILED at {stage}: {err}", file=sys.stderr)
        return False

    names = service_names(target)
    if not names:
        print("  FAILED: no services discovered -- nothing to register", file=sys.stderr)
        return False

    workspace = WorkspaceRegistry().register(
        label=name, repo_path=str(target), service_names=names,
    )
    elapsed = time.perf_counter() - started
    print(f"  done in {elapsed:.1f}s -- workspace #{workspace.id}, "
          f"{len(workspace.service_ids)}/{len(names)} services resolved")
    if workspace.collisions:
        # Two repositories sharing a service name share one graph node, and
        # no filter downstream can separate their exposure again.
        print(f"  WARNING: service names already claimed by another workspace: "
              f"{', '.join(workspace.collisions)}", file=sys.stderr)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m blastradius.seed",
        description="Clone and ingest a fixed set of repositories.",
    )
    parser.add_argument(
        "repos", nargs="*", default=None,
        help="repository URLs to seed (default: the built-in set)",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="re-clone even if the checkout already exists",
    )
    args = parser.parse_args(argv)

    urls = args.repos or REPOS
    client = _client()

    print(f"HydraDB: {client.base_url}")
    try:
        client.query("MATCH (n {id: 0}) RETURN n.id AS id")
    except HydraError as exc:
        print(f"\ncannot reach HydraDB: {exc}\n", file=sys.stderr)
        return 2

    ok = sum(seed_one(url, client, force=args.force) for url in urls)
    print(f"\n{ok}/{len(urls)} repositories seeded.")
    # Non-zero when anything failed, so a deploy script can notice.
    return 0 if ok == len(urls) else 1


if __name__ == "__main__":
    raise SystemExit(main())
