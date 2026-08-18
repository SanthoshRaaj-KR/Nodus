"""HydraDB container lifecycle, driven from Python instead of PowerShell.

`hydra.ps1` does the same job, but running an unsigned .ps1 needs the execution
policy loosened, which is a poor thing to ask of anyone just trying to start a
database. This module shells out to `docker` directly with an argument list --
no shell, so nothing re-interprets the container-side paths.

That last point is the reason this exists rather than a bash script: Git Bash
applies MSYS path translation to anything that looks like a Unix absolute path,
so `-e LOCAL_PATH=/data/store` reaches the container as
`C:/Program Files/Git/data/store` and the node dies with a bare
`PermissionDenied` naming no path. Python's subprocess does no such rewriting.
"""

from __future__ import annotations

import shutil
import subprocess
import time
import urllib.error
import urllib.request

IMAGE = "ghcr.io/hydra-db/hydradb:latest"
CONTAINER = "hydradb"
VOLUME = "hydradb-data"
TOKEN = "local-development-token-32-bytes"
ADMIN = "http://127.0.0.1:9090"

#: The image runs as this uid/gid. A named volume is used rather than a bind
#: mount because a Windows bind mount cannot express that ownership, and the
#: node then fails on its first storage write.
IMAGE_UID = "10001:10001"

RUN_ARGS = [
    "-p", "7687:7687",
    "-p", "8443:8443",
    "-p", "9090:9090",
    "-v", f"{VOLUME}:/data",
    "-e", "CLOUD_PROVIDER=local",
    "-e", "LOCAL_PATH=/data/store",
    "-e", "GRAPH_NAMESPACE=default",
    "-e", "GRAPH_ID=default",
    "-e", "GRAPH_CELL_ID=cell-0",
    "-e", "GRAPH_CELLS=cell-0",
    "-e", "GRAPH_NODE_ID=node-0",
    "-e", "GRAPH_BOLT_NODE_ADDRESSES=node-0=127.0.0.1:7687",
    "-e", "GRAPH_ADVERTISED_BOLT_ADDR=127.0.0.1:7687",
    "-e", "GRAPH_DATA_CACHE_DIR=/data/cache",
    "-e", "GRAPH_AUTH_TOKEN_FILE=/data/auth-token",
    "-e", "GRAPH_ALLOW_PLAINTEXT=true",
    "-e", "RUST_MIN_STACK=33554432",
]


class NodeError(RuntimeError):
    """Something about the container or the daemon is wrong."""


def _docker(*args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    if shutil.which("docker") is None:
        raise NodeError(
            "`docker` is not on PATH. Install Docker Desktop, or open a new "
            "terminal if you just installed it."
        )
    result = subprocess.run(
        ["docker", *args],
        capture_output=capture,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and result.returncode != 0:
        raise NodeError((result.stderr or result.stdout or "").strip()[:800])
    return result


def daemon_ready() -> bool:
    try:
        return _docker("version", "--format", "{{.Server.Version}}", check=False).returncode == 0
    except NodeError:
        return False


def require_daemon() -> None:
    if not daemon_ready():
        raise NodeError(
            "Docker daemon is not reachable.\n"
            "  Start Docker Desktop from the Start menu and wait for the whale\n"
            "  icon in the tray to stop animating, then run this again."
        )


def container_state() -> str:
    """'running', 'exited', 'missing', ..."""
    result = _docker(
        "ps", "-a", "--filter", f"name=^{CONTAINER}$", "--format", "{{.State}}", check=False
    )
    return (result.stdout or "").strip() or "missing"


def readyz(timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(f"{ADMIN}/readyz", timeout=timeout) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError):
        return False


def init_volume(verbose: bool = True) -> None:
    """Create the volume and seed store, cache and auth token. Idempotent."""
    existing = _docker("volume", "ls", "--quiet", "--filter", f"name=^{VOLUME}$", check=False)
    if not (existing.stdout or "").strip():
        if verbose:
            print(f"  creating volume {VOLUME}")
        _docker("volume", "create", VOLUME)

    # The token file and directories must exist and be owned by the image's
    # uid before the node starts, so a throwaway container prepares them.
    script = (
        "mkdir -p /data/store /data/cache && "
        f"printf '%s\\n' '{TOKEN}' > /data/auth-token && "
        f"chown -R {IMAGE_UID} /data"
    )
    if verbose:
        print("  seeding volume (store, cache, auth token)")
    _docker("run", "--rm", "-v", f"{VOLUME}:/data", "--entrypoint", "/bin/sh", IMAGE, "-c", script)


def up(wait: int = 90, verbose: bool = True) -> None:
    require_daemon()
    if container_state() == "running" and readyz():
        if verbose:
            print(f"  {CONTAINER} is already running and ready")
        return

    _docker("rm", "-f", CONTAINER, check=False)
    init_volume(verbose)

    if verbose:
        print(f"  starting {CONTAINER}")
    _docker("run", "-d", "--name", CONTAINER, *RUN_ARGS, IMAGE)

    if verbose:
        print("  waiting for readiness", end="", flush=True)
    for _ in range(wait):
        time.sleep(1)
        if readyz():
            if verbose:
                print(" ready")
            return
        if container_state() not in ("running", "created"):
            logs = _docker("logs", "--tail", "40", CONTAINER, check=False)
            raise NodeError(
                f"container exited during startup:\n{logs.stdout}\n{logs.stderr}"
            )
        if verbose:
            print(".", end="", flush=True)
    if verbose:
        print()
    logs = _docker("logs", "--tail", "40", CONTAINER, check=False)
    raise NodeError(f"node did not become ready in {wait}s. Recent logs:\n{logs.stdout}")


def down(verbose: bool = True) -> None:
    require_daemon()
    _docker("rm", "-f", CONTAINER, check=False)
    if verbose:
        print(f"  {CONTAINER} stopped (volume {VOLUME} kept)")


def logs(tail: int = 60) -> str:
    require_daemon()
    result = _docker("logs", "--tail", str(tail), CONTAINER, check=False)
    return (result.stdout or "") + (result.stderr or "")


def wipe(verbose: bool = True) -> None:
    """Destroy the container and the volume. The data does not come back."""
    require_daemon()
    _docker("rm", "-f", CONTAINER, check=False)
    _docker("volume", "rm", VOLUME, check=False)
    if verbose:
        print("  container and volume destroyed")
