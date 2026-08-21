"""Move a built graph between machines as one piece.

**Why this exists.** The graph is stored in two places that are useless
without each other. HydraDB holds the nodes and edges, in a docker volume
when ``CLOUD_PROVIDER=local`` and in S3 when it is ``aws``. Every name -> id
lookup lives in ``data/ids.sqlite``, and those ids are assigned by insertion
order into that file rather than derived from the graph, so a store restored
next to a different id map resolves nothing. It does not error: the queries
run, match no rows, and the console draws an empty canvas, which reads as
"you have no vulnerabilities" rather than as a storage fault. Shipping the
two together in one archive is the only way to make that mistake impossible
to make.

**Why an archive rather than syncing the bucket.** ``local`` is the cheap
place to build -- no credentials, no egress, no shared bucket to corrupt --
but its object store does not implement the update-in-place write a ``MERGE``
onto an existing node needs, so it can only do a from-empty ingest. That is
exactly the shape of "build the whole graph in one run, then publish it",
which is what this supports: build locally, ``save``, ship the file, ``load``
it where it is served.

The cache directory is deliberately excluded. It is derived from the store,
it is the larger half on disk, and the hosted stack gives it its own volume.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

from . import node

__all__ = ["save", "load", "describe", "push", "pull", "publish",
           "s3_config", "SnapshotError"]

#: Bumped when the archive layout changes in a way an older reader would get
#: wrong. `load` refuses a version it does not know rather than unpacking a
#: shape it will misread.
FORMAT = 1

ROOT = Path(__file__).resolve().parents[1]
IDS = ROOT / "data" / "ids.sqlite"

#: Everything under the volume worth carrying, relative to /data.
STORE_DIR = "store"

#: Where a published snapshot lands. The bucket defaults to the one the hosted
#: stack already reads, but under its own prefix: HydraDB owns the top of that
#: bucket as a live object store, and dropping archives beside its keys would
#: put two different things with two different lifecycles in one namespace.
DEFAULT_BUCKET = node.AWS_BUCKET_NAME
DEFAULT_PREFIX = "snapshots/"
DEFAULT_NAME = "graph-latest.tar.gz"


def s3_config() -> dict:
    """Bucket, prefix and region, from the environment.

    Credentials are deliberately not read here. boto3 resolves them from the
    standard chain -- environment, ~/.aws, instance role -- so a host with a
    role attached needs no secret in the config, and a laptop with a profile
    needs nothing but the profile it already has.
    """
    import os

    return {
        "bucket": os.environ.get("SNAPSHOT_BUCKET", DEFAULT_BUCKET),
        "prefix": os.environ.get("SNAPSHOT_PREFIX", DEFAULT_PREFIX),
        "name": os.environ.get("SNAPSHOT_NAME", DEFAULT_NAME),
        "region": os.environ.get(
            "SNAPSHOT_REGION",
            os.environ.get("AWS_DEFAULT_REGION", node.AWS_DEFAULT_REGION),
        ),
        # Auto-publish is on as soon as a bucket is named. Someone who has
        # gone to the trouble of configuring one wants the build to land
        # there; someone who has not gets a local build and no surprise
        # egress bill.
        "auto": os.environ.get(
            "SNAPSHOT_AUTO_PUSH",
            "1" if os.environ.get("SNAPSHOT_BUCKET") else "0",
        ).strip().lower() in ("1", "true", "yes", "on"),
    }


def _client(region: str):
    """A boto3 S3 client, with the two failure modes named.

    Both are configuration rather than code, and both are much easier to fix
    when the message says which one happened.
    """
    try:
        import boto3  # noqa: PLC0415 - optional until a bucket is configured
    except ImportError:  # pragma: no cover - depends on the install
        raise SnapshotError(
            "boto3 is not installed, so a snapshot cannot be published. "
            "`pip install -r requirements.txt`, or drop SNAPSHOT_BUCKET to "
            "keep builds local."
        ) from None
    try:
        return boto3.client("s3", region_name=region)
    except Exception as exc:  # noqa: BLE001 - surfaced verbatim
        raise SnapshotError(f"could not open an S3 client: {exc}") from None


def _key(cfg: dict, name: str) -> str:
    """Prefix plus file name, with the slashes sorted out once."""
    prefix = cfg["prefix"].strip("/")
    return f"{prefix}/{name}" if prefix else name


def push(path: str | Path, verbose: bool = True, **over) -> str:
    """Upload an archive and return its ``s3://`` URI.

    The object is named after the file unless ``SNAPSHOT_NAME`` says
    otherwise. Uploading ``nightly.tar.gz`` and finding it in the bucket
    under some other name is the kind of surprise that costs an hour when the
    host is pulling a key that nothing writes.
    """
    import os

    cfg = {**s3_config(), **over}
    path = Path(path).expanduser().resolve()
    if not path.exists():
        raise SnapshotError(f"no such snapshot: {path}")

    key = _key(cfg, over.get("name") or os.environ.get("SNAPSHOT_NAME") or path.name)
    uri = f"s3://{cfg['bucket']}/{key}"
    client = _client(cfg["region"])
    if verbose:
        mb = path.stat().st_size / 1e6
        print(f"  uploading {mb:.1f} MB to {uri}")
    try:
        client.upload_file(str(path), cfg["bucket"], key)
    except Exception as exc:  # noqa: BLE001 - the SDK message is the useful part
        raise SnapshotError(f"upload to {uri} failed: {exc}") from None
    if verbose:
        print(f"  published {uri}")
    return uri


def pull(dest: str | Path, verbose: bool = True, **over) -> Path:
    """Download the published archive to ``dest``."""
    cfg = {**s3_config(), **over}
    dest = Path(dest).expanduser().resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)

    key = _key(cfg, cfg["name"])
    uri = f"s3://{cfg['bucket']}/{key}"
    client = _client(cfg["region"])
    if verbose:
        print(f"  downloading {uri}")
    try:
        client.download_file(cfg["bucket"], key, str(dest))
    except Exception as exc:  # noqa: BLE001
        raise SnapshotError(f"download of {uri} failed: {exc}") from None
    if verbose:
        print(f"  wrote {dest} ({dest.stat().st_size / 1e6:.1f} MB)")
    return dest


def publish(verbose: bool = True, **over) -> str:
    """Save the current graph and upload it, leaving no file behind.

    This is the whole point of the module in one call: the graph was built
    locally, and now it is somewhere a host can read it. The archive is
    written to a temporary path because keeping it would leave a stale copy
    of a graph that is about to change again.
    """
    cfg = {**s3_config(), **over}
    with tempfile.TemporaryDirectory() as tmp:
        # Named for the key it is about to become, so `push` needs no special
        # case and the file on disk matches the object in the bucket.
        archive = save(Path(tmp) / cfg["name"], verbose=verbose)
        return push(archive, verbose=verbose, **over)


class SnapshotError(RuntimeError):
    """The archive, the volume or the id map is not in a usable state."""


def _volume_sh(script: str) -> subprocess.CompletedProcess:
    """Run a shell snippet against the HydraDB volume in a throwaway container.

    The volume is owned by the image's uid and is not a bind mount, so it is
    not readable from the host directly -- a container is the only way in.
    Binary mode throughout: this carries a tar stream on stdout, and decoding
    that as text corrupts it in a way that only shows up on extract.
    """
    return subprocess.run(
        ["docker", "run", "--rm", "-v", f"{node.VOLUME}:/d", "alpine", "sh", "-c", script],
        capture_output=True,
    )


def _checkpoint_ids() -> None:
    """Fold the SQLite WAL back into the main file before it is copied.

    Copying ``ids.sqlite`` without ``-wal`` silently drops whatever the last
    ingest wrote, which is the newest and most interesting part of the map.
    Checkpointing means the single file is complete and the archive does not
    have to carry three.
    """
    if not IDS.exists():
        return
    conn = sqlite3.connect(str(IDS))
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()


def _running() -> bool:
    try:
        return node.container_state() == "running"
    except node.NodeError:
        return False


def save(dest: str | Path, verbose: bool = True) -> Path:
    """Write the store and the id map to one ``.tar.gz``.

    The node is stopped first. HydraDB buffers writes, and an archive taken
    from a live volume is a copy of a file set nobody promised was consistent
    -- the failure shows up later as a store that loads and is subtly short.
    It is restarted afterwards only if it was running to begin with.
    """
    node.require_daemon()
    dest = Path(dest).expanduser().resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)

    was_running = _running()
    if was_running:
        if verbose:
            print("  stopping the node for a consistent copy")
        node.down(verbose=False)

    try:
        _checkpoint_ids()
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp)
            # Out of the volume, into a host directory, as a tar on stdout so
            # nothing has to be chowned on the way.
            if verbose:
                print("  reading the store out of the volume")
            proc = _volume_sh(f"tar cf - -C /d {STORE_DIR}")
            if proc.returncode != 0 or not proc.stdout:
                detail = proc.stderr.decode(errors="replace").strip()
                raise SnapshotError(
                    f"could not read {STORE_DIR} from volume {node.VOLUME}: "
                    f"{detail or 'nothing to read -- has anything been ingested?'}"
                )
            store_tar = staging / "store.tar"
            store_tar.write_bytes(proc.stdout)

            if IDS.exists():
                shutil.copy2(IDS, staging / "ids.sqlite")
            elif verbose:
                print("  warning: no data/ids.sqlite -- the archive will not be loadable")

            meta = {
                "format": FORMAT,
                "created_at": int(time.time()),
                "store_bytes": store_tar.stat().st_size,
                "ids_bytes": IDS.stat().st_size if IDS.exists() else 0,
                "volume": node.VOLUME,
            }
            (staging / "manifest.json").write_text(json.dumps(meta, indent=2))

            if verbose:
                print(f"  writing {dest.name}")
            with tarfile.open(dest, "w:gz") as tar:
                for name in ("manifest.json", "store.tar", "ids.sqlite"):
                    path = staging / name
                    if path.exists():
                        tar.add(path, arcname=name)
    finally:
        if was_running:
            node.up(verbose=False)

    if verbose:
        mb = dest.stat().st_size / 1e6
        print(f"  saved {dest} ({mb:.1f} MB)")
    return dest


def describe(src: str | Path) -> dict:
    """Read the manifest without unpacking anything."""
    src = Path(src).expanduser().resolve()
    if not src.exists():
        raise SnapshotError(f"no such snapshot: {src}")
    with tarfile.open(src, "r:gz") as tar:
        member = tar.extractfile("manifest.json")
        if member is None:
            raise SnapshotError(f"{src} has no manifest -- not a graph snapshot")
        return json.loads(member.read().decode())


def load(src: str | Path, verbose: bool = True) -> dict:
    """Replace the store and the id map with the ones in ``src``.

    Destructive by design and in that order: a half-applied restore is the
    desynced state this module exists to prevent, so the store is only wiped
    once the archive has been read and validated.
    """
    node.require_daemon()
    src = Path(src).expanduser().resolve()
    meta = describe(src)
    if meta.get("format") != FORMAT:
        raise SnapshotError(
            f"snapshot format {meta.get('format')!r}, this build reads {FORMAT}"
        )

    was_running = _running()
    if was_running:
        if verbose:
            print("  stopping the node")
        node.down(verbose=False)

    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp)
        with tarfile.open(src, "r:gz") as tar:
            tar.extractall(staging)

        store_tar = staging / "store.tar"
        if not store_tar.exists():
            raise SnapshotError(f"{src} carries no store")

        node.init_volume(verbose=False)
        if verbose:
            print("  replacing the store in the volume")
        proc = subprocess.run(
            ["docker", "run", "--rm", "-i", "-v", f"{node.VOLUME}:/d", "alpine",
             "sh", "-c", f"rm -rf /d/{STORE_DIR} && tar xf - -C /d"],
            input=store_tar.read_bytes(), capture_output=True,
        )
        if proc.returncode != 0:
            raise SnapshotError(
                f"could not write the store into {node.VOLUME}: "
                f"{proc.stderr.decode(errors='replace').strip()}"
            )

        ids = staging / "ids.sqlite"
        if ids.exists():
            IDS.parent.mkdir(parents=True, exist_ok=True)
            # The WAL and shm belong to the map being replaced; leaving them
            # would have SQLite reapply the old tail over the new file.
            for leftover in IDS.parent.glob("ids.sqlite-*"):
                leftover.unlink()
            shutil.copy2(ids, IDS)
            if verbose:
                print(f"  restored the id map to {IDS}")
        elif verbose:
            print("  warning: the archive carries no id map, the graph will resolve nothing")

    if was_running or verbose:
        if verbose:
            print("  starting the node")
        node.up(verbose=False)

    if verbose:
        age = time.time() - meta.get("created_at", time.time())
        print(f"  loaded a snapshot taken {age / 3600:.1f}h ago")
    return meta
