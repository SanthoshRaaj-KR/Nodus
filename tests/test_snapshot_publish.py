"""Where a published snapshot goes, and what happens when it cannot go there.

The upload itself is one boto3 call and is not worth mocking for its own
sake. What is worth pinning down is everything around it: the bucket and key
a given environment resolves to, the rule that decides whether a build
publishes at all, and the promise that a failed upload never costs you the
graph you just spent ten minutes building. Those are the parts that are
configuration rather than code, and the parts that fail on somebody else's
machine at the end of a long run.

No credentials and no network: the client is replaced with a recorder.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blastradius import snapshot  # noqa: E402


class FakeS3:
    """Records what it was asked to do, and can be told to refuse."""

    def __init__(self, fail: str = "") -> None:
        self.uploads: list[tuple[str, str, str]] = []
        self.downloads: list[tuple[str, str, str]] = []
        self.fail = fail

    def upload_file(self, path, bucket, key):
        if self.fail:
            raise RuntimeError(self.fail)
        self.uploads.append((str(path), bucket, key))

    def download_file(self, bucket, key, path):
        if self.fail:
            raise RuntimeError(self.fail)
        self.downloads.append((bucket, key, str(path)))


@pytest.fixture
def clean_env(monkeypatch):
    for name in ("SNAPSHOT_BUCKET", "SNAPSHOT_PREFIX", "SNAPSHOT_NAME",
                 "SNAPSHOT_REGION", "SNAPSHOT_AUTO_PUSH", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(name, raising=False)


# -- where it goes ---------------------------------------------------------

def test_no_bucket_configured_means_no_publish(clean_env):
    """A machine that was never told about a bucket keeps its builds."""
    assert snapshot.s3_config()["auto"] is False


def test_naming_a_bucket_is_enough_to_turn_publishing_on(clean_env, monkeypatch):
    """The whole configuration surface is one variable.

    Anyone who has gone to the trouble of naming a bucket wants the build to
    land in it, so that is the switch. Requiring a second flag would mean a
    build that quietly stayed local on a host set up to publish.
    """
    monkeypatch.setenv("SNAPSHOT_BUCKET", "my-graphs")
    assert snapshot.s3_config()["auto"] is True


def test_publishing_can_be_declined_while_keeping_the_bucket(clean_env, monkeypatch):
    monkeypatch.setenv("SNAPSHOT_BUCKET", "my-graphs")
    monkeypatch.setenv("SNAPSHOT_AUTO_PUSH", "0")
    assert snapshot.s3_config()["auto"] is False


def test_key_is_prefix_plus_name(clean_env, monkeypatch, tmp_path):
    monkeypatch.setenv("SNAPSHOT_BUCKET", "my-graphs")
    monkeypatch.setenv("SNAPSHOT_PREFIX", "builds/")
    monkeypatch.setenv("SNAPSHOT_NAME", "nightly.tar.gz")
    fake = FakeS3()
    monkeypatch.setattr(snapshot, "_client", lambda region: fake)

    archive = tmp_path / "snap.tar.gz"
    archive.write_bytes(b"not really a tarball")
    uri = snapshot.push(archive, verbose=False)

    assert uri == "s3://my-graphs/builds/nightly.tar.gz"
    assert fake.uploads == [(str(archive), "my-graphs", "builds/nightly.tar.gz")]


def test_a_trailing_slash_on_the_prefix_does_not_double(clean_env, monkeypatch, tmp_path):
    """`builds/` and `builds` are the same place, whichever one is typed."""
    monkeypatch.setenv("SNAPSHOT_BUCKET", "b")
    fake = FakeS3()
    monkeypatch.setattr(snapshot, "_client", lambda region: fake)
    archive = tmp_path / "s.tar.gz"
    archive.write_bytes(b"x")

    for prefix in ("builds/", "builds", "/builds/"):
        monkeypatch.setenv("SNAPSHOT_PREFIX", prefix)
        assert snapshot.push(archive, verbose=False) == "s3://b/builds/s.tar.gz"


def test_region_falls_back_to_the_aws_default(clean_env, monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    assert snapshot.s3_config()["region"] == "eu-west-1"


# -- when it cannot go there ----------------------------------------------

def test_a_refused_upload_names_the_target(clean_env, monkeypatch, tmp_path):
    """The SDK's own message survives, with the URI that was attempted.

    "Access Denied" alone does not say which bucket, and a misconfigured
    prefix looks identical to a missing permission without it.
    """
    monkeypatch.setenv("SNAPSHOT_BUCKET", "locked")
    monkeypatch.setattr(snapshot, "_client",
                        lambda region: FakeS3(fail="AccessDenied"))
    archive = tmp_path / "s.tar.gz"
    archive.write_bytes(b"x")

    with pytest.raises(snapshot.SnapshotError) as err:
        snapshot.push(archive, verbose=False)
    assert "s3://locked/snapshots/s.tar.gz" in str(err.value)
    assert "AccessDenied" in str(err.value)


def test_missing_boto3_says_what_to_do(clean_env, monkeypatch):
    """The dependency is optional until a bucket is named, so say so."""
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) \
        else __builtins__.__import__

    def no_boto3(name, *a, **kw):
        if name == "boto3":
            raise ImportError("no boto3")
        return real_import(name, *a, **kw)

    monkeypatch.setattr("builtins.__import__", no_boto3)
    with pytest.raises(snapshot.SnapshotError) as err:
        snapshot._client("ap-south-2")
    assert "boto3 is not installed" in str(err.value)
    assert "SNAPSHOT_BUCKET" in str(err.value)


def test_publishing_never_costs_you_the_build(clean_env, monkeypatch, tmp_path):
    """A failed upload leaves the ingest reported as done.

    The graph is finished and correct on this machine whether or not the
    bucket accepted a copy of it. Failing the whole run for a storage
    misconfiguration would throw away ten minutes of work to report a problem
    that a retry of the last stage fixes.
    """
    calls = {"published": 0}

    def boom(*a, **kw):
        calls["published"] += 1
        raise snapshot.SnapshotError("bucket is on fire")

    monkeypatch.setattr(snapshot, "publish", boom)
    monkeypatch.setenv("SNAPSHOT_BUCKET", "b")

    from ui import live

    job = live.IngestJob(repo="/tmp/x")
    stages: list[str] = []

    def on_stage(name: str) -> None:
        stages.append(name)
        job.stages.append(live.Stage(name=name))

    state = live.LiveState.__new__(live.LiveState)
    state.job = job
    state.bus = types.SimpleNamespace(publish=lambda payload: None)
    state._publish_snapshot(job, on_stage)

    assert calls["published"] == 1
    assert stages == ["publish to s3"]
    assert job.stages[-1].status == "failed"
    assert "bucket is on fire" in job.snapshot_error
    # The caller sets `done` after this returns; the point is that it still can.
    assert job.status != "failed"


# -- publishing into a live bucket ----------------------------------------

class FakeLiveS3(FakeS3):
    """Enough of the object API to check keys, and what gets deleted."""

    def __init__(self, existing: list[str] | None = None) -> None:
        super().__init__()
        self.objects: dict[str, bytes] = {k: b"old" for k in (existing or [])}
        self.deleted: list[str] = []

    def put_object(self, Bucket, Key, Body):  # noqa: N803 - boto3 spelling
        self.objects[Key] = Body

    def list_objects_v2(self, Bucket, Prefix="", **kw):  # noqa: N803
        hits = [{"Key": k} for k in sorted(self.objects) if k.startswith(Prefix)]
        return {"Contents": hits, "IsTruncated": False}

    def delete_objects(self, Bucket, Delete):  # noqa: N803
        for obj in Delete["Objects"]:
            self.deleted.append(obj["Key"])
            self.objects.pop(obj["Key"], None)


def test_sync_writes_the_store_as_keys_under_the_prefix(clean_env, monkeypatch):
    """The relative path in the store is the S3 key, which is the whole trick."""
    monkeypatch.setenv("SNAPSHOT_BUCKET", "live")
    monkeypatch.setenv("SNAPSHOT_PREFIX", "")
    fake = FakeLiveS3()
    monkeypatch.setattr(snapshot, "_client", lambda region: fake)
    monkeypatch.setattr(snapshot, "_store_files", lambda: [
        ("graph/data/_graph_nodes/v1/node-0", b"a"),
        ("graph/data/namespaces/default/graphs/default/cell-0/wal/001.sst", b"b"),
    ])
    monkeypatch.setattr(snapshot, "IDS", Path("/nonexistent/ids.sqlite"))

    out = snapshot.sync(verbose=False)
    assert out["uploaded"] == 2
    assert set(fake.objects) == {
        "graph/data/_graph_nodes/v1/node-0",
        "graph/data/namespaces/default/graphs/default/cell-0/wal/001.sst",
    }


def test_sync_removes_what_the_previous_graph_left(clean_env, monkeypatch):
    """A stale WAL segment is not clutter, it is a second graph.

    Left in place, the node opens a mix of the two and answers from neither.
    """
    monkeypatch.setenv("SNAPSHOT_BUCKET", "live")
    monkeypatch.setenv("SNAPSHOT_PREFIX", "")
    fake = FakeLiveS3(existing=["graph/data/old/wal/999.sst", "graph/data/keep/a"])
    monkeypatch.setattr(snapshot, "_client", lambda region: fake)
    monkeypatch.setattr(snapshot, "_store_files", lambda: [("graph/data/keep/a", b"new")])
    monkeypatch.setattr(snapshot, "IDS", Path("/nonexistent/ids.sqlite"))

    out = snapshot.sync(verbose=False)
    assert fake.deleted == ["graph/data/old/wal/999.sst"]
    assert out["pruned"] == 1
    assert fake.objects["graph/data/keep/a"] == b"new"


def test_sync_can_be_told_to_leave_the_bucket_alone(clean_env, monkeypatch):
    monkeypatch.setenv("SNAPSHOT_BUCKET", "live")
    fake = FakeLiveS3(existing=["snapshots/graph/data/old", "snapshots/x"])
    monkeypatch.setattr(snapshot, "_client", lambda region: fake)
    monkeypatch.setattr(snapshot, "_store_files", lambda: [("graph/data/new", b"n")])
    monkeypatch.setattr(snapshot, "IDS", Path("/nonexistent/ids.sqlite"))

    snapshot.sync(verbose=False, prune=False)
    assert fake.deleted == []


def test_sync_carries_the_id_map_and_never_prunes_it(clean_env, monkeypatch, tmp_path):
    """The map is not an object store key, and deleting it empties the graph."""
    monkeypatch.setenv("SNAPSHOT_BUCKET", "live")
    ids = tmp_path / "ids.sqlite"
    import sqlite3 as _s
    _s.connect(str(ids)).close()
    monkeypatch.setattr(snapshot, "IDS", ids)

    fake = FakeLiveS3(existing=["snapshots/ids.sqlite"])
    monkeypatch.setattr(snapshot, "_client", lambda region: fake)
    monkeypatch.setattr(snapshot, "_store_files", lambda: [("graph/data/a", b"a")])

    snapshot.sync(verbose=False)
    assert "snapshots/ids.sqlite" not in fake.deleted
    assert "snapshots/ids.sqlite" in fake.objects
