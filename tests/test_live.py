"""Live console state: the bus, the path gate, and the aliasing trap.

Three things here are worth pinning down, and each of them was a bug first.

**Publishing must not alias.** The bus hands each subscriber whatever object it
was given and the SSE layer serialises it later, so publishing a mutable dict
means every frame is serialised from whatever state that dict reached by the
time the browser drained its queue. Five simulation stage updates all arrived
reading "done", which looks exactly like the stages never being emitted.

**A slow subscriber must not stall a producer.** A browser tab that stops
reading is ordinary; one that freezes the watcher thread is a denial of service
delivered by closing a laptop lid.

**The path gate is the only thing between a text box and the filesystem.** The
console binds to localhost and is a developer tool, but "type a path and we
will walk it" still needs a floor and a clear refusal.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ui.live import SUBSCRIBER_QUEUE, Bus, IngestJob, LiveState, Stage, _split  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


# -- the bus ----------------------------------------------------------------


def test_every_subscriber_receives_a_publish():
    bus = Bus()
    a, b = bus.subscribe(), bus.subscribe()
    bus.publish({"n": 1})
    assert a.get_nowait() == {"n": 1}
    assert b.get_nowait() == {"n": 1}


def test_a_full_subscriber_drops_its_oldest_and_never_blocks():
    bus = Bus()
    q = bus.subscribe()
    started = time.perf_counter()
    for i in range(SUBSCRIBER_QUEUE * 2):
        bus.publish({"n": i})
    assert time.perf_counter() - started < 2.0, "publish must never block"
    assert q.qsize() <= SUBSCRIBER_QUEUE

    seen = []
    while not q.empty():
        seen.append(q.get_nowait()["n"])
    assert seen[-1] == SUBSCRIBER_QUEUE * 2 - 1, "the newest event survives"
    assert 0 not in seen, "the oldest was dropped"


def test_unsubscribe_stops_delivery_and_is_idempotent():
    bus = Bus()
    q = bus.subscribe()
    bus.unsubscribe(q)
    bus.unsubscribe(q)
    bus.publish({"n": 1})
    assert q.empty()
    assert bus.count == 0


def test_publishing_with_no_subscribers_is_harmless():
    Bus().publish({"n": 1})


# -- the aliasing trap ------------------------------------------------------


def test_simulation_frames_are_snapshots_not_references():
    """The bug this test exists for.

    `_emit_sim` used to publish the live dict. Every queued frame then
    serialised from the *final* state, so a run that moved through five
    stages delivered five identical "done" frames.
    """
    state = LiveState.__new__(LiveState)
    state.bus = Bus()
    q = state.bus.subscribe()

    state.simulation = {"spec": "x@1", "status": "running", "stage": "one"}
    state._emit_sim()
    state.simulation["stage"] = "two"
    state._emit_sim()
    state.simulation["status"] = "done"
    state.simulation["stage"] = ""
    state._emit_sim()

    frames = [q.get_nowait()["simulation"] for _ in range(3)]
    assert [f["stage"] for f in frames] == ["one", "two", ""]
    assert [f["status"] for f in frames] == ["running", "running", "done"]


def test_emitting_a_cleared_simulation_sends_null():
    """A retraction must not serialise as an empty result object.

    The browser distinguishes "no simulation" from "a simulation that found
    nothing", and the second is a claim about the graph.
    """
    state = LiveState.__new__(LiveState)
    state.bus = Bus()
    q = state.bus.subscribe()
    state.simulation = None
    state._emit_sim()
    assert q.get_nowait()["simulation"] is None


# -- the path gate ----------------------------------------------------------


def test_a_real_directory_resolves():
    assert LiveState.resolve_repo(str(REPO)) == REPO


def test_relative_and_user_paths_resolve():
    assert LiveState.resolve_repo("~").is_absolute()


def test_quotes_and_whitespace_are_tolerated():
    """Paths get pasted with the quotes still attached."""
    assert LiveState.resolve_repo(f'  "{REPO}"  ') == REPO
    assert LiveState.resolve_repo(f"'{REPO}'") == REPO


@pytest.mark.parametrize("bad", ["", "   ", "/no/such/place/at/all"])
def test_unusable_paths_are_refused_with_a_reason(bad):
    with pytest.raises(ValueError) as exc:
        LiveState.resolve_repo(bad)
    assert str(exc.value), "a refusal must say what was wrong"


def test_system_directories_are_refused():
    """/etc resolves to /private/etc on macOS, so both spellings are barred."""
    with pytest.raises(ValueError, match="system directory"):
        LiveState.resolve_repo("/etc")


def test_a_file_is_not_a_directory():
    with pytest.raises(ValueError, match="not a directory"):
        LiveState.resolve_repo(str(REPO / "README.md"))


def test_describe_reports_usability_and_says_why_not():
    """A directory with no lockfile is a real answer, not an error."""
    good = LiveState.describe_repo(REPO)
    assert good["usable"] is (good["lockfile_count"] > 0)

    empty = LiveState.describe_repo(REPO / "docs")
    if not empty["lockfile_count"]:
        assert empty["usable"] is False
        assert "package-lock.json" in empty["note"]


# -- specs ------------------------------------------------------------------


@pytest.mark.parametrize("spec,expected", [
    ("lodash@4.17.21", ("lodash", "4.17.21")),
    ("@angular/core@17.0.0", ("@angular/core", "17.0.0")),
    ("a@1.0.0-beta.1+build", ("a", "1.0.0-beta.1+build")),
])
def test_split_handles_scopes_and_prerelease(spec, expected):
    assert _split(spec) == expected


@pytest.mark.parametrize("bad", ["lodash", "@angular/core", "", "@"])
def test_split_rejects_a_bare_name(bad):
    with pytest.raises(ValueError):
        _split(bad)


# -- job serialisation ------------------------------------------------------


def test_job_serialises_for_the_browser():
    import json

    job = IngestJob(repo="/tmp/x", reset=True, status="running")
    job.stages.append(Stage(name="reset", status="ok", seconds=1.234))
    payload = job.to_dict()
    json.dumps(payload)
    assert payload["stages"][0]["seconds"] == 1.23
    assert payload["status"] == "running"


def test_job_dict_is_a_fresh_object_each_call():
    """Why the ingest stream escaped the aliasing bug the simulation hit."""
    job = IngestJob(repo="/tmp/x")
    first = job.to_dict()
    job.status = "done"
    assert first["status"] != job.to_dict()["status"]


# -- threading --------------------------------------------------------------


def test_bus_is_safe_under_concurrent_publishers():
    bus = Bus()
    q = bus.subscribe()
    errors: list[Exception] = []

    def spam(n):
        try:
            for i in range(200):
                bus.publish({"who": n, "i": i})
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=spam, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert not errors
    assert q.qsize() <= SUBSCRIBER_QUEUE
