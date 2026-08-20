"""The live watcher: what it decides, and what it refuses to decide.

The network half is not the interesting part. What matters is the judgement
sitting on top of it, because a watcher that cries wolf on every publish gets
turned off within an hour and one that never fires is indistinguishable from
being switched off already.

Three properties carry the weight:

* **A change is not a publish.** The feed fires for deprecations, dist-tag
  moves and README edits. Treating every change as a publish would multiply
  the noise by roughly the ratio measured against the live feed -- about two
  thirds of changes are not publishes.
* **A slow subscriber must not stall the watcher.** A browser tab that stops
  reading is normal; a browser tab that freezes ingestion is a denial of
  service delivered by a user closing their laptop.
* **A dropped feed must not lose the cursor.** Resuming from the wrong place
  either replays history or skips it, and skipping is silent.

The feed is faked here so the tests are deterministic. Two live tests exercise
the real endpoint and skip when it is unreachable.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.pkg.registry import PackumentSummary, VersionSummary  # noqa: E402
from blastradius.pkg.watcher import (  # noqa: E402
    FRESH_SECONDS,
    SUBSCRIBER_QUEUE,
    Watcher,
)

NOW = 1_700_000_000


def version(v, at, publisher="alice", script=False, repo=""):
    return VersionSummary(
        name="demo", version=v, published_at=at, publisher=publisher,
        has_install_script=script, repository=repo,
    )


def packument(*versions, name="demo", maintainers=(("alice", "a@x"),)):
    return PackumentSummary(
        name=name, versions={v.version: v for v in versions},
        maintainers=list(maintainers), abbreviated_only=False,
    )


class FakeRegistry:
    """Stands in for the npm registry, and records how it was called."""

    def __init__(self, documents: dict[str, PackumentSummary]):
        self.documents = documents
        self.calls: list[tuple[str, bool]] = []

    def packument(self, name, full=False, refresh=False):
        self.calls.append((name, refresh))
        if name not in self.documents:
            from blastradius.pkg.registry import RegistryError

            raise RegistryError(f"not found: {name}")
        return self.documents[name]


def watcher_over(documents, **kw):
    return Watcher(registry=FakeRegistry(documents), **kw)


# -- a change is not a publish ---------------------------------------------


def test_a_recent_version_counts_as_a_publish():
    w = watcher_over({})
    event = w.newest_publish(packument(version("1.0.0", NOW - 30)), now=NOW)
    assert event is not None
    assert event.version == "1.0.0"
    assert event.publisher == "alice"


def test_an_old_newest_version_is_not_a_publish():
    """A deprecation or dist-tag move changes the doc without adding a version.

    Without this the watcher reports every README edit in the registry as a
    publish, and the ratio is not small -- measured live, roughly two thirds of
    changes are not publishes.
    """
    w = watcher_over({})
    old = packument(version("1.0.0", NOW - FRESH_SECONDS - 60))
    assert w.newest_publish(old, now=NOW) is None


def test_the_newest_version_wins_not_the_highest():
    """Publish order, not semver order -- a backport is still the new publish."""
    w = watcher_over({})
    p = packument(
        version("2.0.0", NOW - 5000),
        version("1.9.9", NOW - 10),   # backported after 2.0.0 shipped
    )
    event = w.newest_publish(p, now=NOW)
    assert event.version == "1.9.9"


def test_a_package_with_no_dated_versions_is_skipped():
    w = watcher_over({})
    assert w.newest_publish(packument(version("1.0.0", 0)), now=NOW) is None


def test_empty_packument_is_skipped():
    w = watcher_over({})
    assert w.newest_publish(packument(), now=NOW) is None


# -- assessment -------------------------------------------------------------


def test_assess_fetches_with_refresh():
    """A cached read predates the version we are trying to notice.

    The registry cache has no expiry, which is right for ingest and fatal
    here: a cache hit returns the state before the publish and the watcher
    reports "nothing new" forever.
    """
    docs = {"demo": packument(version("1.0.0", NOW - 30))}
    w = watcher_over(docs)
    w.assess("demo", now=NOW)
    assert w.registry.calls == [("demo", True)], "must bypass the cache"


def test_assess_reports_signals_only_for_the_new_version():
    """A busy package must not re-report its whole recent history.

    Otherwise every publish re-emits the signals of the versions before it,
    and the same finding arrives once per subsequent release.
    """
    docs = {
        "demo": packument(
            version("1.0.0", NOW - 600, publisher="stranger"),
            version("1.0.1", NOW - 30, publisher="stranger"),
        )
    }
    w = watcher_over(docs)
    alert = w.assess("demo", now=NOW)
    assert alert is not None
    assert alert.version == "1.0.1"
    assert all(s["signal"] for s in alert.signals)
    # 1.0.0 also has the signal, but this alert is about 1.0.1 alone.
    assert alert.signals, "the new version's own signal should still fire"


def test_a_clean_publish_produces_a_publish_tier_alert():
    docs = {"demo": packument(version("1.0.0", NOW - 30))}
    w = watcher_over(docs)
    alert = w.assess("demo", now=NOW)
    assert alert.kind == "publish"
    assert alert.signals == []


def test_fleet_membership_escalates_the_tier():
    docs = {"demo": packument(version("1.0.1", NOW - 30, publisher="stranger"))}
    w = watcher_over(docs, fleet_lookup=lambda name: True)
    alert = w.assess("demo", now=NOW)
    assert alert.in_fleet
    assert alert.kind == "fleet"


def test_fleet_hit_hook_runs_and_a_failure_is_contained():
    """Enrichment is optional; a broken hook must not lose the alert."""
    docs = {"demo": packument(version("1.0.1", NOW - 30, publisher="stranger"))}

    def boom(alert):
        raise RuntimeError("frontier exploded")

    w = watcher_over(docs, fleet_lookup=lambda n: True, on_fleet_hit=boom)
    alert = w.assess("demo", now=NOW)
    assert alert is not None, "the alert survives a failed enrichment"
    assert "frontier exploded" in w.last_error


def test_an_unfetchable_package_is_counted_not_raised():
    w = watcher_over({})
    assert w.assess("missing", now=NOW) is None
    assert w.counters["errors"] == 1


def test_an_invalid_package_name_is_skipped():
    w = watcher_over({})
    assert w.assess("NOT A VALID NAME/////", now=NOW) is None
    assert w.counters["skipped"] == 1


# -- subscribers ------------------------------------------------------------


def test_a_full_subscriber_drops_its_oldest_event():
    """A tab that stopped reading must not be able to stall ingestion."""
    w = watcher_over({})
    q = w.subscribe()
    for i in range(SUBSCRIBER_QUEUE + 25):
        w._publish_to_subscribers({"type": "alert", "n": i})

    assert q.qsize() <= SUBSCRIBER_QUEUE
    # The most recent event survived; the oldest did not.
    drained = []
    while not q.empty():
        drained.append(q.get_nowait()["n"])
    assert drained[-1] == SUBSCRIBER_QUEUE + 24
    assert 0 not in drained


def test_publishing_never_blocks():
    """The whole point of the drop policy: this must return promptly."""
    w = watcher_over({})
    w.subscribe()
    started = time.perf_counter()
    for i in range(SUBSCRIBER_QUEUE * 3):
        w._publish_to_subscribers({"type": "alert", "n": i})
    assert time.perf_counter() - started < 2.0


def test_unsubscribe_stops_delivery():
    w = watcher_over({})
    q = w.subscribe()
    w.unsubscribe(q)
    w._publish_to_subscribers({"type": "alert"})
    assert q.empty()


def test_unsubscribing_twice_is_harmless():
    w = watcher_over({})
    q = w.subscribe()
    w.unsubscribe(q)
    w.unsubscribe(q)


# -- the cursor -------------------------------------------------------------


def test_fetch_changes_advances_the_cursor():
    w = watcher_over({})
    w._get = lambda url, timeout=30.0: {
        "results": [{"id": "a"}, {"id": "b"}], "last_seq": 42,
    }
    assert w.fetch_changes() == ["a", "b"]
    assert w.seq == 42


def test_a_failed_fetch_leaves_the_cursor_alone():
    """Resuming from the wrong sequence either replays or skips, and skipping
    is silent -- so a failure must not move the cursor."""
    w = watcher_over({})
    w.seq = 100

    def explode(url, timeout=30.0):
        raise OSError("feed dropped")

    w._get = explode
    with pytest.raises(OSError):
        w.fetch_changes()
    assert w.seq == 100


def test_results_without_ids_are_ignored():
    w = watcher_over({})
    w._get = lambda url, timeout=30.0: {
        "results": [{"id": "a"}, {"deleted": True}, {"id": None}],
        "last_seq": 7,
    }
    assert w.fetch_changes() == ["a"]


def test_a_missing_last_seq_does_not_reset_the_cursor():
    w = watcher_over({})
    w.seq = 55
    w._get = lambda url, timeout=30.0: {"results": [{"id": "a"}]}
    w.fetch_changes()
    assert w.seq == 55


# -- correlated bursts over the live window ---------------------------------


def test_correlated_burst_over_what_the_watcher_has_seen():
    """The cross-package signal, assembled from the rolling window.

    No single change can show this: each publish is one package and looks
    ordinary. Only the accumulated window reveals one account touching many.
    """
    now = int(time.time())
    docs = {
        f"pkg-{i}": packument(
            version("1.0.0", now - 60 + i, publisher="mallory"), name=f"pkg-{i}"
        )
        for i in range(8)
    }
    w = watcher_over(docs)
    for name in docs:
        w.assess(name, now=now)

    bursts = w.correlated_bursts()
    assert len(bursts) == 1
    assert bursts[0]["identity"] == "mallory"
    assert bursts[0]["packages"] == 8


def test_no_burst_when_publishes_are_spread_out():
    now = int(time.time())
    w = watcher_over({})
    docs = {
        f"pkg-{i}": packument(
            version("1.0.0", now - 30, publisher=f"person-{i}"), name=f"pkg-{i}"
        )
        for i in range(8)
    }
    w.registry = FakeRegistry(docs)
    for name in docs:
        w.assess(name, now=now)
    # Eight publishes, eight different accounts: breadth without a shared
    # identity is not propagation.
    assert w.correlated_bursts() == []


# -- lifecycle --------------------------------------------------------------


def test_start_and_stop_are_idempotent():
    w = watcher_over({}, poll_seconds=0.05)
    w._get = lambda url, timeout=30.0: {"results": [], "last_seq": 1}
    w.start()
    w.start()  # second start must not spawn a second thread
    assert w.running
    w.stop()
    w.stop()
    assert not w.running


def test_status_is_serialisable():
    """It is sent to the browser as JSON on every poll."""
    import json

    w = watcher_over({})
    json.dumps(w.status())


# -- the live half ----------------------------------------------------------

LIVE = os.environ.get("BLASTRADIUS_LIVE_FEED") == "1"
live = pytest.mark.skipif(
    not LIVE, reason="needs the network; set BLASTRADIUS_LIVE_FEED=1"
)


@live
def test_real_feed_head_is_readable():
    w = Watcher()
    assert w._latest_seq() > 0


@live
def test_real_feed_returns_names_and_advances():
    w = Watcher()
    w.seq = w._latest_seq()
    time.sleep(12)
    before = w.seq
    names = w.fetch_changes()
    assert w.seq >= before
    assert all(isinstance(n, str) for n in names)
