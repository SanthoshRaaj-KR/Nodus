"""Watch npm as it publishes, and decide what matters to this fleet.

Everything else in this project answers a question you already knew to ask: a
CVE lands, you look it up. That is the static half, and it starts the clock at
whatever moment somebody else noticed. The TanStack worm published 84 artifacts
in six minutes; the advisory that described it arrived considerably later than
that.

npm replicates its registry as a CouchDB change feed, and the feed is public:

    https://replicate.npmjs.com/_changes?since=<seq>

Every publish, deprecation and dist-tag move appears there within seconds, and
``seq`` is a resumable cursor -- so a watcher that records where it got to can
be restarted without either missing changes or replaying them. Measured here,
the whole registry runs at roughly **0.85 changes per second**, which is a
trivial volume to keep up with and the reason this can be a poll loop rather
than a pipeline.

**What this does with each change.** The feed gives a package *name*, not a
version, and fires for changes that are not publishes at all. So each name is
resolved to its packument and the newest version by publish time is compared
against a recency threshold: if it appeared in the last few minutes, it is a
publish and gets assessed by ``anomaly.analyse_package``. That costs one
registry fetch per change, which at this rate is comfortable.

**Two tiers of alert, because most of npm is not your problem.** An anomaly on
a package nobody in your fleet has installed is worth recording and not worth
waking anyone for. An anomaly on a package your services actually resolve is a
different event, and it is escalated with the blast radius already attached --
which services hold it, and what the publisher could reach next. Membership is
decided through the local id map, so it costs no graph query at all.

**Nothing here is a verdict.** The watcher emits the same INVESTIGATE-grade
evidence atoms the offline path does. It is an early-warning surface, not an
oracle, and a live feed does not make a weak signal strong.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass, field
from queue import Empty, Full, Queue
from typing import Any, Callable, Iterable

from .. import schema
from .anomaly import analyse_correlated_burst, analyse_package
from .identity import normalize_name, package_key
from .registry import PackumentSummary, RegistryClient, RegistryError

__all__ = [
    "CHANGES_URL",
    "PublishEvent",
    "Alert",
    "Watcher",
]

CHANGES_URL = "https://replicate.npmjs.com/_changes"

#: A version whose publish time is within this window of "now" is treated as a
#: new publish. The feed does not say what changed, only that something did, so
#: this is what separates a publish from a deprecation or a dist-tag move.
#: Generous enough to absorb clock skew and a slow first fetch.
FRESH_SECONDS = 15 * 60

#: Alerts kept in memory for late subscribers and the REST endpoint. The
#: watcher is a live surface, not a system of record -- anything that matters
#: is also written to the graph by an ingest.
ALERT_BUFFER = 500

#: Bound on each subscriber's queue. A browser that stops reading must not be
#: able to grow the server's memory without limit, so its queue drops the
#: oldest event rather than blocking the watcher thread.
SUBSCRIBER_QUEUE = 256


@dataclass
class PublishEvent:
    """One package version that appeared on the registry."""

    package: str
    version: str
    published_at: int
    seq: int = 0
    publisher: str = ""
    has_install_script: bool = False
    #: Carried so the rolling burst check can tell a monorepo release from an
    #: account reaching across unrelated projects. Without it every large
    #: release reads as propagation.
    repository: str = ""


@dataclass
class Alert:
    """One thing worth telling somebody about, with why."""

    package: str
    version: str
    published_at: int
    seen_at: int
    #: Evidence atoms from anomaly.analyse_package, already rendered.
    signals: list[dict] = field(default_factory=list)
    #: True when this package is in the ingested fleet.
    in_fleet: bool = False
    #: Services resolving it today, when known.
    fleet_services: list[str] = field(default_factory=list)
    #: Packages the publisher could reach next, when computed.
    frontier_packages: int = 0
    frontier_sample: list[str] = field(default_factory=list)
    seq: int = 0
    publisher: str = ""

    @property
    def kind(self) -> str:
        """`fleet` outranks `anomaly` outranks `publish`.

        Three tiers rather than a severity number: a publish is a fact, an
        anomaly is a lead, and a lead on a package you actually run is the only
        one of the three that should ever interrupt somebody.
        """
        if self.in_fleet and self.signals:
            return "fleet"
        if self.signals:
            return "anomaly"
        return "publish"

    def to_dict(self) -> dict:
        out = asdict(self)
        out["kind"] = self.kind
        return out


class Watcher:
    """Tails the npm change feed and emits alerts.

    Runs on its own thread. Start it, subscribe to it, stop it; the loop owns
    its cursor and survives feed errors by backing off and resuming from the
    last sequence it successfully processed.
    """

    def __init__(
        self,
        registry: RegistryClient | None = None,
        ids: Any = None,
        fleet_lookup: Callable[[str], bool] | None = None,
        on_fleet_hit: Callable[[Alert], None] | None = None,
        poll_seconds: float = 5.0,
        batch_limit: int = 200,
        changes_url: str = CHANGES_URL,
    ):
        self.registry = registry or RegistryClient()
        self.ids = ids
        #: Injected so the watcher can be tested without a graph, and so the
        #: membership test stays a local lookup rather than a query.
        self.fleet_lookup = fleet_lookup or self._default_fleet_lookup
        self.on_fleet_hit = on_fleet_hit
        self.poll_seconds = poll_seconds
        self.batch_limit = batch_limit
        self.changes_url = changes_url

        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._subscribers: list[Queue] = []

        self.alerts: deque[Alert] = deque(maxlen=ALERT_BUFFER)
        #: Recent publishes, kept so the cross-package burst check has a window
        #: to work over. Per-package checks need only one packument; the
        #: correlated one needs everything that happened lately.
        self._recent: deque[tuple[int, PublishEvent]] = deque(maxlen=2000)

        self.seq: int = 0
        self.started_at: int = 0
        self.counters: dict[str, int] = {
            "changes": 0, "publishes": 0, "alerts": 0,
            "fleet_hits": 0, "errors": 0, "skipped": 0,
        }
        self.last_error: str = ""

    # -- lifecycle ---------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self.started_at = int(time.time())
        if not self.seq:
            self.seq = self._latest_seq()
        self._thread = threading.Thread(
            target=self._loop, name="npm-watcher", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
        self._thread = None

    def status(self) -> dict:
        return {
            "running": self.running,
            "seq": self.seq,
            "started_at": self.started_at,
            "uptime_seconds": (
                int(time.time()) - self.started_at if self.started_at else 0
            ),
            "counters": dict(self.counters),
            "last_error": self.last_error,
            "buffered_alerts": len(self.alerts),
            "subscribers": len(self._subscribers),
        }

    # -- subscriptions -----------------------------------------------------

    def subscribe(self) -> Queue:
        q: Queue = Queue(maxsize=SUBSCRIBER_QUEUE)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _publish_to_subscribers(self, payload: dict) -> None:
        with self._lock:
            targets = list(self._subscribers)
        for q in targets:
            try:
                q.put_nowait(payload)
            except Full:
                # A subscriber that stopped reading loses its oldest event
                # rather than stalling the watcher or growing without bound.
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                except (Empty, Full):
                    pass

    # -- the feed ----------------------------------------------------------

    def _get(self, url: str, timeout: float = 30.0) -> dict:
        request = urllib.request.Request(
            url, headers={"User-Agent": "blast-radius-watcher/1.0"}
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def _latest_seq(self) -> int:
        """Where the feed is right now, so a fresh start does not replay history."""
        try:
            payload = self._get(
                f"{self.changes_url}?limit=1&descending=true", timeout=20
            )
            return int(payload.get("last_seq") or 0)
        except (urllib.error.URLError, OSError, ValueError, TypeError) as exc:
            self.last_error = f"could not read feed head: {exc}"
            self.counters["errors"] += 1
            return 0

    def fetch_changes(self) -> list[str]:
        """Package names changed since the cursor, advancing it."""
        url = (
            f"{self.changes_url}?since={self.seq}&limit={self.batch_limit}"
        )
        payload = self._get(url)
        results = payload.get("results") or []
        names = [r.get("id") for r in results if r.get("id")]
        last = payload.get("last_seq")
        if last is not None:
            try:
                self.seq = int(last)
            except (TypeError, ValueError):
                pass
        self.counters["changes"] += len(names)
        return [n for n in names if isinstance(n, str)]

    # -- assessment --------------------------------------------------------

    def _default_fleet_lookup(self, name: str) -> bool:
        """Is this package in the ingested fleet? Local id map, no graph hit."""
        if self.ids is None:
            return False
        try:
            return self.ids.lookup(schema.PACKAGE, package_key(name)) is not None
        except Exception:  # noqa: BLE001 - registry names are not ours
            return False

    def newest_publish(
        self, packument: PackumentSummary, now: int | None = None
    ) -> PublishEvent | None:
        """The newest version, if it is new enough to be this change.

        The feed says a document changed, not what changed -- a deprecation and
        a publish look identical from there. Comparing the newest version's
        publish time against a short window is what separates them, and it is
        why the packument has to be fetched with ``refresh=True``: a cached
        copy predates the very version we are trying to notice.
        """
        now = int(now if now is not None else time.time())
        dated = [v for v in packument.versions.values() if v.published_at > 0]
        if not dated:
            return None
        newest = max(dated, key=lambda v: v.published_at)
        if now - newest.published_at > FRESH_SECONDS:
            return None
        return PublishEvent(
            package=packument.name,
            version=newest.version,
            published_at=newest.published_at,
            publisher=newest.publisher,
            has_install_script=newest.has_install_script,
            repository=newest.repository or packument.repository or "",
        )

    def assess(self, name: str, now: int | None = None) -> Alert | None:
        """Fetch, decide whether it is a publish, and grade it."""
        try:
            canonical = normalize_name(name)
        except Exception:  # noqa: BLE001
            self.counters["skipped"] += 1
            return None

        try:
            packument = self.registry.packument(
                canonical, full=True, refresh=True
            )
        except RegistryError as exc:
            self.counters["errors"] += 1
            self.last_error = f"{canonical}: {exc}"
            return None

        event = self.newest_publish(packument, now=now)
        if event is None:
            self.counters["skipped"] += 1
            return None

        event.seq = self.seq
        self.counters["publishes"] += 1
        self._recent.append((event.published_at, event))

        # Only the version that just appeared is interesting; the horizon in
        # analyse_package already bounds this, but scoping by version keeps a
        # busy package from re-reporting its whole recent history every time it
        # publishes again.
        signals = [
            s for s in analyse_package(packument, now=now)
            if s.version == event.version
        ]

        alert = Alert(
            package=event.package,
            version=event.version,
            published_at=event.published_at,
            seen_at=int(time.time()),
            signals=[
                {
                    "signal": s.signal,
                    "detail": s.detail,
                    "witness": s.witness,
                }
                for s in signals
            ],
            in_fleet=self.fleet_lookup(canonical),
            seq=event.seq,
            publisher=event.publisher,
        )

        if alert.in_fleet:
            self.counters["fleet_hits"] += 1
            if self.on_fleet_hit is not None:
                try:
                    self.on_fleet_hit(alert)
                except Exception as exc:  # noqa: BLE001 - enrichment is optional
                    self.last_error = f"fleet enrichment failed: {exc}"

        return alert

    def correlated_bursts(self, window_seconds: int = 15 * 60) -> list[dict]:
        """Cross-package bursts over what the watcher has seen so far.

        The per-change path cannot see this: each publish is one package and
        looks ordinary. Only the accumulated window shows one account touching
        many packages at once, which is the shape the worm had.
        """
        now = int(time.time())
        by_package: dict[str, PackumentSummary] = {}
        for at, event in self._recent:
            if now - at > window_seconds:
                continue
            summary = by_package.setdefault(
                event.package,
                PackumentSummary(
                    name=event.package, abbreviated_only=False,
                    repository=event.repository,
                ),
            )
            from .registry import VersionSummary

            summary.versions[event.version] = VersionSummary(
                name=event.package, version=event.version,
                published_at=event.published_at, publisher=event.publisher,
                repository=event.repository,
            )
        bursts = analyse_correlated_burst(
            list(by_package.values()), window_seconds=window_seconds, now=now
        )
        return [
            {
                "identity": b.identity,
                "packages": b.package_count,
                "artifacts": b.artifact_count,
                "span_seconds": b.span_seconds,
                "sample": sorted(b.packages)[:10],
                "cohesive": b.cohesive,
                "verdict": b.verdict,
                "scopes": len(b.scopes),
                "repositories": len(b.repositories),
                "explain": b.explain(),
            }
            for b in bursts
        ]

    def record(self, alert: Alert) -> None:
        """Buffer an alert and push it to every subscriber."""
        self.alerts.append(alert)
        self.counters["alerts"] += 1
        self._publish_to_subscribers({"type": "alert", "alert": alert.to_dict()})

    # -- the loop ----------------------------------------------------------

    def _loop(self) -> None:
        backoff = self.poll_seconds
        while not self._stop.is_set():
            try:
                names = self.fetch_changes()
                backoff = self.poll_seconds
            except (urllib.error.URLError, OSError, ValueError) as exc:
                # The feed is a public CDN and drops connections. Back off
                # rather than spinning, and keep the cursor: the next successful
                # read resumes exactly where this one failed.
                self.counters["errors"] += 1
                self.last_error = f"feed: {exc}"
                self._publish_to_subscribers(
                    {"type": "status", "status": self.status()}
                )
                self._stop.wait(min(backoff, 60))
                backoff = min(backoff * 2, 60)
                continue

            for name in names:
                if self._stop.is_set():
                    break
                alert = self.assess(name)
                if alert is not None:
                    self.record(alert)

            self._publish_to_subscribers(
                {"type": "status", "status": self.status()}
            )
            self._stop.wait(self.poll_seconds)


def iter_subscriber(q: Queue, stop: threading.Event, heartbeat: float = 15.0
                    ) -> Iterable[dict]:
    """Yield events for one subscriber, with a heartbeat.

    The heartbeat exists for the transport rather than the data: an SSE
    connection through a proxy that sees no bytes for a minute is liable to be
    closed as idle, and the registry is quiet enough for that to happen often.
    """
    while not stop.is_set():
        try:
            yield q.get(timeout=heartbeat)
        except Empty:
            yield {"type": "heartbeat", "at": int(time.time())}
