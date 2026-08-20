"""Live state for the console: the watcher, ingest jobs, and simulations.

`ui/server.py` is a request handler; this is the part that outlives a request.
Three things live here, and they are together because they share one event bus
and the browser consumes them through one stream:

**The watcher.** One process-wide `Watcher`, started and stopped from the UI.
Its fleet-hit hook is wired up here rather than inside the watcher, because
deciding *what a fleet hit means* needs the graph -- which services hold the
package, and what the publisher could reach next -- and the watcher itself is
deliberately ignorant of both so it can be tested without either.

**Ingest jobs.** Pointing the console at a repository runs the full pipeline,
which takes tens of seconds and cannot happen inside a request. It runs on a
thread and reports stage by stage, so the UI shows progress rather than a
spinner that might mean anything.

**Simulations.** Marking a package compromised, running every question the
engine can answer about it, and putting it back. Also threaded, also staged,
for the same reason.

Everything publishes to one bus and the browser subscribes once. A single
stream keeps ordering intact: an alert that arrives during an ingest really did
arrive then, and two sockets would leave that to chance.
"""

from __future__ import annotations

import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Any

from blastradius import schema
from blastradius.hydra_client import HydraClient
from blastradius.ids import IdAllocator
from blastradius.pkg.identity import package_key, version_key
from blastradius.pkg.registry import RegistryClient
from blastradius.pkg.watcher import Watcher

__all__ = ["LiveState", "IngestJob", "state"]

#: Bound per browser connection. A tab that stops reading drops its oldest
#: event rather than growing the server's memory or blocking a producer.
SUBSCRIBER_QUEUE = 512

#: Directories a repository path may never resolve inside. The console binds
#: to localhost and is a developer tool, not a service, but "type a path and
#: we will walk it" still deserves a floor: these hold nothing a dependency
#: scan wants and everything an accident would regret.
FORBIDDEN_ROOTS = ("/etc", "/sys", "/proc", "/dev", "/var/root", "/private/etc")


def _split(spec: str) -> tuple[str, str]:
    """``lodash@4.17.21`` -> ("lodash", "4.17.21"); a scope keeps its @."""
    text = (spec or "").strip()
    if "@" not in text.lstrip("@"):
        raise ValueError(f"expected name@version, got {spec!r}")
    at = text.rindex("@")
    if at == 0:
        raise ValueError(f"expected name@version, got {spec!r}")
    return text[:at], text[at + 1 :]


class Bus:
    """Fan-out to every connected browser. Never blocks a producer."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._subscribers: list[Queue] = []

    def subscribe(self) -> Queue:
        q: Queue = Queue(maxsize=SUBSCRIBER_QUEUE)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, payload: dict) -> None:
        with self._lock:
            targets = list(self._subscribers)
        for q in targets:
            try:
                q.put_nowait(payload)
            except Full:
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                except (Empty, Full):
                    pass

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._subscribers)


@dataclass
class Stage:
    name: str
    status: str = "running"      # running | ok | failed
    seconds: float = 0.0
    detail: str = ""


@dataclass
class IngestJob:
    """One pipeline run against one repository."""

    repo: str
    reset: bool = False
    status: str = "queued"       # queued | running | done | failed
    stages: list[Stage] = field(default_factory=list)
    error: str = ""
    started_at: float = 0.0
    elapsed_s: float = 0.0
    counts: dict[str, int] = field(default_factory=dict)
    advisories: int = 0
    services: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "repo": self.repo,
            "reset": self.reset,
            "status": self.status,
            "error": self.error,
            "started_at": self.started_at,
            "elapsed_s": round(self.elapsed_s, 2),
            "counts": self.counts,
            "advisories": self.advisories,
            "services": self.services,
            "stages": [
                {
                    "name": s.name, "status": s.status,
                    "seconds": round(s.seconds, 2), "detail": s.detail,
                }
                for s in self.stages
            ],
        }


class LiveState:
    """Process-wide singleton holding everything that outlives a request."""

    def __init__(self) -> None:
        self.bus = Bus()
        self.client = HydraClient()
        self.ids = IdAllocator()
        self.registry = RegistryClient()

        self.watcher = Watcher(
            registry=self.registry,
            ids=self.ids,
            on_fleet_hit=self._enrich_fleet_hit,
        )
        # The watcher's own fan-out feeds the shared bus, so the browser has
        # one stream to read rather than one per producer.
        self._watch_pump: threading.Thread | None = None
        self._pump_stop = threading.Event()

        self.job: IngestJob | None = None
        self._job_thread: threading.Thread | None = None
        self._job_lock = threading.RLock()

        self.simulation: dict | None = None
        self._sim_thread: threading.Thread | None = None

    # -- repository validation --------------------------------------------

    @staticmethod
    def resolve_repo(raw: str) -> Path:
        """Turn user input into a directory we are willing to scan.

        Every rejection names what was wrong and what was tried, because the
        single most common failure here is a path that is *nearly* right and a
        message that does not say so.
        """
        text = (raw or "").strip().strip('"').strip("'")
        if not text:
            raise ValueError("no path given")

        path = Path(text).expanduser()
        try:
            path = path.resolve()
        except OSError as exc:
            raise ValueError(f"could not resolve {text!r}: {exc}") from None

        as_posix = path.as_posix()
        for root in FORBIDDEN_ROOTS:
            if as_posix == root or as_posix.startswith(root + "/"):
                raise ValueError(f"refusing to scan a system directory: {path}")

        if not path.exists():
            raise ValueError(f"no such directory: {path}")
        if not path.is_dir():
            raise ValueError(f"not a directory: {path}")

        return path

    @staticmethod
    def describe_repo(path: Path) -> dict:
        """What a scan would find here, before committing to running one."""
        from blastradius.ingest.lockfile import find_lockfiles

        locks = find_lockfiles(path)
        sources = sum(
            1 for p in path.rglob("*")
            if p.suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs")
            and "node_modules" not in p.parts
        )
        return {
            "path": str(path),
            "lockfiles": [str(p.relative_to(path)) for p in locks[:20]],
            "lockfile_count": len(locks),
            "source_files": sources,
            "usable": bool(locks),
            "note": (
                "" if locks else
                "No package-lock.json found. The package tier needs a resolved "
                "lockfile; run `npm install --package-lock-only` in the repo "
                "first, or pick a checkout that has one."
            ),
        }

    # -- ingest ------------------------------------------------------------

    @property
    def job_running(self) -> bool:
        return self._job_thread is not None and self._job_thread.is_alive()

    def start_ingest(self, raw_path: str, reset: bool = True) -> IngestJob:
        """Validate, then run the pipeline on a thread."""
        if self.job_running:
            raise RuntimeError("an ingest is already running")

        repo = self.resolve_repo(raw_path)
        described = self.describe_repo(repo)
        if not described["usable"]:
            raise ValueError(described["note"])

        job = IngestJob(repo=str(repo), reset=reset, status="queued")
        with self._job_lock:
            self.job = job

        self._job_thread = threading.Thread(
            target=self._run_ingest, args=(job,), name="ingest-job", daemon=True
        )
        self._job_thread.start()
        return job

    def _emit_job(self) -> None:
        if self.job is not None:
            self.bus.publish({"type": "ingest", "job": self.job.to_dict()})

    def _run_ingest(self, job: IngestJob) -> None:
        from blastradius.pipeline import run_pipeline

        job.status = "running"
        job.started_at = time.time()
        started = time.perf_counter()
        self._emit_job()

        current: dict[str, Any] = {"stage": None, "at": 0.0}

        def close_current(status: str = "ok") -> None:
            stage = current.get("stage")
            if stage is not None:
                stage.status = status
                stage.seconds = time.perf_counter() - current["at"]

        def on_stage(name: str) -> None:
            close_current("ok")
            stage = Stage(name=name)
            job.stages.append(stage)
            current["stage"] = stage
            current["at"] = time.perf_counter()
            job.elapsed_s = time.perf_counter() - started
            self._emit_job()

        try:
            report = run_pipeline(
                job.repo,
                client=self.client,
                reset=job.reset,
                verbose=False,
                on_stage=on_stage,
            )
            close_current("ok")

            job.counts = dict(report.counts or {})
            job.advisories = report.affects
            job.elapsed_s = time.perf_counter() - started

            # The id map is reopened because `reset` deletes the file this
            # process was holding: keeping the old handle would leave every
            # later lookup reading a database that no longer exists on disk,
            # which fails as "no rows" rather than as an error.
            self._reopen_ids()
            job.services = self._service_names()

            if report.failures:
                job.status = "failed"
                job.error = "; ".join(
                    f"{k}: {v}" for k, v in report.failures.items()
                )
            else:
                job.status = "done"
        except Exception as exc:  # noqa: BLE001 - surfaced to the browser
            close_current("failed")
            job.status = "failed"
            job.error = f"{type(exc).__name__}: {exc}"
            job.elapsed_s = time.perf_counter() - started
            traceback.print_exc()

        self._emit_job()

    def _reopen_ids(self) -> None:
        try:
            self.ids.close()
        except Exception:  # noqa: BLE001
            pass
        self.ids = IdAllocator()
        self.watcher.ids = self.ids

    def _service_names(self) -> list[str]:
        try:
            rows = self.client.query(
                f"MATCH (s:{schema.SERVICE}) RETURN s.name AS name ORDER BY name"
            )
            return [r["name"] for r in rows if r.get("name")]
        except Exception:  # noqa: BLE001
            return []

    # -- watcher -----------------------------------------------------------

    def start_watcher(self) -> dict:
        self.watcher.start()
        self._start_pump()
        return self.watcher.status()

    def stop_watcher(self) -> dict:
        self.watcher.stop()
        self._pump_stop.set()
        return self.watcher.status()

    def _start_pump(self) -> None:
        """Forward the watcher's own queue onto the shared bus."""
        if self._watch_pump is not None and self._watch_pump.is_alive():
            return
        self._pump_stop.clear()
        q = self.watcher.subscribe()

        def pump() -> None:
            while not self._pump_stop.is_set():
                try:
                    self.bus.publish(q.get(timeout=1.0))
                except Empty:
                    continue

        self._watch_pump = threading.Thread(
            target=pump, name="watch-pump", daemon=True
        )
        self._watch_pump.start()

    def _enrich_fleet_hit(self, alert) -> None:
        """Attach blast radius to an alert about a package we actually run.

        Only for fleet hits. Doing it for every publish would put two graph
        queries on the critical path of a feed that never stops, to answer a
        question about packages nobody here has installed.
        """
        from blastradius.pkg.blast import BlastRadius
        from blastradius.pkg.frontier import FrontierEngine

        package_id = self.ids.lookup(schema.PACKAGE, package_key(alert.package))
        if package_id is None:
            return

        engine = FrontierEngine(self.client, self.ids)
        result = BlastRadius(target=f"{alert.package}@{alert.version}")

        alert.fleet_services = sorted(engine.fleet_impact(result, package_id))

        version_id = self.ids.lookup(
            schema.PACKAGE_VERSION, version_key(alert.package, alert.version)
        )
        if version_id is not None:
            frontier = engine.analyse(
                alert.package, alert.version, result=result,
                measure_impact=False,
            )
            alert.frontier_packages = frontier.reachable_packages
            alert.frontier_sample = [t.package for t in frontier.targets[:8]]

    # -- simulation --------------------------------------------------------

    @property
    def sim_running(self) -> bool:
        return self._sim_thread is not None and self._sim_thread.is_alive()

    def start_simulation(self, spec: str) -> dict:
        """Mark a package compromised and answer everything about it.

        Threaded and staged for the same reason the ingest is: it runs several
        graph queries and the browser should watch it happen rather than wait
        on one response that either arrives or does not.
        """
        if self.sim_running:
            raise RuntimeError("a simulation is already running")

        name, version = _split(spec)
        version_id = self.ids.lookup(
            schema.PACKAGE_VERSION, version_key(name, version)
        )
        if version_id is None:
            raise ValueError(
                f"{name}@{version} is not in the graph. Ingest a repository "
                f"that resolves it, or pick one of the suggested targets."
            )

        self.simulation = {
            "spec": f"{name}@{version}", "status": "running",
            "stage": "marking the version compromised", "result": {}, "error": "",
        }
        self._emit_sim()
        self._sim_thread = threading.Thread(
            target=self._run_simulation, args=(name, version, version_id),
            name="simulation", daemon=True,
        )
        self._sim_thread.start()
        return self.simulation

    def _emit_sim(self) -> None:
        """Publish a *snapshot*, never the live dict.

        The bus hands each subscriber whatever object it was given, and the SSE
        generator serialises it later -- so publishing the mutable dict means
        every frame is serialised from the state the simulation reached by the
        time the browser drained its queue. Six stage updates all arrived
        reading "done", which looked like the stages were not being emitted at
        all rather than like an aliasing bug.
        """
        self.bus.publish({
            "type": "simulation",
            "simulation": dict(self.simulation) if self.simulation else None,
        })

    def _run_simulation(self, name: str, version: str, version_id: int) -> None:
        from blastradius.pkg.blast import BlastRadius, BlastRadiusEngine
        from blastradius.pkg.frontier import FrontierEngine
        from blastradius.pkg.incident import create_incident, incident_id_for

        def stage(text: str) -> None:
            self.simulation["stage"] = text
            self._emit_sim()

        try:
            # Named explicitly, and it has to match what `clear_simulation`
            # looks up or Reset retracts nothing. Both now default to the same
            # per-version id, but naming it here keeps the pairing visible at
            # the call site rather than resting on two defaults agreeing.
            create_incident(
                self.client, self.ids, name, version,
                incident_id=incident_id_for(name, version),
            )

            engine = BlastRadiusEngine(self.client, self.ids)
            result = BlastRadius(target=f"{name}@{version}", target_id=version_id)

            stage("finding projects that resolved it")
            exposed = engine.exposed_projects(result, version_id)

            stage("finding versions whose range admits it")
            direct = engine.direct_dependents(result, version_id)

            stage("projecting the publish frontier")
            frontier = FrontierEngine(self.client, self.ids).analyse(
                name, version, result=result, measure_impact=False
            )

            stage("collecting advisories")
            advisories = engine.advisories_for(result, version_id)

            # Node ids the browser should light up: the compromised version,
            # every service it reaches, and every package on the frontier.
            hot: list[int] = [version_id]
            for row in exposed:
                if row.get("id") is not None:
                    hot.append(row["id"])
            for target in frontier.targets:
                if target.package_id:
                    hot.append(target.package_id)

            self.simulation["result"] = {
                "exposed_services": [r["service"] for r in exposed],
                "exposed_detail": exposed,
                "range_only": len(direct),
                "frontier_packages": frontier.reachable_packages,
                "frontier_sample": [t.package for t in frontier.targets[:12]],
                "advisories": advisories,
                "hot_nodes": hot,
                "timings": [
                    {"label": t.label, "ms": round(t.ms, 2), "rows": t.rows}
                    for t in result.timings
                ],
            }
            self.simulation["status"] = "done"
            self.simulation["stage"] = ""
        except Exception as exc:  # noqa: BLE001 - surfaced to the browser
            self.simulation["status"] = "failed"
            self.simulation["error"] = f"{type(exc).__name__}: {exc}"
            traceback.print_exc()
        self._emit_sim()

    def clear_simulation(self, spec: str) -> bool:
        """Retract the synthetic incident. The graph goes back as it was."""
        from blastradius.pkg.incident import clear_incident

        name, version = _split(spec)
        removed = clear_incident(self.client, self.ids, name, version)
        self.simulation = None
        self.bus.publish({"type": "simulation", "simulation": None})
        return removed

    # -- snapshot ----------------------------------------------------------

    def snapshot(self) -> dict:
        """Everything a freshly connected browser needs to render at once."""
        return {
            "watcher": self.watcher.status(),
            "job": self.job.to_dict() if self.job else None,
            "alerts": [a.to_dict() for a in list(self.watcher.alerts)[-100:]],
            "bursts": self.watcher.correlated_bursts(),
            "simulation": self.simulation,
            "subscribers": self.bus.count,
        }


#: The one instance the server routes talk to.
state = LiveState()
