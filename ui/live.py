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

import os
import re
import shutil
import subprocess
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Any

from blastradius import schema
from blastradius.chat.config import load_env
from blastradius.hydra_client import (
    DEFAULT_GRAPH,
    DEFAULT_HTTP,
    DEFAULT_NAMESPACE,
    DEFAULT_TOKEN,
    HydraClient,
)

# Loaded here rather than relying on `ui.server`, which calls it too. This
# module builds its client at import time (`state = LiveState()` at the foot of
# the file), and `ui/server.py` imports this module *above* its own `load_env()`
# call -- so by the time `LiveState.__init__` reads `os.environ`, nothing had
# read `.env` yet and every HYDRA_* here silently fell back to its localhost
# default. That is invisible in local dev, where the defaults happen to be
# right, and fatal in docker-compose, where `HYDRA_HTTP=http://hydradb:8443`
# lives only in the environment this never saw. `load_env` never overrides an
# already-set variable, so calling it from both places is safe and order does
# not matter.
load_env()

#: Ingest is slower against HydraDB's S3 backend than against local-filesystem
#: storage -- enough that the client's default 25s timeout is marginal there.
#:
#: This cannot simply be raised, though: HydraDB's admission control rejects a
#: request whose *declared* `timeout_ms` exceeds `client_query_runtime_ms`
#: (30s on this deployment) with a 429, before running anything. So a larger
#: number does not buy patience, it breaks every query outright. 29s sits just
#: under that ceiling, which is the most this knob can actually ask for.
#:
#: Raising the real ceiling is a server-side setting, not a client one. If
#: ingest still times out here, the fix is a smaller write batch (see
#: `HydraClient.batch`) so each individual query does less work -- not a
#: bigger number here.
_ADMISSION_CEILING_MS = 30_000
_INGEST_TIMEOUT_MS = min(
    int(os.environ.get("HYDRA_INGEST_TIMEOUT_MS", "29000")),
    _ADMISSION_CEILING_MS - 1_000,
)
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

#: Where a GitHub URL gets cloned to. Same directory the demo fixtures already
#: live in (corpus/fleet, corpus/GenReal.ai), so a cloned repo is scannable by
#: every code path that already knows how to point at a local checkout there.
CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"

#: `https://github.com/<owner>/<repo>`, optionally with `.git` and a trailing
#: slash. Deliberately narrow rather than "anything git can clone": the value
#: is passed to a subprocess argument list (never a shell), so there is no
#: injection risk from special characters, but a string starting with `-`
#: could still be read as a git flag, and only GitHub is what "enter a GitHub
#: link" means here -- an SSH remote or an arbitrary host would just fail
#: `git clone` with a confusing error instead of a clear rejection.
_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(\.git)?/?$"
)


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
    #: Where the finished graph was published, and why it was not.
    snapshot_uri: str = ""
    snapshot_error: str = ""

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
            "snapshot_uri": self.snapshot_uri,
            "snapshot_error": self.snapshot_error,
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
        # Mirrors the top-level `client` in ui/server.py -- unqualified
        # `HydraClient()` defaults to 127.0.0.1, which is only ever correct
        # for local dev. In docker-compose, this process and hydradb are
        # separate containers, and 127.0.0.1 here means "myself," not "the
        # sibling container" -- every ingest, watch and simulation call
        # through this class silently failed to connect there until this
        # read the same HYDRA_HTTP the rest of the app already does.
        self.client = HydraClient(
            base_url=os.environ.get("HYDRA_HTTP", DEFAULT_HTTP),
            token=os.environ.get("HYDRA_TOKEN", DEFAULT_TOKEN),
            namespace=os.environ.get("HYDRA_NAMESPACE", DEFAULT_NAMESPACE),
            graph=os.environ.get("HYDRA_GRAPH", DEFAULT_GRAPH),
            timeout_ms=_INGEST_TIMEOUT_MS,
        )
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
        from blastradius.ingest.ignore import IGNORE_FILE, is_ignored, load_ignores
        from blastradius.ingest.lockfile import find_lockfiles

        patterns = load_ignores(path)
        locks, ignored = find_lockfiles(path, with_skipped=True)
        sources = sum(
            1 for p in path.rglob("*")
            if p.suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs")
            and not is_ignored(p, path, patterns)
        )
        note = ""
        if not locks:
            note = (
                "No package-lock.json found. The package tier needs a resolved "
                "lockfile; run `npm install --package-lock-only` in the repo "
                "first, or pick a checkout that has one."
            )
            if ignored:
                # The difference between "this repo has none" and "this repo
                # told me to skip all of them" is the whole answer here.
                note = (
                    f"No usable package-lock.json: all {len(ignored)} found were "
                    f"excluded by {IGNORE_FILE}."
                )
        return {
            "path": str(path),
            "lockfiles": [str(p.relative_to(path)) for p in locks[:20]],
            "lockfile_count": len(locks),
            # Shown before the scan runs, so nobody is surprised by the count
            # afterwards and nobody has to guess why it is lower than `find`.
            "ignored": [str(p.relative_to(path)) for p in ignored[:20]],
            "ignored_count": len(ignored),
            "source_files": sources,
            "usable": bool(locks),
            "note": note,
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

    # -- github ---------------------------------------------------------

    @staticmethod
    def parse_github_url(raw: str) -> tuple[str, str]:
        """`https://github.com/owner/repo` -> `("owner", "repo")`, or raise."""
        text = (raw or "").strip()
        match = _GITHUB_URL_RE.match(text)
        if not match:
            raise ValueError(
                f"expected a GitHub URL like https://github.com/owner/repo, got {raw!r}"
            )
        return match.group(1), match.group(2)

    def start_ingest_from_github(self, url: str, reset: bool = False) -> IngestJob:
        """Clone a GitHub repository, then run the same pipeline as a local path.

        `reset` defaults to False here, unlike `start_ingest`'s default of True:
        the picker's whole point is that more than one repository's chatbot can
        exist at once (see `blastradius/chat/workspaces.py`), so adding a second
        repo must not erase the first one's services out from under its
        already-registered chatbot.
        """
        if self.job_running:
            raise RuntimeError("an ingest is already running")

        owner, name = self.parse_github_url(url)
        target = CORPUS_DIR / f"{owner}-{name}"

        job = IngestJob(repo=url, reset=reset, status="queued")
        with self._job_lock:
            self.job = job

        self._job_thread = threading.Thread(
            target=self._run_github_ingest, args=(job, url, target),
            name="ingest-job", daemon=True,
        )
        self._job_thread.start()
        return job

    def _clone(self, url: str, target: Path) -> None:
        """Fresh clone every time, rather than fetch-and-reset an existing one.

        A shallow clone is one `git` invocation with no branch-tracking edge
        cases to get wrong; re-running "Start" on the same repo just replaces
        it. The cost is a re-download on every re-ingest, which for a picker
        that is clicked rarely is cheaper than the failure modes of trying to
        keep a checkout in sync.
        """
        CORPUS_DIR.mkdir(parents=True, exist_ok=True)
        if target.exists():
            shutil.rmtree(target)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, str(target)],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "git clone failed").strip())

    def _run_github_ingest(self, job: IngestJob, url: str, target: Path) -> None:
        job.status = "running"
        job.started_at = time.time()
        self._emit_job()

        stage = Stage(name="clone")
        job.stages.append(stage)
        t0 = time.perf_counter()
        try:
            self._clone(url, target)
        except Exception as exc:  # noqa: BLE001 - surfaced to the browser
            stage.status = "failed"
            stage.seconds = time.perf_counter() - t0
            job.status = "failed"
            job.error = f"clone failed: {exc}"
            self._emit_job()
            return
        stage.status = "ok"
        stage.seconds = time.perf_counter() - t0

        described = self.describe_repo(target)
        if not described["usable"]:
            job.status = "failed"
            job.error = described["note"]
            self._emit_job()
            return

        # From here the job is indistinguishable from a local-path ingest --
        # `job.repo` now names the clone, which is what gets registered as the
        # chatbot's `repo_path` once the pipeline finishes.
        job.repo = str(target)
        self._emit_job()
        self._run_pipeline_stages(job)

    def _emit_job(self) -> None:
        if self.job is not None:
            self.bus.publish({"type": "ingest", "job": self.job.to_dict()})

    def _run_ingest(self, job: IngestJob) -> None:
        job.status = "running"
        job.started_at = time.time()
        self._emit_job()
        self._run_pipeline_stages(job)

    def _run_pipeline_stages(self, job: IngestJob) -> None:
        """Run the pipeline against `job.repo` -- a resolved local path.

        Shared by both entry points. By the time this runs, `job.repo` is
        always a local directory: `start_ingest` resolves it before creating
        the job, and `_run_github_ingest` overwrites the URL with the clone
        path once cloning succeeds.
        """
        from blastradius.pipeline import run_pipeline

        started = time.perf_counter()
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
                # The graph is built and local. Publishing it is the last
                # stage of the build rather than a thing somebody remembers
                # to do afterwards, and it appears in the stage list with its
                # own timing like every other stage.
                #
                # A failure here does not fail the build: the graph on this
                # machine is finished and correct, and the console should say
                # so even when the bucket is misconfigured. The error is
                # carried on the stage instead, where it names itself.
                self._publish_snapshot(job, on_stage)
                job.status = "done"
        except Exception as exc:  # noqa: BLE001 - surfaced to the browser
            close_current("failed")
            job.status = "failed"
            job.error = f"{type(exc).__name__}: {exc}"
            job.elapsed_s = time.perf_counter() - started
            traceback.print_exc()

        self._emit_job()

    def _publish_snapshot(self, job: IngestJob, on_stage) -> None:
        """Upload the finished graph, if a bucket has been configured."""
        from blastradius import snapshot

        cfg = snapshot.s3_config()
        if not cfg["auto"]:
            return

        on_stage("publish to s3")
        stage = job.stages[-1]
        started = time.perf_counter()
        try:
            uri = snapshot.publish(verbose=False)
            stage.status = "ok"
            stage.detail = uri
            job.snapshot_uri = uri
        except Exception as exc:  # noqa: BLE001 - reported, never fatal
            stage.status = "failed"
            stage.detail = str(exc)
            job.snapshot_error = str(exc)
        stage.seconds = time.perf_counter() - started
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

            # Two of the brief's six questions, and the simulation was
            # answering neither: it built a BlastRadius by hand rather than
            # calling engine.analyse(), so the relationship and typosquat
            # queries never ran. They are INVESTIGATE-grade by construction --
            # sharing a maintainer is not a compromise -- but the whole point
            # of the drill is "what else would you go and look at".
            stage("finding shared maintainers and infrastructure")
            package_id = engine.resolve_package(name)
            shared_maintainer = (
                engine.shared_maintainer(result, package_id)
                if package_id is not None else []
            )
            shared_repository = engine.shared_repository(result, version_id)
            shared_publisher = engine.shared_publisher(result, version_id)

            stage("looking for typosquat neighbours")
            typosquats = (
                engine.typosquats(result, package_id)
                if package_id is not None else []
            )

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
                # The routes, not just the count. "34 packages" is a number;
                # "these three accounts reach them, rotate those" is the
                # action, and the witness set is the only part that names
                # them.
                "frontier_detail": [
                    {
                        "package": t.package,
                        "routes": {r: sorted(w) for r, w in t.routes.items()},
                        "identities": sorted(t.identities),
                        "confidence": t.confidence,
                        "atoms": sorted(t.atoms),
                        "exposed_services": sorted(t.exposed_services),
                        "impact_measured": t.impact_measured,
                    }
                    for t in frontier.targets[:20]
                ],
                "frontier_identities": sorted(
                    {who for t in frontier.targets for who in t.identities}
                ),
                "shared_maintainer": shared_maintainer[:40],
                "shared_repository": shared_repository[:40],
                "shared_publisher": shared_publisher[:40],
                "typosquats": typosquats[:40],
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
