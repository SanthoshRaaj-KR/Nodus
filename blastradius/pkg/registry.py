"""npm registry client: dependency metadata, maintainers, publish times.

Three endpoints, chosen so that the expensive one is used least.

``GET /{name}`` with ``Accept: application/vnd.npm.install-v1+json``
    The *abbreviated* packument. Carries every version with its dependency
    ranges, dist integrity and ``hasInstallScript``, and nothing else. This
    builds the dependency graph, and it is 3-4x smaller than the full document
    (69 KB vs 248 KB for lodash), which matters when the crawl is thousands of
    packages wide.

``GET /{name}``
    The *full* packument. The only source for ``maintainers``, ``repository``,
    per-version ``_npmUser`` and the ``time`` map that gives each version its
    publication date. Fetched only for packages where those are actually
    needed, because it is the expensive one.

``GET /-/v1/search?text=maintainer:{user}``
    Reverse lookup: the packages an account maintains. This is what makes the
    shared-maintainer question cheap. Answering "what else does lodash's
    maintainer publish" by fetching every packument in the ecosystem and
    filtering would be absurd; here it is one paged request per account.

Everything is cached on disk and safe to re-run: the cache key is the URL, and
a cached body is reused until it is explicitly refreshed. Nothing about a
published version changes, so a stale read is not a correctness risk for
dependency data.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .identity import normalize_name, normalize_repo_url

__all__ = ["RegistryClient", "RegistryError", "PackumentSummary", "VersionSummary"]

REGISTRY = "https://registry.npmjs.org"
ABBREVIATED = "application/vnd.npm.install-v1+json"
DEFAULT_CACHE = Path(__file__).resolve().parents[2] / "data" / "registry-cache"

#: npm publishes these keys per version; each maps to a dependency kind we
#: keep distinct, because "a dev dependency of a library" is not a production
#: exposure and conflating them inflates every result.
DEP_FIELDS = {
    "dependencies": "prod",
    "devDependencies": "dev",
    "optionalDependencies": "optional",
    "peerDependencies": "peer",
}


class RegistryError(RuntimeError):
    """A registry request failed in a way the caller should see."""


@dataclass
class VersionSummary:
    """One published version, reduced to what the graph stores."""

    name: str
    version: str
    #: (package name, range, dep_type, optional, peer, bundled)
    dependencies: list[tuple[str, str, str, bool, bool, bool]] = field(
        default_factory=list
    )
    integrity: str = ""
    has_install_script: bool = False
    published_at: int = 0
    license: str = ""
    description: str = ""
    repository: str = ""
    publisher: str = ""
    publisher_email: str = ""
    deprecated: bool = False


@dataclass
class PackumentSummary:
    """One package, reduced to what the graph stores."""

    name: str
    versions: dict[str, VersionSummary] = field(default_factory=dict)
    latest: str = ""
    maintainers: list[tuple[str, str]] = field(default_factory=list)  # (user, email)
    repository: str = ""
    downloads: int = 0
    deprecated: bool = False
    #: True when only the abbreviated document was read, so maintainer /
    #: repository / publish-time fields are unknown rather than absent.
    abbreviated_only: bool = True

    @property
    def version_count(self) -> int:
        return len(self.versions)


class RegistryClient:
    """Cached, concurrent reader for the npm registry."""

    def __init__(
        self,
        cache_dir: Path | str = DEFAULT_CACHE,
        timeout: float = 30.0,
        concurrency: int = 12,
        user_agent: str = "blast-radius-graph/2.0 (supply-chain research)",
        offline: bool = False,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        #: The registry is a CDN and tolerates parallel reads; the work is
        #: entirely network-bound, so threads are the right tool despite the
        #: GIL. Kept modest to stay a well-behaved client.
        self.concurrency = max(1, concurrency)
        self.user_agent = user_agent
        #: When true, only the cache is consulted. Makes an ingest reproducible
        #: and lets the test suite run without a network.
        self.offline = offline
        self.stats = {"hits": 0, "misses": 0, "errors": 0, "bytes": 0}
        self._lock = threading.Lock()

    # -- transport ---------------------------------------------------------

    def _cache_path(self, url: str, accept: str) -> Path:
        digest = hashlib.sha256(f"{accept}|{url}".encode()).hexdigest()[:32]
        return self.cache_dir / f"{digest}.json.gz"

    def _get_json(
        self, url: str, accept: str | None = None, refresh: bool = False
    ) -> Any:
        """Fetch a document, preferring the cache unless ``refresh`` is set.

        The cache has no expiry, and for the ingest that is correct: a
        *published version* is immutable, so a stale read cannot be wrong about
        one. It is emphatically not correct for the live watcher, whose entire
        job is to notice a version that did not exist when the document was
        cached -- there, a cache hit returns the past and reports "nothing new"
        forever. ``refresh`` skips the read and still writes, so the watcher
        stays current while every later reader gets the fresh copy.
        """
        path = self._cache_path(url, accept or "")
        if path.exists() and not refresh:
            with self._lock:
                self.stats["hits"] += 1
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                return json.load(handle)

        if self.offline:
            if path.exists():
                # Offline plus refresh is not an error: the caller asked for
                # fresh data and we have stale data, which beats nothing.
                with gzip.open(path, "rt", encoding="utf-8") as handle:
                    return json.load(handle)
            raise RegistryError(f"offline and not cached: {url}")

        headers = {"User-Agent": self.user_agent, "Accept-Encoding": "gzip"}
        if accept:
            headers["Accept"] = accept

        last: Exception | None = None
        for attempt in range(3):
            try:
                request = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read()
                    if response.headers.get("Content-Encoding") == "gzip":
                        raw = gzip.decompress(raw)
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    raise RegistryError(f"not found: {url}") from None
                # 429 and 5xx are worth another try; the registry is a CDN and
                # transient failures are common at this concurrency.
                last = exc
                if exc.code not in (429, 500, 502, 503, 504):
                    raise RegistryError(f"HTTP {exc.code} for {url}") from None
                time.sleep(0.5 * (2**attempt))
            except (urllib.error.URLError, TimeoutError) as exc:
                last = exc
                time.sleep(0.5 * (2**attempt))
        else:
            with self._lock:
                self.stats["errors"] += 1
            raise RegistryError(f"giving up on {url}: {last}")

        with self._lock:
            self.stats["misses"] += 1
            self.stats["bytes"] += len(raw)

        payload = json.loads(raw.decode("utf-8"))
        tmp = path.with_suffix(".tmp")
        with gzip.open(tmp, "wt", encoding="utf-8") as handle:
            json.dump(payload, handle)
        tmp.replace(path)  # atomic, so a killed run never leaves a torn cache
        return payload

    # -- packuments --------------------------------------------------------

    def packument(
        self, name: str, full: bool = False, refresh: bool = False
    ) -> PackumentSummary:
        """Fetch and reduce one package document.

        ``full=False`` reads the abbreviated document, which is enough for the
        dependency graph. ``full=True`` additionally yields maintainers, the
        repository, per-version publishers and publication times. ``refresh``
        bypasses the cache read -- required by anything watching for versions
        that did not exist when the document was last cached.
        """
        canonical = normalize_name(name)
        url = f"{REGISTRY}/{urllib.parse.quote(canonical, safe='@')}"
        raw = self._get_json(url, None if full else ABBREVIATED, refresh=refresh)
        return self._reduce(canonical, raw, full)

    def _reduce(self, name: str, raw: dict, full: bool) -> PackumentSummary:
        out = PackumentSummary(name=name, abbreviated_only=not full)
        out.latest = (raw.get("dist-tags") or {}).get("latest", "")
        times = raw.get("time") or {}

        if full:
            for entry in raw.get("maintainers") or []:
                if isinstance(entry, dict) and entry.get("name"):
                    out.maintainers.append((entry["name"], entry.get("email", "")))
                elif isinstance(entry, str):
                    out.maintainers.append((entry, ""))
            repo = raw.get("repository")
            if isinstance(repo, dict):
                out.repository = repo.get("url", "") or ""
            elif isinstance(repo, str):
                out.repository = repo
            # A packument-level `deprecated` is rare; per-version is the norm.
            out.deprecated = bool(raw.get("deprecated"))

        for version, doc in (raw.get("versions") or {}).items():
            if not isinstance(doc, dict):
                continue
            summary = VersionSummary(name=name, version=version)
            summary.integrity = (doc.get("dist") or {}).get("integrity", "") or ""
            summary.has_install_script = bool(doc.get("hasInstallScript"))
            summary.deprecated = bool(doc.get("deprecated"))

            for field_name, dep_type in DEP_FIELDS.items():
                bundled = set(
                    doc.get("bundleDependencies")
                    or doc.get("bundledDependencies")
                    or []
                )
                for dep_name, dep_range in (doc.get(field_name) or {}).items():
                    summary.dependencies.append((
                        dep_name,
                        dep_range or "*",
                        dep_type,
                        dep_type == "optional",
                        dep_type == "peer",
                        dep_name in bundled,
                    ))

            if full:
                summary.license = _license_of(doc)
                summary.description = (doc.get("description") or "")[:160]
                repo = doc.get("repository")
                if isinstance(repo, dict):
                    summary.repository = repo.get("url", "") or ""
                elif isinstance(repo, str):
                    summary.repository = repo
                npm_user = doc.get("_npmUser") or {}
                if isinstance(npm_user, dict):
                    summary.publisher = npm_user.get("name", "") or ""
                    summary.publisher_email = npm_user.get("email", "") or ""
                published = times.get(version)
                if published:
                    from .osv import parse_timestamp

                    summary.published_at = parse_timestamp(published)

            out.versions[version] = summary

        if full and not out.repository:
            # Fall back to the newest version that names one; older packages
            # often carry it per-version only.
            for version in sorted(out.versions, reverse=True):
                if out.versions[version].repository:
                    out.repository = out.versions[version].repository
                    break
        return out

    def packuments(
        self,
        names: Iterable[str],
        full: bool = False,
        on_error: Callable[[str, Exception], None] | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> dict[str, PackumentSummary]:
        """Fetch many packages concurrently. Failures are reported, not fatal."""
        wanted = list(dict.fromkeys(names))
        out: dict[str, PackumentSummary] = {}
        done = 0
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {
                pool.submit(self.packument, name, full): name for name in wanted
            }
            for future in as_completed(futures):
                name = futures[future]
                done += 1
                try:
                    out[normalize_name(name)] = future.result()
                except Exception as exc:  # noqa: BLE001 - registry data varies
                    if on_error:
                        on_error(name, exc)
                if progress:
                    progress(done, len(wanted))
        return out

    # -- maintainer reverse lookup ----------------------------------------

    def packages_by_maintainer(
        self, username: str, limit: int = 250
    ) -> list[tuple[str, list[str]]]:
        """Packages an account maintains, as (package, all maintainers).

        This is what makes the shared-maintainer signal affordable: the
        alternative is fetching every packument in the ecosystem and filtering,
        which is not a real option. One paged request per account instead.
        """
        out: list[tuple[str, list[str]]] = []
        page_size = 250
        offset = 0
        while offset < limit:
            size = min(page_size, limit - offset)
            url = (
                f"{REGISTRY}/-/v1/search?text=maintainer:"
                f"{urllib.parse.quote(username)}&size={size}&from={offset}"
            )
            try:
                payload = self._get_json(url)
            except RegistryError:
                break
            objects = payload.get("objects") or []
            if not objects:
                break
            for obj in objects:
                package = obj.get("package") or {}
                name = package.get("name")
                if not name:
                    continue
                names = [
                    m.get("username") or m.get("name")
                    for m in package.get("maintainers") or []
                    if isinstance(m, dict)
                ]
                out.append((name, [n for n in names if n]))
            if len(objects) < size:
                break
            offset += size
        return out

    def download_counts(self, names: Iterable[str]) -> dict[str, int]:
        """Weekly download counts, used only as the typosquat popularity signal.

        The bulk endpoint takes up to 128 names but rejects scoped packages.
        Names it does not answer for are **left out of the result entirely**,
        not recorded as zero: an unknown popularity is not a low one, and
        conflating them made every scoped package look like a squat of
        something famous. The caller treats a missing key as unknown.
        """
        wanted = [normalize_name(n) for n in dict.fromkeys(names)]
        unscoped = [n for n in wanted if not n.startswith("@")]
        out: dict[str, int] = {}

        for i in range(0, len(unscoped), 128):
            chunk = unscoped[i : i + 128]
            url = f"{REGISTRY.replace('registry', 'api')}/downloads/point/last-week/{','.join(chunk)}"
            try:
                payload = self._get_json(url)
            except RegistryError:
                continue
            if not isinstance(payload, dict):
                continue
            if "downloads" in payload and "package" in payload:
                payload = {payload["package"]: payload}
            for name, entry in payload.items():
                if isinstance(entry, dict) and isinstance(entry.get("downloads"), int):
                    out[normalize_name(name)] = entry["downloads"]
        return out

    # -- reporting ---------------------------------------------------------

    def render_stats(self) -> str:
        total = self.stats["hits"] + self.stats["misses"]
        rate = (self.stats["hits"] / total * 100) if total else 0.0
        return (
            f"registry: {self.stats['misses']} fetched, {self.stats['hits']} cached "
            f"({rate:.0f}% hit), {self.stats['bytes']/1e6:.1f} MB, "
            f"{self.stats['errors']} errors"
        )


def _license_of(doc: dict) -> str:
    value = doc.get("license")
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("type", "") or ""
    if isinstance(value, list) and value:
        first = value[0]
        if isinstance(first, dict):
            return first.get("type", "") or ""
        return str(first)
    return ""
