"""Enrich the dependency graph with package and vulnerability metadata.

Two sources:
  * OSV API (api.osv.dev) -- for each vulnerable package@version: advisory id,
    summary, full details (why it is vulnerable), CVSS severity, aliases,
    fixed version, publication date, references.
  * Package registries (PyPI / npm) -- maintainers, author, homepage.

Registry lookups are cached to a local JSON file so re-runs are fast and the
registry is not hammered.
"""

import json
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    from packaging.utils import canonicalize_name
except ImportError:
    canonicalize_name = None

OSV_API = "https://api.osv.dev/v1/query"
CACHE_FILE = Path(__file__).parent / "pkg_meta_cache.json"
CACHE_TTL = 7 * 24 * 3600  # 7 days
NORM = (canonicalize_name if canonicalize_name is not None
        else (lambda s: s.lower().replace("_", "-")))


def _http_json(url, data=None, timeout=20):
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method="POST" if data else "GET")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "hackhydra-osv-tool/1.0")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


# --------------------------------------------------------------------------
# OSV vulnerability details
# --------------------------------------------------------------------------


def _osv_details(package_name, ecosystem):
    """All advisories for a package (any version) from the OSV API."""
    try:
        return _http_json(OSV_API, {
            "package": {"name": package_name, "ecosystem": ecosystem},
        }).get("vulns", [])
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return []


def _version_in_affected(version, affected):
    """Best-effort check: does any affected range cover this version?"""
    if not version or "<unresolved>" in version:
        return True
    parts = [int(p) for p in version.split(".") if p.isdigit()] or [0]

    def ver_tuple(v):
        return tuple(int(p) for p in v.split(".") if p.isdigit()) or (0,)

    vt = ver_tuple(version)
    for entry in affected:
        for rng in entry.get("ranges", []):
            events = rng.get("events", [])
            introduced = "0"
            fixed = None
            for ev in events:
                if "introduced" in ev:
                    introduced = ev["introduced"]
                if "fixed" in ev:
                    fixed = ev["fixed"]
            if vt >= ver_tuple(introduced) and (fixed is None or vt < ver_tuple(fixed)):
                return True
    return False


def enrich_vulnerabilities(graph, vulnerable):
    """Attach full advisory details to every vulnerable node.

    Args:
        graph (dict): from deps.build_graph()
        vulnerable (dict): canonical name -> set of vulnerable versions.

    Returns:
        dict: node key -> list of advisory dicts (id, summary, details,
            severity, aliases, fixed, published, references).
    """
    by_name: dict[str, dict] = {}
    for key, node in graph["nodes"].items():
        vuln_versions = vulnerable.get(NORM(node["name"]), set())
        if vuln_versions and node["version"] in vuln_versions:
            by_name.setdefault(node["name"], []).append((key, node))

    enriched = {}
    for name, entries in by_name.items():
        ecosystem = entries[0][1]["ecosystem"]
        advisories = _osv_details(name, ecosystem)
        for key, node in entries:
            hits = []
            for adv in advisories:
                if _version_in_affected(node["version"], adv.get("affected", [])):
                    severity = adv.get("severity", [])
                    hits.append({
                        "id": adv.get("id"),
                        "aliases": adv.get("aliases", []),
                        "summary": adv.get("summary", ""),
                        "details": adv.get("details", ""),
                        "cvss": [
                            {"type": s.get("type"), "score": s.get("score")}
                            for s in severity
                        ],
                        "fixed": _fixed_versions(adv.get("affected", [])),
                        "published": adv.get("published", ""),
                        "references": [
                            r.get("url") for r in adv.get("references", [])
                            if r.get("type") == "ADVISORY"
                        ],
                    })
            enriched[key] = hits
    return enriched


def _fixed_versions(affected):
    fixed = []
    for entry in affected:
        for rng in entry.get("ranges", []):
            for ev in rng.get("events", []):
                if ev.get("fixed") and ev["fixed"] not in fixed:
                    fixed.append(ev["fixed"])
    return fixed


# --------------------------------------------------------------------------
# Registry metadata (maintainers etc.), cached
# --------------------------------------------------------------------------


def _load_cache():
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if time.time() - data.get("ts", 0) < CACHE_TTL:
                return data.get("packages", {})
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_cache(cache):
    try:
        CACHE_FILE.write_text(
            json.dumps({"ts": time.time(), "packages": cache}, indent=1),
            encoding="utf-8",
        )
    except OSError:
        pass


def _fetch_pypi_meta(name):
    try:
        d = _http_json(f"https://pypi.org/pypi/{name}/json", timeout=15)
        info = d.get("info", {})
        urls = info.get("project_urls") or {}
        return {
            "name": name,
            "maintainers": [u for u in (info.get("maintainer_email") or "").split(",") if u.strip()],
            "author": info.get("author") or "",
            "homepage": urls.get("Homepage") or info.get("home_page") or "",
            "license": (info.get("license_expression")
                        or (info.get("license") or "")[:80]),
            "latest_version": info.get("version", ""),
        }
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return None


def _fetch_npm_meta(name):
    try:
        d = _http_json(f"https://registry.npmjs.org/{name}", timeout=15)
        latest = d.get("dist-tags", {}).get("latest", "")
        return {
            "name": name,
            "maintainers": [m.get("name") for m in d.get("maintainers", [])],
            "author": (d.get("author") or {}).get("name", ""),
            "homepage": d.get("homepage") or "",
            "license": (d.get("license") or "")[:80],
            "latest_version": latest,
        }
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return None


def enrich_registry_metadata(graph):
    """Fetch maintainer/author/homepage for every package, cached.

    Returns:
        dict: canonical package name -> metadata dict.
    """
    cache = _load_cache()
    names = sorted({NORM(n["name"]) for n in graph["nodes"].values()})
    todo = [n for n in names if n not in cache]

    if todo:
        def fetch(norm_name):
            meta = (_fetch_pypi_meta(norm_name)
                    if norm_name in {NORM(n["name"]) for n in graph["nodes"].values()
                                     if n.get("ecosystem") == "PyPI"}
                    else _fetch_npm_meta(norm_name))
            return norm_name, meta or {}

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(fetch, n) for n in todo]
            for fut in as_completed(futures):
                norm_name, meta = fut.result()
                if meta:
                    cache[norm_name] = meta
        _save_cache(cache)

    return {n: cache.get(n, {}) for n in names}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main():
    sys.path.insert(0, str(Path(__file__).parent))
    from deps import build_graph, vulnerable_nodes

    if len(sys.argv) < 2:
        print("Usage: python3 enrich.py <repo_path> [output.json]")
        sys.exit(1)
    repo_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "enriched_graph.json"

    graph = build_graph(repo_path)
    vulnerable = vulnerable_nodes(graph)
    advs = enrich_vulnerabilities(graph, vulnerable)
    registry = enrich_registry_metadata(graph)

    for key, node in graph["nodes"].items():
        node["maintainers"] = registry.get(NORM(node["name"]), {}).get("maintainers", [])
        node["author"] = registry.get(NORM(node["name"]), {}).get("author", "")
        node["homepage"] = registry.get(NORM(node["name"]), {}).get("homepage", "")
        node["latest_version"] = registry.get(NORM(node["name"]), {}).get("latest_version", "")
        node["advisories"] = advs.get(key, [])

    out = {
        "repo_path": repo_path,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "graph_nodes": len(graph["nodes"]),
            "graph_edges": len(graph["edges"]),
            "vulnerable_packages": len(vulnerable),
        },
        "graph": graph,
    }
    Path(out_path).write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"Wrote {out_path} with per-node maintainers and advisory details")


if __name__ == "__main__":
    main()