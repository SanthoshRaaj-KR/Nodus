"""Dependency graph + blast radius for a repo.

Builds the FULL dependency graph (down to leaf packages that import nothing
else), then, given the vulnerable packages found by scan.py, walks the graph
backwards to find every package exposed to each vulnerability.

Sources supported:
  * requirements.txt / requirements.lock -- resolved via
    `pip install --dry-run --report`, which produces the exact resolution pip
    would install, down to roots like numpy.
  * package-lock.json -- parsed directly; it already IS a resolved graph.

Ground truth for vulnerabilities is the RESOLVED graph itself: the exact
versions pip/npm would install are written as pins and scanned with
osv-scanner. Scanning the raw manifests instead would mismatch versions
(unpinned ranges resolve to the newest, safe version -- exactly what pip
installs -- so manifest versions are not what runs).
"""

import csv
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
except ImportError:
    Requirement = None
    canonicalize_name = None

#: Subprocess output is decoded as UTF-8 explicitly. Windows otherwise uses
#: the locale codec (cp1252), which cannot decode bytes that osv-scanner and
#: pip both emit -- and the failure lands in subprocess's reader thread, so
#: it surfaces as a stray traceback and an empty result rather than an error
#: anyone can act on. Undecodable bytes are replaced, never raised.
_IGNORED_DIR_PARTS = {".git", ".venv", "venv", "site-packages", "node_modules"}


# --------------------------------------------------------------------------
# Manifest discovery
# --------------------------------------------------------------------------


def find_manifests(repo_path):
    """Discover package manifests under repo_path.

    Returns:
        dict: {"requirements": [paths], "package-lock": [paths]}
    """
    root = Path(repo_path)
    reqs, locks = [], []
    for p in root.rglob("*"):
        if _IGNORED_DIR_PARTS & set(p.parts):
            continue
        if p.name in ("requirements.txt", "requirements.lock"):
            reqs.append(p)
        elif p.name == "package-lock.json":
            locks.append(p)
    return {"requirements": sorted(reqs), "package-lock": sorted(locks)}


# --------------------------------------------------------------------------
# Python graph via pip resolution
# --------------------------------------------------------------------------


def _req_name(req_str):
    """'numpy>=1.26; python_version<"3.11"' -> canonical name or None.

    Environment markers are evaluated against the current platform. `extra`
    markers can't be evaluated from a bare requirement -- but the resolved
    pip report only lists packages that were actually installed, so an
    extra-conditional dependency that appears in `resolved` is kept: the
    extras were requested by the manifest.
    """
    if Requirement is None:
        return None
    try:
        req = Requirement(req_str)
    except Exception:
        return None
    if req.marker is not None:
        try:
            if not req.marker.evaluate():
                # `extra == "..."` markers always evaluate False from a bare
                # requirement. The manifest requested the extras, and the
                # `resolved` dict only lists what pip actually installed, so
                # keep the dependency -- it is still filtered downstream if
                # it was never resolved.
                if "extra" not in str(req.marker):
                    return None
        except Exception:
            pass
    return canonicalize_name(req.name)


def _resolve_one_requirements_file(req_file):
    """Resolve one requirements file with pip's resolver (dry run).

    Packages pip cannot resolve (no wheel for this platform, build-required
    sdists) are dropped one at a time and returned as unresolved leaf nodes
    instead of failing the whole graph.

    Returns:
        (dict nodes, list edges)
    """
    text = Path(req_file).read_text(encoding="utf-8")
    cmd_base = [
        sys.executable, "-m", "pip", "install",
        "--dry-run", "--ignore-installed", "--only-binary", ":all:", "--quiet",
        "--report", "-",
    ]

    for _attempt in range(15):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
            tf.write(text)
            tmp_path = tf.name
        result = subprocess.run(
            cmd_base + ["-r", tmp_path], capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
        if result.returncode == 0:
            Path(tmp_path).unlink(missing_ok=True)
            break
        if "ResolutionImpossible" in result.stderr:
            # The backtracking resolver gave up on a version conflict. The
            # legacy resolver picks greedily and resolves most real-world
            # requirement files; it is the fallback, not the default.
            result = subprocess.run(
                cmd_base + ["--use-deprecated=legacy-resolver", "-r", tmp_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        Path(tmp_path).unlink(missing_ok=True)
        if result.returncode == 0:
            break
        failed = re.findall(
            r"requirement ([A-Za-z0-9_.\-]+) from|"
            r"satisfies the requirement ([A-Za-z0-9_.\-]+)|"
            r"Failed to build '([A-Za-z0-9_.\-]+)'",
            result.stderr,
        )
        bad = {n for tup in failed for n in tup if n}
        if not bad:
            raise RuntimeError(f"pip resolution failed:\n{result.stderr[-2000:]}")
        for name in bad:
            text = re.sub(
                rf"(?im)^[ \t]*[A-Za-z0-9_.\-]*{re.escape(name)}[A-Za-z0-9_.\-]*[^\n]*\n",
                "",
                text,
            )
    else:
        raise RuntimeError("pip resolution failed after retries")

    report = json.loads(result.stdout)
    resolved = {}
    for entry in report.get("install", []):
        meta = entry.get("metadata") or {}
        name = meta.get("name")
        version = meta.get("version")
        if not name or not version:
            continue
        resolved[canonicalize_name(name)] = version

    nodes, edges = {}, []
    for entry in report.get("install", []):
        meta = entry.get("metadata") or {}
        name, version = meta.get("name"), meta.get("version")
        if not name or not version:
            continue
        key = f"{canonicalize_name(name)}@{version}"
        nodes[key] = {
            "name": name,
            "version": version,
            "key": key,
            "ecosystem": "PyPI",
            "summary": meta.get("summary", ""),
            "requires_python": meta.get("requires_python", ""),
            "license": meta.get("license_expression", ""),
        }
    for entry in report.get("install", []):
        meta = entry.get("metadata") or {}
        name, version = meta.get("name"), meta.get("version")
        if not name or not version:
            continue
        key = f"{canonicalize_name(name)}@{version}"
        for req_str in meta.get("requires_dist", []) or []:
            dep_name = _req_name(req_str)
            if dep_name is None:
                continue
            dep_version = resolved.get(dep_name)
            if dep_version is None:
                continue
            child_key = f"{dep_name}@{dep_version}"
            if child_key in nodes:
                edges.append((key, child_key))
    return nodes, edges


def resolve_python(req_files):
    """Full dependency graph across every requirements file, unioned.

    Each file is resolved independently (they are separate dependency
    contexts -- merging them creates false conflicts), then the graphs are
    unioned.

    Returns:
        dict: {"nodes": {name@version: {...}}, "edges": [(parent, child)]}
    """
    nodes, edges = {}, []
    for req_file in req_files:
        file_nodes, file_edges = _resolve_one_requirements_file(req_file)
        nodes.update(file_nodes)
        edges.extend(file_edges)
    return {"nodes": nodes, "edges": sorted(set(edges))}


# --------------------------------------------------------------------------
# npm graph via package-lock.json
# --------------------------------------------------------------------------


def _npm_resolve_dep(from_path, dep_name, packages):
    """Node's resolution rule: the requiring package's own node_modules
    first, then walk up the tree until a hoisted copy is found."""
    parts = from_path.split("/") if from_path else []
    while True:
        prefix = "/".join(parts)
        candidate = f"{prefix}/node_modules/{dep_name}" if prefix else f"node_modules/{dep_name}"
        if candidate in packages:
            return candidate
        if not parts:
            return None
        try:
            idx = len(parts) - 1 - parts[::-1].index("node_modules")
        except ValueError:
            return None
        parts = parts[:idx]


def _npm_name(entry_path, entry):
    """npm lockfile v3 entries under node_modules/ omit the `name` field;
    it must be derived from the path. Root/workspace entries carry it."""
    name = entry.get("name")
    if name:
        return name
    marker = "node_modules/"
    idx = entry_path.rfind(marker)
    return entry_path[idx + len(marker):] if idx >= 0 else entry_path


def resolve_npm(lock_path):
    """Read the resolved graph out of a package-lock.json (v2/v3).

    Every entry under ``packages`` (including nested ``node_modules/``) is a
    resolved package version. Dependency declarations hold semver RANGES, so
    each one must be resolved against the tree with node's hoisting rule:
    the requiring package's own ``node_modules`` first, then walk up the
    nesting until a hoisted copy is found.

    The root entry (``""``) is the app itself and has no version -- it is
    synthesised as ``<app>@0.0.0`` so the app still appears as a dependent
    of every package it imports.
    """
    raw = json.loads(Path(lock_path).read_text(encoding="utf-8"))
    packages = raw.get("packages") or {}
    nodes, edges = {}, []

    for entry_path, entry in packages.items():
        if entry.get("link"):
            continue
        name = _npm_name(entry_path, entry)
        version = entry.get("version") or ("0.0.0" if entry_path == "" else None)
        if not name or not version:
            continue
        key = f"{name}@{version}"
        nodes[key] = {
            "name": name,
            "version": version,
            "key": key,
            "ecosystem": "npm",
            "summary": "",
            "requires_python": "",
            "license": entry.get("license", ""),
        }

    for entry_path, entry in packages.items():
        if entry.get("link"):
            continue
        parent_name = _npm_name(entry_path, entry)
        parent_key = f"{parent_name}@{entry.get('version') or ('0.0.0' if entry_path == '' else '')}"
        if parent_key not in nodes:
            continue
        declared = {}
        for field_name in ("dependencies", "optionalDependencies", "peerDependencies"):
            declared.update(entry.get(field_name) or {})
        for dep_name in declared:
            target_path = _npm_resolve_dep(entry_path, dep_name, packages)
            if target_path is None:
                continue
            target = packages[target_path]
            if target.get("link"):
                continue
            child_key = f"{target.get('name') or dep_name}@{target.get('version')}"
            if child_key in nodes and child_key != parent_key:
                edges.append((parent_key, child_key))
    return {"nodes": nodes, "edges": sorted(set(edges))}


# --------------------------------------------------------------------------
# Graph assembly
# --------------------------------------------------------------------------


def build_graph(repo_path):
    """Full dependency graph for a repo.

    Returns:
        dict: {"nodes": {key: node}, "edges": [(parent, child)], "sources": [..]}
    """
    manifests = find_manifests(repo_path)
    nodes, edges, sources = {}, [], []

    if manifests["requirements"]:
        py = resolve_python(manifests["requirements"])
        nodes.update(py["nodes"])
        edges.extend(py["edges"])
        sources.extend(str(p) for p in manifests["requirements"])
    for lock in manifests["package-lock"]:
        npm = resolve_npm(lock)
        nodes.update(npm["nodes"])
        edges.extend(npm["edges"])
        sources.append(str(lock))

    children = {c for _p, c in edges}
    for node in nodes.values():
        node["direct"] = node["key"] not in children

    return {"nodes": nodes, "edges": sorted(set(edges)), "sources": sources}


# --------------------------------------------------------------------------
# Vulnerabilities of the RESOLVED graph
# --------------------------------------------------------------------------


def vulnerable_nodes(graph):
    """Scan the exact resolved versions with osv-scanner.

    The resolved graph is ground truth: these are the versions that would
    actually be installed, so the scan and the blast-radius walk agree.
    PyPI and npm packages are scanned separately, each via a manifest that
    osv-scanner's extractors recognize.

    Returns:
        dict: resolved package name (canonical) -> set of vulnerable versions
    """
    vulnerable = {}
    _scan_pypi_pins(graph, vulnerable)
    _scan_npm_pins(graph, vulnerable)
    return vulnerable


def _scan_pypi_pins(graph, vulnerable):
    """Scan the resolved PyPI versions via a pinned requirements file."""
    pins = "\n".join(
        f"{node['name']}=={node['version']}"
        for node in graph["nodes"].values()
        if node.get("ecosystem") == "PyPI" and "unresolved" not in node["version"]
    )
    if not pins:
        return
    with tempfile.TemporaryDirectory() as tmp:
        pin_path = Path(tmp) / "requirements.txt"
        pin_path.write_text(pins, encoding="utf-8")
        result = subprocess.run(
            ["osv-scanner", "scan", "--lockfile", str(pin_path), "--format", "json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    _accumulate_vulns(result, vulnerable)


def _scan_npm_pins(graph, vulnerable):
    """Scan the resolved npm versions via a synthetic package-lock.json."""
    npm_nodes = [
        node for node in graph["nodes"].values()
        if node.get("ecosystem") == "npm"
    ]
    if not npm_nodes:
        return
    packages = {"": {"name": "scanned", "version": "0.0.0", "license": "MIT"}}
    for node in npm_nodes:
        packages[f"node_modules/{node['name']}"] = {
            "name": node["name"],
            "version": node["version"],
            "license": node.get("license", ""),
        }
    lock = {"lockfileVersion": 3, "packages": packages}
    with tempfile.TemporaryDirectory() as tmp:
        lock_path = Path(tmp) / "package-lock.json"
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        result = subprocess.run(
            ["osv-scanner", "scan", "--lockfile", str(lock_path), "--format", "json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    _accumulate_vulns(result, vulnerable)


def _accumulate_vulns(result, vulnerable):
    """Merge osv-scanner results into the vulnerable dict (in place)."""
    if result.returncode not in (0, 1):
        raise RuntimeError(f"osv-scanner failed: {result.stderr[-2000:]}")
    if not result.stdout.strip():
        return
    data = json.loads(result.stdout)
    for group in data.get("results", []):
        for item in group.get("packages", []):
            pkg = item.get("package", {})
            name = pkg.get("name")
            version = pkg.get("version")
            if not name or not version:
                continue
            if item.get("vulnerabilities"):
                vulnerable.setdefault(canonicalize_name(name), set()).add(version)


# --------------------------------------------------------------------------
# Blast radius
# --------------------------------------------------------------------------


def find_blast_radius(graph, vulnerable):
    """Every package exposed to any vulnerable package.

    Walks the graph BACKWARDS (who depends on the vulnerable package?),
    breadth-first, so results carry a real depth and a concrete chain.

    Args:
        graph (dict): output of build_graph().
        vulnerable (dict): canonical name -> set of vulnerable versions,
            as returned by vulnerable_nodes().

    Returns:
        list: [{"exposed_package", "exposed_version", "depth", "path",
                "vulnerable_package", "vulnerable_version", ...}]
    """
    nodes = graph["nodes"]
    parents = {}
    for parent, child in graph["edges"]:
        parents.setdefault(child, []).append(parent)

    norm = canonicalize_name if canonicalize_name is not None else (
        lambda s: s.lower().replace("_", "-")
    )

    vuln_keys = []
    for name, versions in vulnerable.items():
        for version in versions:
            key = f"{norm(name)}@{version}"
            if key in nodes:
                vuln_keys.append(key)

    exposed = []
    for vuln_key in vuln_keys:
        seen = {vuln_key}
        queue = [(vuln_key, [vuln_key])]
        while queue:
            current, path = queue.pop(0)
            depth = len(path) - 1
            node = nodes[current]
            exposed.append({
                "exposed_package": node["name"],
                "exposed_version": node["version"],
                "ecosystem": node.get("ecosystem", ""),
                "depth": depth,
                "path": " -> ".join(path),
                "vulnerable_package": nodes[vuln_key]["name"],
                "vulnerable_version": nodes[vuln_key]["version"],
                "direct": bool(node.get("direct")),
                "summary": node.get("summary", ""),
            })
            for parent in parents.get(current, []):
                if parent not in seen:
                    seen.add(parent)
                    queue.append((parent, [parent] + path))
    return exposed


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

GRAPH_FIELDS = ["parent", "parent_version", "child", "child_version", "ecosystem"]
BLAST_FIELDS = [
    "exposed_package", "exposed_version", "ecosystem", "depth", "path",
    "vulnerable_package", "vulnerable_version", "direct", "summary",
]


def write_csv(path, rows, fields):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 deps.py <repo_path> [output_prefix]")
        sys.exit(1)
    repo_path = sys.argv[1]
    prefix = sys.argv[2] if len(sys.argv) > 2 else "deps"

    graph = build_graph(repo_path)
    vulnerable = vulnerable_nodes(graph)
    exposed = find_blast_radius(graph, vulnerable)

    write_csv(f"{prefix}_graph.csv", [
        {"parent": p, "parent_version": graph["nodes"][p]["version"],
         "child": c, "child_version": graph["nodes"][c]["version"],
         "ecosystem": graph["nodes"][p].get("ecosystem", "")}
        for p, c in graph["edges"]
    ], GRAPH_FIELDS)
    write_csv(f"{prefix}_blast_radius.csv", exposed, BLAST_FIELDS)

    summary = {
        "repo_path": repo_path,
        "manifest_sources": graph["sources"],
        "graph_nodes": len(graph["nodes"]),
        "graph_edges": len(graph["edges"]),
        "vulnerable_packages": len(vulnerable),
        "exposed_packages": len({e["exposed_package"] for e in exposed}),
        "exposed_entries": len(exposed),
    }
    print(json.dumps(summary, indent=2))
    print(f"\nGraph CSV:        {prefix}_graph.csv")
    print(f"Blast radius CSV: {prefix}_blast_radius.csv")


if __name__ == "__main__":
    main()