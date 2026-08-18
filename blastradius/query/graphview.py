"""Whole-graph views for the UI, in the layered shape the design expects.

The Dual Graph visualiser draws two column-layered graphs:

    macro   SERVICES -> DIRECT DEPS -> TRANSITIVE -> DEEP TRANSITIVE
    micro   ENTRY POINTS -> HTTP ROUTES -> HANDLERS -> FUNCTIONS -> IMPORTS

Both are read out of HydraDB here and handed to the browser as plain nodes and
edges. The blast-radius highlighting is then computed client-side by reverse
BFS from whatever the user typed, so dragging the query around costs no round
trips -- the graph is small enough to live in memory, and an incident responder
typing a package name should not wait on the network for each keystroke.

Every statement is a fixed-length MATCH. Variable-length reads would need a
pinned source, and these are deliberately whole-graph sweeps.
"""

from __future__ import annotations

from ..hydra_client import HydraClient

#: depth on PRESENT_IN -> column in the macro view. Anything deeper than 3 is
#: still "deep transitive"; the design has four columns, not N.
MAX_MACRO_LAYER = 3


def _layer_for_depth(depth: int) -> int:
    if depth <= 1:
        return 1
    if depth == 2:
        return 2
    return MAX_MACRO_LAYER


def macro_graph(client: HydraClient) -> dict:
    """Services and the package versions they resolve to, by depth."""
    services = client.query(
        "MATCH (s:Service) RETURN s.id AS id, s.name AS name, s.repo AS repo, "
        "s.path AS path ORDER BY name"
    ).rows

    packages = client.query(
        "MATCH (p:PackageVersion) RETURN p.id AS id, p.key AS key, p.name AS name, "
        "p.version AS version, p.dev AS dev ORDER BY key"
    ).rows

    presence = client.query(
        "MATCH (p:PackageVersion)-[e:PRESENT_IN]->(s:Service) "
        "RETURN p.key AS package, s.name AS service, e.depth AS depth, "
        "e.dev AS dev, e.direct AS direct"
    ).rows

    dep_edges = client.query(
        "MATCH (a:PackageVersion)-[:DEPENDS_ON]->(b:PackageVersion) "
        "RETURN a.key AS parent, b.key AS child"
    ).rows

    direct_edges = client.query(
        "MATCH (s:Service)-[e:DEPENDS_ON]->(p:PackageVersion) "
        "RETURN s.name AS service, p.key AS package, e.dev AS dev"
    ).rows

    # Shallowest appearance anywhere decides the column, so a package that is
    # direct in one service does not get buried because it is deep in another.
    shallowest: dict[str, int] = {}
    dev_only: dict[str, bool] = {}
    used_by: dict[str, set[str]] = {}
    for row in presence:
        key = row["package"]
        depth = int(row["depth"] or 99)
        shallowest[key] = min(shallowest.get(key, 99), depth)
        dev_only[key] = dev_only.get(key, True) and bool(row["dev"])
        used_by.setdefault(key, set()).add(row["service"])

    nodes = [
        {
            "id": f"svc:{s['name']}",
            "layer": 0,
            "kind": "service",
            "label": s["name"],
            "sub": f"{s['repo']} · {s['path']}",
            "file": s["path"],
            "stack": [],
        }
        for s in services
    ]

    for pkg in packages:
        key = pkg["key"]
        depth = shallowest.get(key)
        if depth is None:
            continue  # in the graph but reachable from no service
        layer = _layer_for_depth(depth)
        consumers = sorted(used_by.get(key, ()))
        kind = {1: "direct", 2: "transitive", MAX_MACRO_LAYER: "deep"}[layer]
        via = f"depth {depth} · {len(consumers)} service(s)"
        nodes.append(
            {
                "id": key,
                "layer": layer,
                "kind": kind,
                "label": pkg["name"],
                "sub": f"{pkg['version']} · {via}" + (" · dev" if dev_only.get(key) else ""),
                "pkg": pkg["name"],
                "version": pkg["version"],
                "file": f"node_modules/{pkg['name']}",
            }
        )

    present = {n["id"] for n in nodes}
    edges = [
        [f"svc:{e['service']}", e["package"]]
        for e in direct_edges
        if f"svc:{e['service']}" in present and e["package"] in present
    ]
    edges += [
        [e["parent"], e["child"]]
        for e in dep_edges
        if e["parent"] in present and e["child"] in present
    ]

    return {
        "mode": "macro",
        "cols": ["SERVICES", "DIRECT DEPS", "TRANSITIVE", "DEEP TRANSITIVE"],
        "nodes": nodes,
        "edges": _dedupe(edges),
    }


def micro_graph(client: HydraClient) -> dict:
    """Entry points, routes, handlers, functions and external imports."""
    functions = client.query(
        "MATCH (f:Function) RETURN f.id AS id, f.name AS name, f.file AS file, "
        "f.line AS line, f.service AS service, f.exported AS exported"
    ).rows
    routes = client.query(
        "MATCH (r:Route) RETURN r.id AS id, r.method AS method, r.pattern AS pattern, "
        "r.file AS file, r.line AS line, r.service AS service"
    ).rows
    imports = client.query(
        "MATCH (e:ExternalImport) RETURN e.id AS id, e.specifier AS specifier, "
        "e.service AS service, e.names AS names, e.file AS file"
    ).rows

    calls = client.query(
        "MATCH (a:Function)-[:CALLS]->(b:Function) RETURN a.id AS src, b.id AS dst"
    ).rows
    handled = client.query(
        "MATCH (r:Route)-[:HANDLED_BY]->(f:Function) RETURN r.id AS src, f.id AS dst"
    ).rows
    externals = client.query(
        "MATCH (f:Function)-[:CALLS_EXTERNAL]->(e:ExternalImport) "
        "RETURN f.id AS src, e.id AS dst"
    ).rows
    resolves = client.query(
        "MATCH (e:ExternalImport)-[:RESOLVES_TO]->(p:PackageVersion) "
        "RETURN e.id AS src, p.key AS package, p.name AS name, p.version AS version"
    ).rows

    handler_ids = {row["dst"] for row in handled}
    resolved = {r["src"]: r for r in resolves}

    nodes: list[dict] = []
    for fn in functions:
        is_module = fn["name"] == "<module>"
        if is_module:
            layer, kind = 0, "entry"
            sub = f"{fn['service']} · module scope"
        elif fn["id"] in handler_ids:
            layer, kind = 2, "handler"
            sub = f"{fn['file']}:{fn['line']}"
        else:
            layer, kind = 3, "fn"
            sub = f"{fn['file']}:{fn['line']}"
        nodes.append(
            {
                "id": f"fn:{fn['id']}",
                "layer": layer,
                "kind": kind,
                "label": fn["file"] if is_module else f"{fn['name']}()",
                "sub": sub,
                "file": f"{fn['file']}:{fn['line']}",
                "service": fn["service"],
            }
        )

    for route in routes:
        nodes.append(
            {
                "id": f"rt:{route['id']}",
                "layer": 1,
                "kind": "route",
                "label": f"{route['method']} {route['pattern']}",
                "sub": f"{route['file']}:{route['line']}",
                "file": f"{route['file']}:{route['line']}",
                "service": route["service"],
            }
        )

    for imp in imports:
        hit = resolved.get(imp["id"])
        nodes.append(
            {
                "id": f"im:{imp['id']}",
                "layer": 4,
                "kind": "import",
                "label": f"import '{imp['specifier']}'",
                "sub": (f"{hit['version']} · " if hit else "") + (imp["names"] or "—"),
                "file": imp["file"],
                "service": imp["service"],
                # Carries the resolved package so the same query that lights up
                # the macro view lights up this one.
                "pkg": hit["name"] if hit else imp["specifier"],
                "version": hit["version"] if hit else "",
            }
        )

    present = {n["id"] for n in nodes}
    edges: list[list[str]] = []

    # A module has no edge to a route in the graph -- routes are registered by
    # top-level statements, which the scanner attributes to <module>. Joining
    # them on file recovers the entry-point column the design draws.
    module_by_file = {
        (f["service"], f["file"]): f"fn:{f['id']}"
        for f in functions
        if f["name"] == "<module>"
    }
    for route in routes:
        module = module_by_file.get((route["service"], route["file"]))
        if module and module in present:
            edges.append([module, f"rt:{route['id']}"])

    edges += [[f"rt:{r['src']}", f"fn:{r['dst']}"] for r in handled]
    edges += [[f"fn:{c['src']}", f"fn:{c['dst']}"] for c in calls]
    edges += [[f"fn:{e['src']}", f"im:{e['dst']}"] for e in externals]

    edges = [e for e in edges if e[0] in present and e[1] in present]

    return {
        "mode": "micro",
        "cols": ["ENTRY POINTS", "HTTP ROUTES", "HANDLERS", "FUNCTIONS", "PACKAGE IMPORTS"],
        "nodes": nodes,
        "edges": _dedupe(edges),
    }


def _dedupe(edges: list[list[str]]) -> list[list[str]]:
    seen = set()
    out = []
    for src, dst in edges:
        if (src, dst) not in seen and src != dst:
            seen.add((src, dst))
            out.append([src, dst])
    return out
