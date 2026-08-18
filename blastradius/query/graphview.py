"""The code-graph view for the UI, in the layered shape the design expects.

    micro   ENTRY POINTS -> HTTP ROUTES -> HANDLERS -> FUNCTIONS -> IMPORTS

Read out of HydraDB here and handed to the browser as plain nodes and edges.
The blast-radius highlighting is then computed client-side by reverse BFS from
whatever the user typed, so dragging the query around costs no round trips --
the code graph is small enough to live in memory, and an incident responder
typing a package name should not wait on the network for each keystroke.

That trade is what makes this view work and is also why the macro view no
longer lives here. A whole-graph sweep plus a client-side name match answers
"is this name present somewhere", which over the package tier is the
range-only heuristic the evidence model exists to replace: it cannot tell a
version a range merely admits from one a lockfile actually resolved. The
macro view is now scoped to a single version and answered server-side, in
blastradius/pkg/graphview.py, against evidence stored on the edges.

Every statement is a fixed-length MATCH. Variable-length reads would need a
pinned source, and this is deliberately a whole-graph sweep.
"""

from __future__ import annotations

from ..hydra_client import HydraClient

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
                # The specifier alone, unwrapped. `import '<name>'` spends 9
                # of a 214px card on punctuation and ellipsises away the one
                # thing the node exists to tell you.
                "label": imp["specifier"],
                "sub": (f"{hit['version']} · " if hit else "")
                + (imp["names"] or "side-effect import"),
                "file": imp["file"],
                "service": imp["service"],
                # Carries the resolved package so a `name@version` typed into
                # this view matches the import that resolves to it, not just
                # the specifier as written in the source.
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
