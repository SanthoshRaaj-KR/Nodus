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

from collections import deque

from ..hydra_client import HydraClient
from .exposure import full_exposure


#: Call chains deeper than this fold into the last function column. A column
#: strip has to end somewhere, and the node still carries its true depth.
MAX_CALL_DEPTH = 6

#: Column index of the first function column. 0 entry, 1 route, 2 handler.
FIRST_FN_LAYER = 3


def _rank_calls(function_ids, calls, seed_ids):
    """Longest-path layering over the call graph, cycles broken first.

    The view used to put every non-handler function in a single column, which
    is why the code graph did not look like a hierarchy: a five-deep call chain
    drew as five cards stacked in one column with the calls between them
    looping backwards 222px under the cards. Depth is a real property of the
    graph, so it is computed rather than flattened.

    Longest path, not shortest: a utility called from both depth 1 and depth 4
    belongs to the right of *both* its callers, otherwise its incoming edge
    from the deeper one points backwards and the crossing it makes is exactly
    the mess this replaces. Shortest path would place it at 2.

    Recursion and mutual recursion make longest path undefined, so back edges
    are removed first by a depth-first pass. They are dropped from the ranking
    only; the edge itself is still drawn, and the frontend routes it as an arc
    because it is genuinely a back edge and pretending otherwise would be a
    lie about the code.
    """
    adjacency: dict = {}
    for call in calls:
        adjacency.setdefault(call["src"], []).append(call["dst"])

    # -- break cycles: iterative DFS, dropping any edge back into the stack --
    WHITE, GREY, BLACK = 0, 1, 2
    colour = {fid: WHITE for fid in function_ids}
    back_edges = set()
    # Seeds first, so the spanning forest starts where control actually enters.
    order = [f for f in seed_ids if f in colour] + [
        f for f in function_ids if f not in seed_ids
    ]
    for root in order:
        if colour.get(root) != WHITE:
            continue
        stack = [(root, iter(adjacency.get(root, ())))]
        colour[root] = GREY
        while stack:
            node, children = stack[-1]
            advanced = False
            for child in children:
                if child not in colour:
                    continue
                if colour[child] == GREY:
                    back_edges.add((node, child))
                elif colour[child] == WHITE:
                    colour[child] = GREY
                    stack.append((child, iter(adjacency.get(child, ()))))
                    advanced = True
                    break
            if not advanced:
                colour[node] = BLACK
                stack.pop()

    forward: dict = {}
    indegree = {fid: 0 for fid in function_ids}
    for src, children in adjacency.items():
        if src not in indegree:
            continue
        for dst in children:
            if dst not in indegree or (src, dst) in back_edges or src == dst:
                continue
            forward.setdefault(src, []).append(dst)
            indegree[dst] += 1

    # -- longest path over the now-acyclic graph, in topological order -------
    depth = {fid: 0 for fid in function_ids}
    queue = deque(fid for fid, d in indegree.items() if d == 0)
    remaining = dict(indegree)
    while queue:
        node = queue.popleft()
        for child in forward.get(node, ()):
            if depth[node] + 1 > depth[child]:
                depth[child] = depth[node] + 1
            remaining[child] -= 1
            if remaining[child] == 0:
                queue.append(child)
    return depth, back_edges


def micro_graph(client: HydraClient) -> dict:
    """Entry points, routes, handlers, functions and external imports.

    Every node also carries its vulnerability *heat* -- see
    :mod:`blastradius.query.exposure`. This is a second, independent channel
    from the query highlight the browser computes: ``heat`` answers "is this
    exposed to a known CVE", which is a fact about the graph and is true before
    anyone types anything, while ``hot`` answers "does this match what the user
    is looking at". Conflating them is what left this view unable to show a
    vulnerability at all -- the only red it had was driven by the search box.
    """
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

    # One model, shared with the package view, so the two tabs cannot disagree
    # about the same CVE.
    model = full_exposure(client)

    def heat_of(node_id) -> dict:
        """Vulnerability fields for one graph node, or the clean defaults."""
        hit = model.heat.get(node_id)
        if hit is None:
            return {
                "heat": 0.0,
                "hops": -1,
                "severity": "",
                "vuln": False,
                "vulnSource": "",
                "advisory": "",
            }
        return {
            "heat": round(hit.heat, 4),
            "hops": hit.hops,
            "severity": hit.severity,
            "vuln": True,
            "vulnSource": hit.source,
            "advisory": hit.advisory,
        }

    # Entry points and route handlers are where control enters, so they anchor
    # the ranking; everything else is placed by how deep it is called from one.
    function_ids = [fn["id"] for fn in functions]
    module_ids = {fn["id"] for fn in functions if fn["name"] == "<module>"}
    seed_ids = list(module_ids | handler_ids)
    call_depth, back_edges = _rank_calls(function_ids, calls, seed_ids)

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
            depth = min(call_depth.get(fn["id"], 0), MAX_CALL_DEPTH)
            layer, kind = FIRST_FN_LAYER + depth, "fn"
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
                **heat_of(fn["id"]),
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
                **heat_of(route["id"]),
            }
        )

    # Imports sit in the last column, whatever the deepest call chain turned
    # out to be -- a package import is the end of every path that reaches it.
    deepest_fn = max((n["layer"] for n in nodes if n["kind"] == "fn"), default=FIRST_FN_LAYER)
    import_layer = max(deepest_fn + 1, FIRST_FN_LAYER + 1)

    for imp in imports:
        hit = resolved.get(imp["id"])
        nodes.append(
            {
                "id": f"im:{imp['id']}",
                "layer": import_layer,
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
                **heat_of(imp["id"]),
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

    worst = model.worst()
    return {
        "mode": "micro",
        "cols": _columns(import_layer),
        "nodes": nodes,
        "edges": _dedupe(edges),
        # Lets the view say "clean" with authority instead of merely drawing
        # nothing red, which is the same picture as a broken join.
        "exposure": {
            "exposed": sum(1 for n in nodes if n["vuln"]),
            "total": len(nodes),
            "worst": worst.as_dict() if worst else None,
            "advisories": len(model.seeds),
        },
    }


def _columns(import_layer: int) -> list[str]:
    """Headers for a strip whose function band is however deep the code is.

    The first function column is what an entry point or handler calls
    directly; each one after it is a further call down. Naming them by depth
    rather than repeating "FUNCTIONS" is the point of ranking them at all.
    """
    cols = ["ENTRY POINTS", "HTTP ROUTES", "HANDLERS"]
    for depth in range(import_layer - FIRST_FN_LAYER):
        cols.append("FUNCTIONS" if depth == 0 else f"CALL DEPTH {depth + 1}")
    cols.append("PACKAGE IMPORTS")
    return cols


def _dedupe(edges: list[list[str]]) -> list[list[str]]:
    seen = set()
    out = []
    for src, dst in edges:
        if (src, dst) not in seen and src != dst:
            seen.add((src, dst))
            out.append([src, dst])
    return out
