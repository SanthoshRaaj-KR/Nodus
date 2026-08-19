"""Generate a self-contained HTML visualization of the dependency graph.

Usage:
    python3 visualize.py <repo_path> [output.html]

Produces an interactive force-directed graph:
  * nodes colored by ecosystem (PyPI / npm),
  * vulnerable packages highlighted red, exposed packages amber,
  * click a node to see its full metadata (version, license, summary,
    requires_python, direct/transitive, and which vulnerability hits it).
"""

import json
import sys

from deps import build_graph, find_blast_radius, vulnerable_nodes
from enrich import (NORM, enrich_registry_metadata, enrich_vulnerabilities)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Dependency Graph — __REPO__</title>
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
  body { margin: 0; font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
         background: #0f1115; color: #e6e6e6; }
  #header { padding: 14px 20px; border-bottom: 1px solid #2a2e37;
            background: #15181f; display: flex; align-items: baseline; gap: 16px; }
  #header h1 { font-size: 16px; margin: 0; font-weight: 600; }
  #header .meta { color: #8b93a3; font-size: 12px; }
  #legend { display: flex; gap: 14px; margin-left: auto; font-size: 12px; }
  .swatch { display: inline-block; width: 11px; height: 11px; border-radius: 50%;
             margin-right: 5px; vertical-align: -1px; }
  #graph { height: calc(100vh - 122px); }
  #details { position: fixed; right: 18px; top: 84px; width: 330px; max-height: 70vh;
             overflow-y: auto; background: #1a1e27; border: 1px solid #2a2e37;
             border-radius: 8px; padding: 14px 16px; font-size: 12.5px;
             display: none; line-height: 1.5; }
  #details h2 { font-size: 14px; margin: 0 0 8px; }
  #details .kv { display: flex; gap: 8px; margin: 3px 0; }
  #details .k { color: #8b93a3; min-width: 110px; flex-shrink: 0; }
  #details .v { word-break: break-word; }
  #details .vuln { color: #ff6b6b; }
  #details .exposed { color: #ffb454; }
  #details .ok { color: #6bc77a; }
</style>
</head>
<body>
<div id="header">
  <h1>Dependency Graph</h1>
  <span class="meta">__REPO__</span>
  <span class="meta">__NODES__ nodes &middot; __EDGES__ edges &middot; __VULN__ vulnerable</span>
  <div id="legend">
    <span><span class="swatch" style="background:#5a7bd8"></span>PyPI</span>
    <span><span class="swatch" style="background:#7ac75f"></span>npm</span>
    <span><span class="swatch" style="background:#ff6b6b"></span>Vulnerable</span>
    <span><span class="swatch" style="background:#ffb454"></span>Exposed (blast radius)</span>
    <span><span class="swatch" style="background:#8b93a3"></span>Safe leaf</span>
  </div>
</div>
<div id="graph"></div>
<div id="details"></div>

<script>
const GRAPH = __GRAPH__;
const VULNERABLE = __VULNERABLE__;
const EXPOSED = __EXPOSED__;
const byKey = {};
GRAPH.nodes.forEach(n => byKey[n.key] = n);

const NODE_COLORS = {
  PyPI: '#5a7bd8',
  npm:  '#7ac75f',
};
const VULN_COLOR = '#ff6b6b';
const EXPOSED_COLOR = '#ffb454';
const SAFE_LEAF = '#8b93a3';

const vulnKeys = new Set();
for (const [name, versions] of Object.entries(VULNERABLE)) {
  for (const v of versions) vulnKeys.add(name + '@' + v);
}
const exposedKeys = new Set(EXPOSED.map(e => e.exposed_package + '@' + e.exposed_version));

const nodes = GRAPH.nodes.map(n => {
  let color = NODE_COLORS[n.ecosystem] || '#8b93a3';
  let label = n.name;
  if (vulnKeys.has(n.key)) {
    color = VULN_COLOR;
    label = '⚠ ' + n.name + '\\n' + n.version;
  } else if (exposedKeys.has(n.key)) {
    color = EXPOSED_COLOR;
    label = n.name + '\\n' + n.version;
  }
  return {
    id: n.key,
    label,
    color,
    shape: 'dot',
    size: n.direct ? 16 : 11,
    borderWidth: 1,
    borderColor: '#00000055',
    title: n.name + '\\n' + n.version,
  };
});

const edges = GRAPH.edges.map(([from, to]) => ({
  from, to,
  arrows: { to: { enabled: true, scaleFactor: 0.55 } },
  color: { color: '#3a4150', opacity: 0.55 },
}));

const container = document.getElementById('graph');
const options = {
  physics: {
    solver: 'forceAtlas2Based',
    forceAtlas2Based: { gravitationalConstant: -80, springLength: 110 },
    stabilization: { iterations: 400 },
  },
  interaction: { hover: true, tooltipDelay: 120 },
  nodes: { font: { color: '#e6e6e6', size: 12, face: 'Menlo, monospace' } },
  edges: { smooth: { enabled: true, type: 'continuous', roundness: 0.4 } },
};

const network = new vis.Network(container, { nodes, edges }, options);

const details = document.getElementById('details');
network.on('click', (params) => {
  if (!params.nodes.length) { details.style.display = 'none'; return; }
  const n = byKey[params.nodes[0]];
  if (!n) return;
  const vulns = [...vulnKeys].filter(k => k.startsWith(n.name + '@'));
  const blast = EXPOSED.filter(e =>
    e.exposed_package === n.name && e.exposed_version === n.version);
  const status = vulns.length
    ? '<span class="vuln">VULNERABLE</span>'
    : blast.length
      ? '<span class="exposed">exposed via blast radius</span>'
      : '<span class="ok">no known vulnerabilities</span>';
  const vulnLines = vulns.length
    ? `<div class="kv"><span class="k">advisories</span>
       <span class="v vuln">${vulns.join('<br>')}</span></div>`
    : '';
  const blastLines = blast.length
    ? `<div class="kv"><span class="k">exposed by</span>
       <span class="v">${blast.map(b => b.vulnerable_package + '@' + b.vulnerable_version + ' (depth ' + b.depth + ')').join('<br>')}</span></div>`
    : '';
  const advLines = (n.advisories || []).map(a =>
    `<div style="margin:8px 0 4px;border-top:1px solid #2a2e37;padding-top:6px">
       <div class="v vuln">${a.id}</div>
       <div class="v" style="margin:2px 0">${a.summary || '(no summary)'}</div>
       <div class="kv"><span class="k">fixed in</span><span class="v">${(a.fixed||[]).join(', ') || 'unknown'}</span></div>
       <div class="kv"><span class="k">CVSS</span><span class="v">${(a.cvss||[]).map(c=>c.score).join('<br>') || 'n/a'}</span></div>
       <div class="kv"><span class="k">aliases</span><span class="v">${(a.aliases||[]).join(', ') || 'n/a'}</span></div>
       <div class="kv"><span class="k">published</span><span class="v">${a.published || 'n/a'}</span></div>
       <div class="kv"><span class="k">why</span><span class="v">${a.details ? a.details.slice(0, 500) + (a.details.length > 500 ? '…' : '') : 'n/a'}</span></div>
     </div>`).join('');
  details.innerHTML = `
    <h2>${n.name}</h2>
    <div class="kv"><span class="k">status</span><span class="v">${status}</span></div>
    <div class="kv"><span class="k">version</span><span class="v">${n.version}${n.latest_version && n.latest_version !== n.version ? ' (latest: ' + n.latest_version + ')' : ''}</span></div>
    <div class="kv"><span class="k">ecosystem</span><span class="v">${n.ecosystem}</span></div>
    <div class="kv"><span class="k">dependency</span><span class="v">${n.direct ? 'direct' : 'transitive'}</span></div>
    <div class="kv"><span class="k">license</span><span class="v">${n.license || 'n/a'}</span></div>
    <div class="kv"><span class="k">maintainers</span><span class="v">${(n.maintainers||[]).join(', ') || 'n/a'}</span></div>
    <div class="kv"><span class="k">author</span><span class="v">${n.author || 'n/a'}</span></div>
    <div class="kv"><span class="k">homepage</span><span class="v">${n.homepage || 'n/a'}</span></div>
    <div class="kv"><span class="k">requires python</span><span class="v">${n.requires_python || 'n/a'}</span></div>
    ${vulnLines}${blastLines}${advLines}
    <div class="kv"><span class="k">summary</span><span class="v">${n.summary || 'n/a'}</span></div>`;
  details.style.display = 'block';
});
</script>
</body>
</html>
"""


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 visualize.py <repo_path> [output.html]")
        sys.exit(1)
    repo_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "dependency_graph.html"

    graph = build_graph(repo_path)
    vulnerable = vulnerable_nodes(graph)
    exposed = find_blast_radius(graph, vulnerable)
    vulnerable_ser = {k: sorted(v) for k, v in vulnerable.items()}

    registry = enrich_registry_metadata(graph)
    advisories = enrich_vulnerabilities(graph, vulnerable)
    for key, node in graph["nodes"].items():
        node["maintainers"] = registry.get(NORM(node["name"]), {}).get("maintainers", [])
        node["author"] = registry.get(NORM(node["name"]), {}).get("author", "")
        node["homepage"] = registry.get(NORM(node["name"]), {}).get("homepage", "")
        node["latest_version"] = registry.get(NORM(node["name"]), {}).get("latest_version", "")
        node["advisories"] = advisories.get(key, [])

    html = (HTML_TEMPLATE
            .replace("__REPO__", repo_path)
            .replace("__NODES__", str(len(graph["nodes"])))
            .replace("__EDGES__", str(len(graph["edges"])))
            .replace("__VULN__", str(len(vulnerable)))
            .replace("__GRAPH__", json.dumps(
                {"nodes": list(graph["nodes"].values()),
                 "edges": graph["edges"]}))
            .replace("__VULNERABLE__", json.dumps(vulnerable_ser))
            .replace("__EXPOSED__", json.dumps(exposed)))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Wrote {out_path} ({len(graph['nodes'])} nodes, "
          f"{len(graph['edges'])} edges, {len(vulnerable)} vulnerable)")


if __name__ == "__main__":
    main()