import { useMemo, useState } from 'react';
import { TIERS, TONES, EDGE_COLOR, TIER_OF_TONE, WHY, WHY_EDGES, MOD, toneOf } from '../lib/tokens';
import { ATOMS, COLUMN_HELP } from '../lib/explain';

/* The lane renderer.
 *
 * The server already decided which column each node belongs in (`layer`) and
 * whether it is hot (`vuln`, `kind`), so this does no graph reasoning of its
 * own — it lays out what it was handed. That split matters: the argument the
 * graph makes is the engine's, and a renderer that re-derived exposure could
 * disagree with the numbers in the KPI strip directly above it. */

const LANE_W = 244;
const LANE_GAP = 32;
const ROW_H = 62;
//: Room for the lane header *and* its explanation line. The columns are the
//: argument the graph makes, so the space to say what each one means is not
//: optional chrome.
const TOP = 140;

const TAGS = {
  compromised: { text: 'COMPROMISED', bg: 'rgba(179,38,44,0.9)', fg: '#fff' },
  possible:    { text: 'RANGE ONLY',  bg: 'rgba(176,110,26,0.9)', fg: '#fff' },
  resolution:  { text: 'CONFIRMED',   bg: MOD, fg: '#1a1206' },
  exposed:     { text: 'EXPOSED',     bg: MOD, fg: '#1a1206' },
};

function layout(g) {
  const byLayer = {};
  (g.nodes || []).forEach((n) => {
    const l = n.layer ?? 0;
    (byLayer[l] = byLayer[l] || []).push(n);
  });
  const layers = Object.keys(byLayer).map(Number).sort((a, b) => a - b);

  const laneX = {};
  layers.forEach((l, i) => { laneX[l] = 8 + i * (LANE_W + LANE_GAP); });

  const pos = {};
  layers.forEach((l) => byLayer[l].forEach((n, i) => { pos[n.id] = { x: laneX[l], y: TOP + i * ROW_H }; }));

  const width = 8 + layers.length * (LANE_W + LANE_GAP);
  const maxRows = Math.max(...layers.map((l) => byLayer[l].length), 1);
  const height = Math.max(240, TOP + maxRows * ROW_H + 40);

  return { byLayer, layers, laneX, pos, width, height };
}

/* The hover card speaks in the engine's words, not the renderer's.
 *
 * It used to print a generic sentence per colour ("Amber because a traced edge
 * chain connects it…"), which is true of the colour but says nothing about
 * *this* node. Every node already carries its own `verdict`, the atoms that
 * fired, and the witness on disk — so show those, and fall back to the generic
 * gloss only when a node has no verdict of its own. */
function Tooltip({ hover }) {
  if (!hover) return null;
  const { node, tone } = hover;
  const tier = TIER_OF_TONE[tone];
  const T = TIERS[tier];
  const atoms = node.why || [];
  const negs = node.neg || [];

  return (
    <div className="tip" style={{ left: hover.x, top: hover.y }}>
      <div className="r">
        <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: T.color }}>{T.glyph}</span>
        <span className="nm">{node.label}</span>
        <span className="spacer" />
        <span className="tr" style={{ color: T.color }}>{node.conf || tier}</span>
      </div>

      <div className="why">{node.verdict || WHY[tone]}</div>

      {atoms.length > 0 && (
        <>
          <div className="k">because</div>
          {atoms.map((a) => (
            <div className="tip-atom" key={a}>{ATOMS[a] || a}</div>
          ))}
        </>
      )}

      {negs.length > 0 && (
        <>
          <div className="k">but not</div>
          {negs.map((n, i) => <div className="tip-neg" key={i}>{n}</div>)}
        </>
      )}

      <div className="k">edges</div>
      <div className="edges">
        {(WHY_EDGES[tone] || []).map((e) => <span className="e" key={e}>{e}</span>)}
      </div>

      {node.file && <div className="mt">{node.file}</div>}
      <div className="tip-hint">click to pin this detail</div>
    </div>
  );
}

export default function GraphCard({ graph, title, hint, selected, onSelect }) {
  const [hover, setHover] = useState(null);

  const L = useMemo(() => (graph && graph.nodes && graph.nodes.length ? layout(graph) : null), [graph]);

  if (!L) {
    return (
      <div className="card">
        <div className="card-head"><span className="t">{title}</span></div>
        <div className="empty">no graph to draw yet<br />pick a trace target, or run an ingest</div>
      </div>
    );
  }

  const cols = graph.cols || [];
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));

  const edges = (graph.edges || []).map(([a, b], i) => {
    const pa = L.pos[a];
    const pb = L.pos[b];
    if (!pa || !pb) return null;
    const ta = toneOf(nodeById.get(a));
    const tb = toneOf(nodeById.get(b));
    const tone = ta === 'hot' || tb === 'hot' ? 'hot' : tb === 'path' || ta === 'path' ? 'path' : 'clean';
    const x1 = pa.x + LANE_W;
    const y1 = pa.y + 26;
    const x2 = pb.x;
    const y2 = pb.y + 26;
    const c = Math.max(26, (x2 - x1) * 0.5);
    const anim =
      tone === 'clean'
        ? `brDraw 1s ease-out ${(0.12 + i * 0.02).toFixed(2)}s both`
        : `brDraw .9s ease-out ${(0.1 + i * 0.03).toFixed(2)}s both, brFlow 1.5s linear ${(1 + i * 0.03).toFixed(2)}s infinite`;
    return (
      <path
        key={`${a}-${b}-${i}`}
        d={`M${x1},${y1} C${x1 + c},${y1} ${x2 - c},${y2} ${x2},${y2}`}
        fill="none"
        stroke={EDGE_COLOR[tone]}
        strokeWidth={tone === 'clean' ? 1 : 1.6}
        strokeDasharray={tone === 'clean' ? '2 6' : '7 7'}
        strokeLinecap="round"
        style={{ animation: anim }}
      />
    );
  });

  return (
    <div className="card">
      <div className="card-head">
        <span className="t">{title}</span>
        <span className="h">{hint}</span>
        <span className="spacer" />
        <span className="edge-key"><i style={{ background: 'rgba(255,93,93,0.6)' }} />advisory edge</span>
        <span className="edge-key"><i style={{ background: 'rgba(255,177,77,0.75)' }} />confirmed path</span>
        <span className="edge-key"><i style={{ background: 'rgba(255,255,255,0.22)' }} />checked, clear</span>
      </div>

      <div className="graph-scroll">
        <div className="graph-plane" style={{ width: L.width, height: L.height }}>
          <svg width={L.width} height={L.height}>{edges}</svg>

          {L.layers.map((l, i) => {
            const group = L.byLayer[l];
            const anyHot = group.some((n) => toneOf(n) === 'hot');
            const anyPath = group.some((n) => toneOf(n) === 'path');
            const rule = anyHot
              ? 'rgba(255,93,93,0.45)'
              : anyPath
              ? 'rgba(255,177,77,0.45)'
              : 'rgba(72,213,151,0.35)';
            return (
              <div className="lane" key={l} style={{ left: L.laneX[l], width: LANE_W }}>
                <div className="r">
                  <span className="step">{String(i + 1).padStart(2, '0')}</span>
                  <span className="title">{cols[l] || `layer ${l}`}</span>
                </div>
                <div className="count">{group.length} node{group.length === 1 ? '' : 's'}</div>
                {/* What this column is actually claiming. Without it the six
                    headings read as jargon and the graph looks like decoration. */}
                {COLUMN_HELP[cols[l]] && (
                  <div className="lane-help">{COLUMN_HELP[cols[l]]}</div>
                )}
                <div className="rule" style={{ background: rule }} />
              </div>
            );
          })}

          {graph.nodes.map((n, i) => {
            const p = L.pos[n.id];
            if (!p) return null;
            const tone = toneOf(n);
            const T = TONES[tone];
            const delay = 0.06 + i * 0.03;
            const pulse = tone === 'hot' || n.kind === 'compromised';
            const anim =
              `brRise .5s cubic-bezier(.2,.7,.3,1) ${delay.toFixed(2)}s both` +
              (pulse ? `, brPulse 2.6s ease-out ${(delay + 0.7).toFixed(2)}s infinite` : '');
            const tag = TAGS[n.kind];
            return (
              <div
                key={n.id}
                className={`gnode${selected === n.id ? ' sel' : ''}`}
                style={{
                  left: p.x, top: p.y, width: LANE_W,
                  borderColor: T.border, background: T.bg, animation: anim,
                }}
                onMouseEnter={() =>
                  setHover({
                    node: n,
                    tone,
                    x: Math.max(0, Math.min(p.x, L.width - 320)),
                    y: p.y + 62,
                  })
                }
                onMouseLeave={() => setHover(null)}
                /* Every node is inspectable, not just functions: "why is this
                   one here" is the question the whole view exists to answer. */
                onClick={() => onSelect && onSelect(n)}
              >
                <div className="r1">
                  <span className="gl" style={{ color: T.dot }}>{T.glyph}</span>
                  <span className="nm">{n.label}</span>
                </div>
                <div className="r2">
                  <span className="mt">{n.sub || ''}</span>
                  {tag && (
                    <span className="tag" style={{ color: tag.fg, background: tag.bg }}>{tag.text}</span>
                  )}
                </div>
              </div>
            );
          })}

          <Tooltip hover={hover} />
        </div>
      </div>
    </div>
  );
}
