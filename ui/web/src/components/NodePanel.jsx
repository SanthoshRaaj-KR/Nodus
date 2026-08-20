import { TIERS, TONES, TIER_OF_TONE, toneOf } from '../lib/tokens';
import { explainNode } from '../lib/explain';

/* The "why is this here" panel.
 *
 * Every field shown is the engine's own, not the renderer's paraphrase. The
 * order is deliberate: the verdict first (what we concluded), then the
 * evidence that produced it, then what was checked and did *not* fire, then
 * the witness on disk. Negative evidence is given equal weight because a tool
 * that only ever shows what it found teaches you to distrust the silences. */

export default function NodePanel({ node, onClose, onFocus }) {
  if (!node) {
    return (
      <div className="side-card node-panel">
        <div className="k">node detail</div>
        <div className="empty" style={{ padding: '28px 4px' }}>
          click any node in the graph<br />to see why it is there
        </div>
      </div>
    );
  }

  const e = explainNode(node);
  const tone = toneOf(node);
  const T = TONES[tone];
  const tier = TIERS[TIER_OF_TONE[tone]];
  const focusable = node.pkg && node.version;

  return (
    <div className="side-card node-panel">
      <div className="np-head">
        <span className="gl" style={{ color: T.dot }}>{T.glyph}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="np-title">{e.label}</div>
          <div className="np-sub">{e.sub}</div>
        </div>
        <button className="ghost np-x" onClick={onClose} title="Close">×</button>
      </div>

      {/* The conclusion, in the engine's words. */}
      <div
        className="verdict-box"
        style={{ borderColor: T.border, background: T.bg }}
      >
        <div className="t" style={{ color: T.dot }}>{e.verdict || 'No verdict recorded'}</div>
        <div className="np-chips">
          {e.confidence && (
            <span className="np-chip" style={{ color: tier.color, borderColor: T.border }}>
              confidence {e.confidence}
            </span>
          )}
          {e.severity && <span className="np-chip">{e.severity}</span>}
          {e.depth != null && <span className="np-chip">depth {e.depth}</span>}
        </div>
      </div>

      {/* Why it fired. */}
      {e.why.length > 0 && (
        <>
          <div className="k np-k">evidence that fired</div>
          {e.why.map((w) => (
            <div className="np-atom" key={w.atom}>
              <div className="np-atom-id">{w.atom}</div>
              <div className="np-atom-text">{w.text}</div>
            </div>
          ))}
        </>
      )}

      {/* What was checked and did not fire. Equal billing on purpose. */}
      {e.negative.length > 0 && (
        <>
          <div className="k np-k">checked, did not fire</div>
          {e.negative.map((n, i) => (
            <div className="np-neg" key={i}>{n}</div>
          ))}
        </>
      )}

      {(e.detail || e.witness || e.advisory) && (
        <>
          <div className="k np-k">the receipt</div>
          {e.advisory && (
            <div className="meta-row"><span className="k">advisory</span><span className="v">{e.advisory}</span></div>
          )}
          {e.detail && (
            <div className="meta-row"><span className="k">detail</span><span className="v">{e.detail}</span></div>
          )}
          {e.witness && (
            <div className="meta-row"><span className="k">witness</span><span className="v">{e.witness}</span></div>
          )}
          {e.source && e.source !== e.label && (
            <div className="meta-row"><span className="k">from</span><span className="v">{e.source}</span></div>
          )}
        </>
      )}

      {focusable && (
        <button className="open-btn np-focus" onClick={() => onFocus(`${node.pkg}@${node.version}`)}>
          trace {node.pkg}@{node.version} →
        </button>
      )}
    </div>
  );
}
