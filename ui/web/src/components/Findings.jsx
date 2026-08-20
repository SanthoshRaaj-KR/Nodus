import { TIERS, TONES, TIER_OF_CONFIDENCE, EDGE_TYPES } from '../lib/tokens';

const TONE_OF_TIER = { P0: 'hot', P1: 'path', P2: 'build', P3: 'clean' };

export default function Findings({ pkg, selected, onSelect, onOpen }) {
  const list = (pkg && pkg.findings) || [];

  if (!list.length) {
    return (
      <div className="card">
        <div className="card-head"><span className="t">findings</span></div>
        <div className="empty">no findings for this target<br />a clean result is a result</div>
      </div>
    );
  }

  return (
    <div className="split">
      <div className="pane">
        <div className="pane-head">
          <span className="t">findings</span>
          <span className="h">tier · entity · evidence chain · action</span>
        </div>

        {list.map((f, i) => {
          const tier = TIER_OF_CONFIDENCE[f.confidence] || 'P3';
          const T = TIERS[tier];
          const tone = TONES[TONE_OF_TIER[tier]];
          const hops = (f.path && f.path.length ? f.path : [f.entity]);
          return (
            <div
              className={`finding${i === selected ? ' on' : ''}`}
              key={`${f.entity}-${i}`}
              onClick={() => onSelect(i)}
            >
              <span className="tier-badge" style={{ color: T.color }}>
                <span className="g">{T.glyph}</span>{tier}
              </span>

              <div style={{ minWidth: 0 }}>
                <div className="pkg">{f.entity}</div>
                <div className="counts">
                  {[f.entity_type, f.status].filter(Boolean).join(' · ')}
                </div>
              </div>

              <div style={{ minWidth: 0 }}>
                <div className="sentence">{f.reason || ''}</div>
                <div className="path">
                  {hops.map((p, j) => (
                    <span key={`${p}-${j}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      <span
                        className="hop"
                        style={{ color: tone.dot, background: tone.bg, borderColor: tone.border }}
                      >
                        {p}
                      </span>
                      {j < hops.length - 1 && <span className="hop-edge">→</span>}
                    </span>
                  ))}
                </div>
              </div>

              <button
                className="open-btn"
                onClick={(ev) => { ev.stopPropagation(); onOpen(f.entity); }}
              >
                open in graph →
              </button>
            </div>
          );
        })}
      </div>

      <div className="side-card">
        <div className="k">tier meaning</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 13 }}>
          {Object.keys(TIERS).map((id) => (
            <div className="tier-def" key={id}>
              <span className="id" style={{ color: TIERS[id].color }}>{TIERS[id].glyph} {id}</span>
              <span className="help">{TIERS[id].help}</span>
            </div>
          ))}
        </div>

        <div className="hr" />

        <div className="k">edge types</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 9, marginTop: 12 }}>
          {EDGE_TYPES.map((e) => (
            <div className="edge-def" key={e.id}>
              <div className="id">{e.id}</div>
              <div className="help">{e.help}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
