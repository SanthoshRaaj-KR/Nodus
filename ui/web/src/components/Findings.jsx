import { TIERS, TONES, TIER_OF_CONFIDENCE, EDGE_TYPES } from '../lib/tokens';
import { ATOMS } from '../lib/explain';

const TONE_OF_TIER = { P0: 'hot', P1: 'path', P2: 'build', P3: 'clean' };

/* Which package version this finding can be traced to.
 *
 * This was the "open in graph" bug: the button passed `finding.entity`
 * straight to the package lookup, but for a Project finding the entity is a
 * service name ("legacy-pinned-older"), which is not a package spec and can
 * never resolve. The package is in the finding's own path -- it is the hop
 * that carries an @ -- so trace that instead, and when there is no such hop,
 * do not offer a button that cannot work. */
export function focusSpecOf(f) {
  if (!f) return null;
  if (f.entity_type === 'PackageVersion' && f.entity.includes('@')) return f.entity;
  const hop = (f.path || []).find((p) => typeof p === 'string' && p.includes('@'));
  return hop || null;
}

export default function Findings({ pkg, selected, onSelect, onOpen }) {
  const list = (pkg && pkg.findings) || [];

  if (!list.length) {
    return (
      <div className="card">
        <div className="card-head"><span className="t">findings</span></div>
        <div className="empty">
          no findings for this target<br />a clean result is a result
        </div>
      </div>
    );
  }

  const active = list[selected] || list[0];
  const activeAtoms = (active.atoms || []).map((a) => ({ atom: a, text: ATOMS[a] || a }));

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
          const hops = f.path && f.path.length ? f.path : [f.entity];
          const spec = focusSpecOf(f);

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

              {/* Only offered when there is a package to actually trace. */}
              {spec ? (
                <button
                  className="open-btn"
                  onClick={(ev) => { ev.stopPropagation(); onOpen(spec); }}
                  title={`Focus ${spec} in the supply-chain graph`}
                >
                  trace {spec.split('@')[0]} →
                </button>
              ) : (
                <span className="open-none" title="No package version on this finding's path to trace">
                  —
                </span>
              )}
            </div>
          );
        })}
      </div>

      <div className="side-card">
        {/* Why the selected row says what it says. */}
        <div className="k">why this finding</div>
        <div className="fx-reason">{active.reason || '—'}</div>

        {activeAtoms.length > 0 && (
          <>
            <div className="k np-k">evidence that fired</div>
            {activeAtoms.map((w) => (
              <div className="np-atom" key={w.atom}>
                <div className="np-atom-id">{w.atom}</div>
                <div className="np-atom-text">{w.text}</div>
              </div>
            ))}
          </>
        )}

        {(active.negative_evidence || []).length > 0 && (
          <>
            <div className="k np-k">checked, did not fire</div>
            {active.negative_evidence.map((n, i) => (
              <div className="np-neg" key={i}>{n}</div>
            ))}
          </>
        )}

        <div className="hr" />

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
