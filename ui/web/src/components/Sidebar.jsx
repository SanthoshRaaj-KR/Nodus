import { NAV, TIERS, specOf } from '../lib/tokens';

/* Tier shown against a suggested target, from what the corpus can say about
 * it: something a lockfile resolved outranks something only a range admits.
 * This is a display hint for ranking the list, not a verdict — the verdict
 * comes from the engine once the target is actually queried. */
function targetTier(t) {
  if (t.exposed_projects > 0 || t.projects > 0) return 'P0';
  if (t.range_admits > 0) return 'P2';
  return 'P3';
}

function targetMeta(t) {
  const parts = [];
  if (t.range_admits != null) parts.push(`${t.range_admits} admit`);
  const installed = t.projects != null ? t.projects : t.exposed_projects;
  if (installed != null) parts.push(`${installed} installed`);
  return parts.join(' · ') || 'no resolution data';
}

export default function Sidebar({ view, targets, target, counts, foot, onGo, onPick }) {
  return (
    <aside>
      <div className="brand-box">
        <div className="brand">Blast Radius</div>
        <div className="brand-sub">console · v2.4</div>
      </div>

      <nav>
        {NAV.map(([id, label, glyph]) => (
          <button
            key={id}
            className={`nav-btn${view === id ? ' on' : ''}`}
            onClick={() => onGo(id)}
          >
            <span className="g">{glyph}</span>
            <span className="lbl">{label}</span>
            <span className="n">{counts[id] || ''}</span>
          </button>
        ))}
      </nav>

      <div className="side-head">trace targets</div>
      <div className="targets">
        {targets.length === 0 ? (
          <div className="empty" style={{ padding: '18px 6px' }}>no targets yet</div>
        ) : (
          targets.map((t) => {
            const spec = specOf(t);
            const tier = TIERS[targetTier(t)];
            return (
              <button
                key={spec}
                className={`tgt${spec === target ? ' on' : ''}`}
                onClick={() => onPick(spec)}
              >
                <div className="row">
                  <span className="gl" style={{ color: tier.color }}>{tier.glyph}</span>
                  <span className="nm">{spec}</span>
                </div>
                <div className="mt">{targetMeta(t)}</div>
              </button>
            );
          })
        )}
      </div>

      <div className="side-foot">
        <div>{foot.line1}</div>
        <div>{foot.line2 || ' '}</div>
      </div>
    </aside>
  );
}
