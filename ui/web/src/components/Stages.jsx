import { G, HIGH, MOD, WARN, SAFE } from '../lib/tokens';

/* The proof chain: the six questions the engine asks, each with its own
 * answer and its own witness. "Clear" is rendered as a positive green result
 * rather than a blank, because a check that ran and found nothing is evidence,
 * and a blank row reads as a check that failed to run. */

function state(count, onColor, onBg, onGlyph, clearText = 'clear') {
  return count
    ? { status: String(count), fg: onColor, bg: onBg, g: onGlyph }
    : { status: clearText, fg: SAFE, bg: 'rgba(72,213,151,0.1)', g: G.p3 };
}

export default function Stages({ pkg }) {
  if (!pkg || !pkg.stats) return null;
  const s = pkg.stats;

  const rows = [
    ['01', 'Threat', state(s.advisories, HIGH, 'rgba(255,93,93,0.1)', G.p0, 'none'),
      'Published advisories and simulated incidents filed against this version.'],
    ['02', 'Compromised version',
      pkg.compromised
        ? { status: '1 match', fg: MOD, bg: 'rgba(255,177,77,0.1)', g: G.p1 }
        : { status: 'clear', fg: SAFE, bg: 'rgba(72,213,151,0.1)', g: G.p3 },
      'The exact release the threat points at. Marking 4.17.21 never touches 4.17.20.'],
    ['03', 'Range admits it', state(s.range_admits, WARN, 'rgba(242,208,90,0.1)', G.p2),
      'Declared ranges that provably admit it. A lead, not a finding — this is what a range-only tool would report in full.'],
    ['04', 'Lockfile resolves it', state(s.lockfile_entries, MOD, 'rgba(255,177,77,0.1)', G.p1),
      'A lockfile actually selected this version. This is the confirmed claim.'],
    ['05', 'Exposed projects', state(s.exposed_projects, MOD, 'rgba(255,177,77,0.1)', G.p1),
      'One hop over the precomputed RESOLVED_IN closure — no live traversal.'],
    ['06', 'Related by identity', state(s.related, WARN, 'rgba(242,208,90,0.1)', G.p2),
      'Shared maintainer, repository, publisher, or a typosquat neighbour. Never a verdict on its own.'],
  ];

  return (
    <div className="card">
      <div className="card-head">
        <span className="t">proof chain · six checks</span>
        <span className="h">each row is one graph question with its own witness</span>
      </div>
      {rows.map(([step, title, st, blurb]) => (
        <div className="stage" key={step}>
          <span className="step">{step}</span>
          <span className="title">{title}</span>
          <span className="status" style={{ color: st.fg, background: st.bg }}>
            <span className="g">{st.g}</span>{st.status}
          </span>
          <span className="blurb">{blurb}</span>
        </div>
      ))}
    </div>
  );
}
