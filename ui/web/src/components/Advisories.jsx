import { G, HIGH, MOD } from '../lib/tokens';

export default function Advisories({ advisories, onPick }) {
  if (!advisories.length) {
    return (
      <div className="card">
        <div className="card-head"><span className="t">advisories</span></div>
        <div className="empty">no advisories loaded</div>
      </div>
    );
  }

  return (
    <div className="split">
      <div className="pane">
        <div className="adv-head">
          <span>identifier</span>
          <span>severity</span>
          <span>package · range</span>
          <span style={{ textAlign: 'right' }}>source</span>
        </div>

        {advisories.map((a) => {
          const hi = (a.severity || '').toUpperCase() === 'HIGH';
          return (
            <div className="adv-grid" key={a.advisory_id + a.package}>
              {/* The identifier is the handle: clicking it focuses the version
                  the advisory actually points at, so the next question --
                  "did any lockfile resolve it?" -- is one click away. */}
              <button className="id" onClick={() => onPick(a.query || a.package)}>
                {a.advisory_id}
              </button>
              <span className="sev" style={{ color: hi ? HIGH : MOD }}>
                <span className="g">{hi ? G.p0 : G.p1}</span>
                {a.severity || '—'}
              </span>
              <span className="vec">
                {a.package}{a.range ? ` · ${a.range}` : ''}
              </span>
              <span className="fix">{a.source || ''}</span>
            </div>
          );
        })}
      </div>

      <div className="side-card">
        <div className="k">what these are</div>
        <div className="note" style={{ marginTop: 12 }}>
          Published advisories loaded into the graph from the OSV scan. Clicking an identifier
          focuses the affected version so you can see whether any lockfile actually resolved it —
          an advisory existing is not the same as you being exposed.
        </div>
      </div>
    </div>
  );
}
