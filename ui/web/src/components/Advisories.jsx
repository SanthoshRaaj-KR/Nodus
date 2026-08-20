import { useState } from 'react';
import { G, HIGH, MOD, WARN, SAFE } from '../lib/tokens';
import { decodeCvss, cvssHeadline, fmtDate, SEVERITY_ORDER } from '../lib/explain';

/* Advisories, with what the advisory actually says.
 *
 * The previous version listed an identifier and a severity word, which names a
 * finding without explaining it: "CVE-2020-28500, moderate" tells a reader
 * nothing about what breaks, how reachable it is, or what to upgrade to. The
 * OSV scan already wrote the summary, the CVSS vector, the fixed versions and
 * the references to disk -- this shows them. */

const SEV_COLOR = { critical: HIGH, high: HIGH, moderate: MOD, medium: MOD, low: WARN };
const SEV_GLYPH = { critical: G.p0, high: G.p0, moderate: G.p1, medium: G.p1, low: G.p2 };

function sevColor(s) { return SEV_COLOR[(s || '').toLowerCase()] || SAFE; }
function sevGlyph(s) { return SEV_GLYPH[(s || '').toLowerCase()] || G.p3; }

function Row({ a, open, onToggle, onPick }) {
  const color = sevColor(a.severity);
  const metrics = decodeCvss(a.cvss_vector);
  const headline = cvssHeadline(a.cvss_vector);
  const fixed = (a.fixed_versions || [])[0];

  return (
    <div className={`adv${open ? ' open' : ''}`}>
      <div className="adv-row" onClick={onToggle}>
        <span className="adv-caret">{open ? '▾' : '▸'}</span>

        <div className="adv-main">
          <div className="adv-id-line">
            <span className="adv-id">{a.advisory_id}</span>
            <span className="adv-sev" style={{ color }}>
              <span className="g">{sevGlyph(a.severity)}</span>{(a.severity || 'unknown').toUpperCase()}
            </span>
          </div>
          {/* The one line that was missing: what this vulnerability actually is. */}
          <div className="adv-summary">{a.summary || 'No summary published for this advisory.'}</div>
        </div>

        <div className="adv-pkg">
          <div className="adv-pkg-name">{a.package}</div>
          <div className="adv-pkg-sub">
            {(a.affected_versions || []).length
              ? `affects ${a.affected_versions.join(', ')}`
              : a.range || 'range unspecified'}
          </div>
        </div>

        <div className="adv-fix">
          {fixed
            ? <span className="pill">fixed in {fixed}</span>
            : <span className="adv-nofix">no fix published</span>}
        </div>
      </div>

      {open && (
        <div className="adv-body">
          {headline && (
            <div className="adv-headline" style={{ color }}>{headline}</div>
          )}

          {metrics.length > 0 && (
            <>
              <div className="k adv-k">CVSS breakdown</div>
              <div className="cvss-grid">
                {metrics.map((m) => (
                  <div className="cvss-cell" key={m.key}>
                    <div className="cvss-lbl">{m.label}</div>
                    <div className="cvss-val">{m.value}</div>
                  </div>
                ))}
              </div>
              <div className="adv-vector">{a.cvss_vector}</div>
            </>
          )}

          <div className="adv-facts">
            {(a.fixed_versions || []).length > 0 && (
              <div className="meta-row">
                <span className="k">safe versions</span>
                <span className="v">{a.fixed_versions.join(', ')}</span>
              </div>
            )}
            {a.published_at ? (
              <div className="meta-row">
                <span className="k">published</span>
                <span className="v">{fmtDate(a.published_at)}</span>
              </div>
            ) : null}
            {(a.aliases || []).length > 0 && (
              <div className="meta-row">
                <span className="k">aliases</span>
                <span className="v">{a.aliases.join(', ')}</span>
              </div>
            )}
            <div className="meta-row">
              <span className="k">source</span>
              <span className="v">{a.source || 'unknown'}</span>
            </div>
          </div>

          <div className="adv-actions">
            <button className="open-btn" onClick={(ev) => { ev.stopPropagation(); onPick(a.query || a.package); }}>
              trace {a.query || a.package} in the graph →
            </button>
            {(a.references || []).slice(0, 1).map((r) => (
              <a className="ghost adv-link" key={r} href={r} target="_blank" rel="noreferrer noopener"
                 onClick={(ev) => ev.stopPropagation()}>
                read the advisory ↗
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function Advisories({ advisories, onPick }) {
  const [open, setOpen] = useState(null);

  if (!advisories.length) {
    return (
      <div className="card">
        <div className="card-head"><span className="t">advisories</span></div>
        <div className="empty">no advisories loaded<br />run: python -m blastradius.cli osv-scan</div>
      </div>
    );
  }

  const sorted = [...advisories].sort((a, b) => {
    const sa = SEVERITY_ORDER[(a.severity || '').toLowerCase()] ?? 9;
    const sb = SEVERITY_ORDER[(b.severity || '').toLowerCase()] ?? 9;
    return sa - sb || a.advisory_id.localeCompare(b.advisory_id);
  });

  return (
    <div className="split">
      <div className="pane">
        <div className="pane-head">
          <span className="t">advisories</span>
          <span className="h">worst first · click a row for the full detail</span>
        </div>
        {sorted.map((a) => (
          <Row
            key={a.advisory_id + a.package}
            a={a}
            open={open === a.advisory_id + a.package}
            onToggle={() => setOpen(open === a.advisory_id + a.package ? null : a.advisory_id + a.package)}
            onPick={onPick}
          />
        ))}
      </div>

      <div className="side-card">
        <div className="k">reading these</div>
        <div className="note" style={{ marginTop: 12 }}>
          An advisory existing is <strong>not</strong> the same as you being exposed. These are
          published facts about a package; whether any lockfile in your fleet actually resolved an
          affected version is a separate question, and the one that decides whether you act.
        </div>
        <div className="hr" />
        <div className="k">severity vs reachability</div>
        <div className="note" style={{ marginTop: 12 }}>
          The CVSS breakdown says how bad it is <em>if reached</em>. The graph says whether it is
          reached here. A critical CVE in a package nothing resolves outranks nothing.
        </div>
      </div>
    </div>
  );
}
