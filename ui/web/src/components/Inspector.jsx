import { G, MOD, SAFE } from '../lib/tokens';

/* The code view's right rail: what is *not* reachable on the left, and the
 * selected node on the right. Zero routes is stated out loud as a finding
 * ("nothing is exploitable from outside") rather than left as an empty panel. */

export default function Inspector({ micro, selected }) {
  if (!micro) return null;

  const nodes = micro.nodes || [];
  const node = nodes.find((x) => x.label === selected);
  const routes = nodes.filter((x) => x.kind === 'route').length;
  const handlers = nodes.filter((x) => x.kind === 'handler').length;
  const onPath = node ? !!node.vuln : false;

  return (
    <div className="split">
      <div className="side-card" style={{ flex: '1 1 380px', maxWidth: 'none' }}>
        <div className="k">unreached surface</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 13 }}>
          <div className="clear-box">
            <div className="t">HTTP routes · {routes}</div>
            <div className="n">
              {routes
                ? 'Network-facing routes exist; check which resolve to a flagged import.'
                : 'No network-facing routes in this project, so nothing is exploitable from outside.'}
            </div>
          </div>
          <div className="clear-box">
            <div className="t">Handlers · {handlers} nodes</div>
            <div className="n">
              {handlers
                ? 'Handlers bind to routes; the call graph shows what they reach.'
                : 'No route or event handlers bind to a flagged package.'}
            </div>
          </div>
        </div>
      </div>

      <div className="side-card" style={{ flex: '1 1 320px', maxWidth: 400 }}>
        {node ? (
          <>
            <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
              <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: onPath ? MOD : SAFE }}>
                {onPath ? G.p1 : G.p3}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 14, color: 'var(--fg)', wordBreak: 'break-all' }}>
                  {node.label}
                </div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--mut-3)', marginTop: 4 }}>
                  {node.kind || ''}
                </div>
              </div>
            </div>

            <div
              className="verdict-box"
              style={{
                borderColor: onPath ? 'rgba(255,177,77,0.32)' : 'rgba(72,213,151,0.28)',
                background: onPath ? 'rgba(255,177,77,0.08)' : 'rgba(72,213,151,0.07)',
              }}
            >
              <div className="t" style={{ color: onPath ? '#ffc478' : '#6fe0af' }}>
                {onPath ? 'A flagged import is reachable here' : 'No advisory reaches this node'}
              </div>
              <div className="n">
                {onPath
                  ? 'This node calls through to a package with an open advisory. Re-check it after the upgrade.'
                  : 'Nothing on this call path imports a package with an open advisory.'}
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', marginTop: 8 }}>
              {[['id', node.id], ['type', node.kind || ''], ['label', node.label], ['detail', node.sub || '—']].map(
                ([k, v]) => (
                  <div className="meta-row" key={k}>
                    <span className="k">{k}</span>
                    <span className="v">{String(v)}</span>
                  </div>
                )
              )}
            </div>
          </>
        ) : (
          <>
            <div className="k">inspector</div>
            <div className="empty" style={{ padding: '28px 4px' }}>
              click a node in the call graph<br />to inspect it
            </div>
          </>
        )}
      </div>
    </div>
  );
}
