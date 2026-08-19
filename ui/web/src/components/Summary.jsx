import { TIERS, HIGH, MOD, WARN, SAFE } from '../lib/tokens';

/* The story banner and the KPI strip are one unit: the banner states the
 * conclusion in a sentence, the strip shows the numbers it rests on. They are
 * derived from the same payload and always render together, so they live in
 * one file rather than duplicating the same `which view am I` switch twice. */

const NEUTRAL = '#cfd2de';

export function storyData({ view, loading, project, pkg, micro, advisories, repos }) {
  if (loading) {
    return { tier: 'P3', sentence: 'Querying the graph…', sub: 'one hop over the precomputed closure' };
  }

  if (view === 'repos') {
    return {
      tier: 'P3',
      sentence:
        'Submit a public GitHub repository and it is queued for lockfile resolution, OSV scanning, and blast-radius ingest.',
      sub: `${repos.length} repository(ies) submitted · nothing is cloned or executed from the browser`,
    };
  }

  if (view === 'advisories') {
    const hi = advisories.filter((a) => (a.severity || '').toUpperCase() === 'HIGH').length;
    return {
      tier: hi ? 'P0' : 'P3',
      sentence: advisories.length
        ? `${advisories.length} advisories are filed against packages present in this graph.`
        : 'No advisories are loaded for this graph.',
      sub: `${hi} high · ${advisories.length - hi} other`,
    };
  }

  if (view === 'code' && micro) {
    return {
      tier: 'P3',
      sentence: 'Call-graph reach from application entry points through to external package imports.',
      sub: `${(micro.nodes || []).length} nodes traced`,
    };
  }

  const g = view === 'overview' ? project : pkg;
  if (g && g.verdict) {
    const v = g.verdict;
    const tier = v.compromised ? 'P0' : v.level && v.level !== 'clean' ? 'P1' : 'P3';
    return {
      tier,
      sentence: [v.headline, v.reach].filter(Boolean).join(' — ') || 'No known vulnerabilities.',
      sub:
        (g.target ? `focus ${g.target} · ` : '') +
        ((g.stats || {}).query_ms != null ? `${g.stats.query_ms} ms` : ''),
    };
  }

  return { tier: 'P3', sentence: 'Pick a trace target to run a blast-radius query.', sub: 'nothing marked yet' };
}

export function Story(props) {
  const d = storyData(props);
  const t = TIERS[d.tier] || TIERS.P3;
  return (
    <div className={`story${d.tier === 'P0' ? ' p0' : ''}`}>
      <span className="badge" style={{ color: t.color }}>
        <span className="g">{t.glyph}</span>
        {d.tier}
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className="sentence">{d.sentence}</div>
        <div className="sub">{d.sub}</div>
      </div>
    </div>
  );
}

function kpiItems({ view, project, pkg, micro, advisories, repos }) {
  if (view === 'overview' && project) {
    const s = project.stats || {};
    return [
      { label: 'Vulnerable versions', value: s.vulnerable_versions ?? 0, unit: 'seeds', color: s.vulnerable_versions ? HIGH : SAFE },
      { label: 'In radius', value: s.in_radius ?? 0, unit: 'nodes', color: s.in_radius ? MOD : SAFE },
      { label: 'Resolved versions', value: s.resolved_versions ?? 0, unit: 'lockfile', color: NEUTRAL },
      { label: 'Drawn', value: s.drawn ?? 0, unit: 'nodes', color: NEUTRAL },
      { label: 'Answered in', value: s.query_ms ?? '—', unit: 'ms', color: NEUTRAL },
    ];
  }

  if ((view === 'supply' || view === 'findings') && pkg) {
    const s = pkg.stats || {};
    return [
      { label: 'Advisories', value: s.advisories ?? 0, unit: 'filed', color: s.advisories ? HIGH : SAFE },
      { label: 'Range admits it', value: s.range_admits ?? 0, unit: 'range-only leads', color: s.range_admits ? WARN : SAFE },
      { label: 'Lockfile resolves it', value: s.lockfile_entries ?? 0, unit: 'confirmed', color: s.lockfile_entries ? MOD : SAFE },
      { label: 'Exposed projects', value: s.exposed_projects ?? 0, unit: 'projects', color: s.exposed_projects ? MOD : SAFE },
      { label: 'Related by identity', value: s.related ?? 0, unit: 'identity only', color: s.related ? WARN : SAFE },
      { label: 'Answered in', value: s.query_ms ?? '—', unit: 'ms', color: NEUTRAL },
    ];
  }

  if (view === 'code' && micro) {
    const n = micro.nodes || [];
    const imports = n.filter((x) => x.kind === 'import').length;
    const routes = n.filter((x) => x.kind === 'route').length;
    return [
      { label: 'Nodes traced', value: n.length, unit: 'total', color: NEUTRAL },
      { label: 'External imports', value: imports, unit: 'packages', color: imports ? MOD : SAFE },
      { label: 'HTTP routes', value: routes, unit: 'entry points', color: routes ? MOD : SAFE },
      { label: 'Edges', value: (micro.edges || []).length, unit: 'calls', color: NEUTRAL },
    ];
  }

  if (view === 'advisories') {
    const hi = advisories.filter((a) => (a.severity || '').toUpperCase() === 'HIGH').length;
    return [
      { label: 'High severity', value: hi, unit: 'advisories', color: hi ? HIGH : SAFE },
      { label: 'Other', value: advisories.length - hi, unit: 'advisories', color: MOD },
      { label: 'Total', value: advisories.length, unit: 'in graph', color: NEUTRAL },
    ];
  }

  if (view === 'repos') {
    const queued = repos.filter((r) => r.status === 'queued').length;
    const scanned = repos.filter((r) => r.status === 'scanned').length;
    return [
      { label: 'Submitted', value: repos.length, unit: 'repos', color: NEUTRAL },
      { label: 'Queued', value: queued, unit: 'awaiting scan', color: queued ? MOD : SAFE },
      { label: 'Scanned', value: scanned, unit: 'ingested', color: scanned ? SAFE : NEUTRAL },
    ];
  }

  return [];
}

export function Kpis(props) {
  const items = kpiItems(props);
  if (!items.length) return null;
  return (
    <div className="kpis">
      {items.map((k) => (
        <div className="kpi" key={k.label}>
          <div className="lbl">{k.label}</div>
          <div className="val">
            <span className="v" style={{ color: k.color }}>{k.value}</span>
            <span className="u">{k.unit}</span>
          </div>
        </div>
      ))}
    </div>
  );
}
