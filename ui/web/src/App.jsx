import { useCallback, useEffect, useMemo, useState } from 'react';
import * as API from './lib/api';
import { TITLES, specOf } from './lib/tokens';

import Sidebar from './components/Sidebar';
import Header from './components/Header';
import { Story, Kpis } from './components/Summary';
import GraphCard from './components/GraphCard';
import Findings from './components/Findings';
import Advisories from './components/Advisories';
import Stages from './components/Stages';
import Inspector from './components/Inspector';
import Repos, { parseRepo } from './components/Repos';
import NodePanel from './components/NodePanel';

const REPO_KEY = 'br.repos.pending';

export default function App() {
  /* Lands on `supply`, not `overview`, and the reason is latency: the project
   * view is several unpinned whole-graph sweeps plus a BFS (~2.6s cold against
   * the fleet corpus), where a single package query is one hop over the
   * precomputed closure (~76ms). Overview is still the first nav item, so it
   * stays discoverable -- it just is not what a cold open pays for. */
  const [view, setView] = useState('supply');
  const [target, setTarget] = useState(null);
  const [targets, setTargets] = useState([]);

  const [project, setProject] = useState(null);
  const [pkg, setPkg] = useState(null);
  const [micro, setMicro] = useState(null);
  const [advisories, setAdvisories] = useState([]);

  const [findingIdx, setFindingIdx] = useState(0);
  const [selected, setSelected] = useState(null);
  const [marked, setMarked] = useState(() => new Set());

  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const [repos, setRepos] = useState([]);
  const [repoMsg, setRepoMsg] = useState(null);

  /* ------------------------------------------------------------------ boot */
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const [list, health] = await Promise.all([
          API.getTargets(8).catch(() => []),
          API.getHealth().catch(() => null),
        ]);
        if (!alive) return;
        setTargets(list || []);

        const q = new URLSearchParams(window.location.search);
        const urlTarget = q.get('target');
        const urlView = q.get('view');
        setTarget(urlTarget || (list && list.length ? specOf(list[0]) : null));
        if (urlView && TITLES[urlView]) setView(urlView);

        if (health && health.empty) {
          setError('The graph is empty. Run:  python -m blastradius.cli pipeline corpus --reset');
        }
      } catch (e) {
        if (alive) setError(e.message);
      }
    })();
    return () => { alive = false; };
  }, []);

  /* Local entries are a stand-in; if the backend answers, it is the truth. */
  useEffect(() => {
    try { setRepos(JSON.parse(localStorage.getItem(REPO_KEY) || '[]')); } catch { /* none yet */ }
    API.listRepos()
      .then((list) => { if (Array.isArray(list)) setRepos(list); })
      .catch(() => { /* endpoint not built yet — localStorage stands in */ });
  }, []);

  useEffect(() => {
    try { localStorage.setItem(REPO_KEY, JSON.stringify(repos)); } catch { /* private mode */ }
  }, [repos]);

  /* --------------------------------------------------------------- loading
     Each payload is fetched once and kept, so switching tabs does not re-hit
     the node for data already in hand. Marking an incident clears them. */
  useEffect(() => {
    let alive = true;
    (async () => {
      setLoading(true);
      try {
        if (view === 'overview' && !project) {
          const p = await API.getProject();
          if (alive) setProject(p);
        }
        if ((view === 'supply' || view === 'findings') && target && !pkg) {
          const p = await API.getPackage(target);
          if (alive) setPkg(p);
        }
        if (view === 'code' && !micro) {
          const m = await API.getMicro();
          if (alive) setMicro(m);
        }
        if (view === 'advisories' && !advisories.length) {
          const a = await API.getAdvisories();
          if (alive) setAdvisories(a);
        }
        if (alive) setError(null);
      } catch (e) {
        if (alive) setError(e.message);
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => { alive = false; };
  }, [view, target, project, pkg, micro, advisories.length]);

  /* ---------------------------------------------------------------- naving */
  const syncUrl = useCallback((v, t) => {
    try {
      const q = new URLSearchParams();
      q.set('view', v);
      if (t) q.set('target', t);
      window.history.replaceState(null, '', `?${q}`);
    } catch { /* file:// or a locked-down embed */ }
  }, []);

  const go = useCallback((v) => { setView(v); syncUrl(v, target); }, [target, syncUrl]);

  const pick = useCallback((spec) => {
    setTarget(spec);
    setPkg(null);
    setFindingIdx(0);
    setSelected(null);   // the pinned node belonged to the previous graph
    const next = view === 'findings' ? 'findings' : 'supply';
    setView(next);
    syncUrl(next, spec);
  }, [view, syncUrl]);

  /* ------------------------------------------------------ simulate/retract */
  const onMark = useCallback(async () => {
    if (!target) return;
    setBusy(true);
    try {
      if (marked.has(target)) {
        await API.clearIncident(target);
        setMarked((m) => { const n = new Set(m); n.delete(target); return n; });
      } else {
        await API.markIncident(target);
        setMarked((m) => new Set(m).add(target));
      }
      setPkg(null);      // the graph changed underneath us
      setProject(null);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }, [target, marked]);

  /* ------------------------------------------------------------ repo intake */
  const submitRepo = useCallback(async (raw, clear) => {
    const p = parseRepo(raw);
    if (p.error) { setRepoMsg({ kind: 'err', text: p.error }); return; }
    if (repos.some((r) => r.url.toLowerCase() === p.url.toLowerCase())) {
      setRepoMsg({ kind: 'err', text: 'That repository is already in the queue.' });
      return;
    }

    setRepoMsg({ kind: 'wait', text: `submitting ${p.owner}/${p.name}…` });
    const entry = {
      id: `local-${Date.now()}`,
      url: p.url, owner: p.owner, name: p.name,
      status: 'queued', submitted_at: new Date().toISOString(), local: true,
    };

    try {
      const saved = await API.addRepo({ url: p.url, owner: p.owner, name: p.name });
      setRepos((r) => [{ ...entry, ...saved, local: false }, ...r]);
      setRepoMsg({ kind: 'ok', text: `queued ${p.owner}/${p.name} for scanning` });
    } catch {
      /* No backend yet — say so rather than showing a fake success. */
      setRepos((r) => [entry, ...r]);
      setRepoMsg({
        kind: 'ok',
        text: `saved ${p.owner}/${p.name} locally · backend endpoint /api/repos not live yet`,
      });
    }
    clear();
  }, [repos]);

  const removeRepo = useCallback((id) => {
    setRepos((r) => r.filter((x) => x.id !== id));
    API.removeRepoRemote(id).catch(() => { /* nothing remote to remove yet */ });
    setRepoMsg(null);
  }, []);

  /* ----------------------------------------------------------------- chrome */
  const counts = useMemo(() => ({
    findings: pkg?.findings?.length || '',
    supply: pkg?.nodes?.length || '',
    code: micro?.nodes?.length || '',
    advisories: advisories.length || '',
    repos: repos.length || '',
  }), [pkg, micro, advisories.length, repos.length]);

  const foot = useMemo(() => {
    const g = pkg || project;
    const ms = g?.stats?.query_ms != null ? `${g.stats.query_ms} ms` : '—';
    const ex = g?.exposure ? `${g.exposure.exposed || 0} of ${g.exposure.total || 0} in radius` : '';
    return { line1: `scan complete · ${ms}`, line2: ex };
  }, [pkg, project]);

  const summary = { view, loading, project, pkg, micro, advisories, repos };

  /* ------------------------------------------------------------------ body */
  let content;
  if (error && !loading) {
    content = <div className="banner">{error}</div>;
  } else if (loading) {
    content = (
      <div className="card">
        <div className="empty"><span className="spinner" />  querying HydraDB…</div>
      </div>
    );
  } else {
    content = (
      <>
        {view === 'overview' && (
          <div className="graph-with-panel">
            <div className="gwp-main">
              <GraphCard graph={project} title="supply-chain propagation"
                hint="click any node to see why it is there"
                selected={selected?.id} onSelect={setSelected} />
            </div>
            <NodePanel node={selected} onClose={() => setSelected(null)} onFocus={pick} />
          </div>
        )}
        {view === 'supply' && (
          <>
            <div className="graph-with-panel">
              <div className="gwp-main">
                <GraphCard graph={pkg} title="supply-chain propagation"
                  hint="click any node to see why it is there"
                  selected={selected?.id} onSelect={setSelected} />
              </div>
              <NodePanel node={selected} onClose={() => setSelected(null)} onFocus={pick} />
            </div>
            <Stages pkg={pkg} />
          </>
        )}
        {view === 'code' && (
          <>
            <GraphCard graph={micro} title="call graph · code reach"
              hint="click to inspect · hover for the reason it is flagged"
              selected={selected?.id} onSelect={setSelected} />
            <Inspector micro={micro} selected={selected?.label} />
          </>
        )}
        {view === 'findings' && (
          <Findings pkg={pkg} selected={findingIdx} onSelect={setFindingIdx} onOpen={pick} />
        )}
        {view === 'advisories' && <Advisories advisories={advisories} onPick={pick} />}
        {view === 'repos' && (
          <Repos repos={repos} message={repoMsg} onSubmit={submitRepo} onRemove={removeRepo} />
        )}
      </>
    );
  }

  return (
    <div className="shell">
      <Sidebar
        view={view} targets={targets} target={target} counts={counts} foot={foot}
        onGo={go} onPick={pick}
      />
      <main>
        <Header view={view} target={target} marked={marked} busy={busy} onMark={onMark} />
        <div className="body">
          <Story {...summary} />
          <Kpis {...summary} />
          {content}
        </div>
      </main>
    </div>
  );
}
