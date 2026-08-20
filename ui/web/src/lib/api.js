/* Empty by default so a same-origin deploy (FastAPI serving this build under
 * /static/app) keeps working unchanged. Set VITE_API_URL at build time only
 * when the UI is hosted separately from the API (e.g. on Vercel). */
const API_BASE = import.meta.env.VITE_API_URL || '';

/* Thin fetch wrapper. FastAPI reports failures as {detail: "..."}, and that
 * string is usually the actual HydraError — worth surfacing verbatim rather
 * than replacing with a generic "request failed", because "node is down" and
 * "no such package" need different reactions from whoever is looking. */
export async function api(path, opts) {
  const r = await fetch(`${API_BASE}${path}`, opts);
  if (!r.ok) {
    let detail = '';
    try {
      detail = (await r.json()).detail || '';
    } catch {
      /* body was not JSON; the status line is all we have */
    }
    throw new Error(detail || `${r.status} ${r.statusText}`);
  }
  return r.json();
}

export const getTargets = (limit = 8) => api(`/api/pkg/targets?limit=${limit}`);
export const getHealth = () => api('/api/health');
export const getProject = () => api('/api/pkg/project');
export const getPackage = (spec) => api(`/api/pkg/graph?spec=${encodeURIComponent(spec)}`);
export const getMicro = () => api('/api/graph?mode=micro');
export const getAdvisories = () => api('/api/advisories');

export const markIncident = (spec) =>
  api(`/api/pkg/incident?spec=${encodeURIComponent(spec)}`, { method: 'POST' });
export const clearIncident = (spec) =>
  api(`/api/pkg/incident?spec=${encodeURIComponent(spec)}`, { method: 'DELETE' });

/* Repository intake. These three are the frontend half only — /api/repos does
 * not exist server-side yet, and the Repos view degrades to localStorage and
 * says so rather than showing a fake queue. */
export const listRepos = () => api('/api/repos');
export const addRepo = (body) =>
  api('/api/repos', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
export const removeRepoRemote = (id) =>
  api(`/api/repos?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
