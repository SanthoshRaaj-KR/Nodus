import { useState } from 'react';
import { G, HIGH, MOD, SAFE } from '../lib/tokens';

/* REPO INTAKE — frontend only.
 *
 * Accepts a GitHub repository URL, validates it in the browser, and POSTs to
 * /api/repos. That endpoint does not exist server-side yet: this is the
 * frontend half, per the brief. Until the backend lands, submissions persist
 * to localStorage so the view is demonstrable end to end, and the UI says so
 * plainly rather than showing a queue that is not real.
 *
 * Backend contract this expects, when it is built:
 *   POST   /api/repos   {url, owner, name} -> {id, url, owner, name, status, submitted_at}
 *   GET    /api/repos                      -> [ ...same shape ]
 *   DELETE /api/repos?id=<id>              -> {removed: true}
 */

/* Accepts the forms people actually paste: full URL with or without scheme,
 * with or without .git, the SSH remote, and bare owner/name. Anything else is
 * rejected rather than guessed at — a silently-wrong repo is worse than a
 * rejected one. */
export function parseRepo(raw) {
  const s = (raw || '').trim().replace(/\s+/g, '');
  if (!s) return { error: 'Paste a GitHub repository URL.' };

  let m = s.match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/i);
  if (!m) m = s.match(/^git@github\.com:([\w.-]+)\/([\w.-]+?)(?:\.git)?$/i);
  if (!m) m = s.match(/^([\w.-]+)\/([\w.-]+?)(?:\.git)?$/);
  if (!m) return { error: 'Not a GitHub repository. Try https://github.com/owner/name' };

  const [, owner, name] = m;
  if (owner === '.' || owner === '..' || name === '.' || name === '..') {
    return { error: 'That owner/name pair is not valid.' };
  }
  return { owner, name, url: `https://github.com/${owner}/${name}` };
}

const STATUS = {
  scanned: { fg: SAFE, bg: 'rgba(72,213,151,0.1)', g: G.p3, t: 'scanned' },
  failed:  { fg: HIGH, bg: 'rgba(255,93,93,0.1)',  g: G.p0, t: 'failed' },
  queued:  { fg: MOD,  bg: 'rgba(255,177,77,0.1)', g: G.p1, t: 'queued' },
};

export default function Repos({ repos, message, onSubmit, onRemove }) {
  const [value, setValue] = useState('');

  function submit(ev) {
    ev.preventDefault();
    onSubmit(value, () => setValue(''));
  }

  return (
    <>
      <div className="card">
        <div className="card-head">
          <span className="t">add a repository</span>
          <span className="h">public GitHub repos · lockfile resolution + OSV scan + ingest</span>
        </div>
        <div style={{ padding: 16 }}>
          <form className="repo-form" onSubmit={submit} autoComplete="off">
            <label className="repo-input">
              <span className="pre">github.com/</span>
              <input
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder="owner/name  ·  or paste the full URL"
                spellCheck="false"
              />
            </label>
            <button className="repo-submit" type="submit" disabled={message?.kind === 'wait'}>
              queue scan
            </button>
          </form>

          {message && (
            <div className={`repo-msg ${message.kind}`}>
              {message.kind === 'wait' && <span className="spinner" />}
              {message.text}
            </div>
          )}

          <div className="note">
            The repository is read for its lockfiles only. Nothing is cloned, built, or executed from
            the browser, and no package code is run — the scan resolves declared ranges against what
            the lockfile actually pinned, then asks OSV about those exact versions.
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <span className="t">submitted</span>
          <span className="h">repo · submitted · status</span>
        </div>

        {repos.length === 0 ? (
          <div className="empty">
            no repositories submitted yet<br />paste a GitHub URL above to queue one
          </div>
        ) : (
          repos.map((r) => {
            const st = STATUS[r.status] || STATUS.queued;
            let when = '—';
            try { when = new Date(r.submitted_at).toLocaleString(); } catch { /* keep the dash */ }
            return (
              <div className="repo-row" key={r.id}>
                <div style={{ minWidth: 0 }}>
                  <div className="nm">{r.owner}/{r.name}</div>
                  <div className="sub">
                    {r.url}{r.local ? ' · not yet sent to backend' : ''}
                  </div>
                </div>
                <span className="when">{when}</span>
                <span className="status" style={{ color: st.fg, background: st.bg }}>
                  <span className="g">{st.g}</span>{st.t}
                </span>
                <button className="ghost" onClick={() => onRemove(r.id)}>remove</button>
              </div>
            );
          })
        )}
      </div>
    </>
  );
}
