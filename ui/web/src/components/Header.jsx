import { TIERS, TITLES } from '../lib/tokens';

export default function Header({ view, target, marked, busy, onMark }) {
  const [title, sub] = TITLES[view] || TITLES.overview;
  const isMarked = target && marked.has(target);

  /* Marking is meaningless without a version to mark, and the code view is
   * the friend's call graph rather than the package tier, so the control is
   * disabled there rather than silently doing nothing. */
  const disabled = !target || busy || view === 'repos' || view === 'code';

  return (
    <header>
      <div style={{ minWidth: 190 }}>
        <div className="view-title">{title}</div>
        <div className="view-sub">{sub}</div>
      </div>

      <div className="focus">
        <span className="k">focus</span>
        <span className="v">{view === 'code' ? 'src call graph' : target || 'whole project'}</span>
        <span className="spacer" />
        <span className="q">?target=</span>
      </div>

      <span className="spacer" />

      <div className="tiers">
        <span className="k">tiers</span>
        {Object.keys(TIERS).map((id) => {
          const t = TIERS[id];
          return (
            <span className="tier-chip" key={id} title={t.help}>
              <span className="g" style={{ color: t.color }}>{t.glyph}</span>
              <span className="id" style={{ color: t.color }}>{id}</span>
              {t.label}
            </span>
          );
        })}
      </div>

      <button
        className={`act${isMarked ? ' retract' : ''}`}
        disabled={disabled}
        onClick={onMark}
        title="Writes a synthetic Incident node against this version in our own database. Nothing is downloaded, nothing is executed, and no package is modified."
      >
        {busy ? 'working…' : isMarked ? 'retract simulation' : 'simulate compromise'}
      </button>
    </header>
  );
}
