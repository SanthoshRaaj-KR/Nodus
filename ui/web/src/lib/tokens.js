/* The design's vocabulary, in one place.
 *
 * Two vocabularies meet in this file: the engine's (node kinds, confidence
 * levels) and the design's (four tiers, four tones). Every translation between
 * them lives here rather than being smeared through the components, so that a
 * change to what P0 means is a one-line change and not an audit. */

export const HIGH = '#ff5d5d';
export const MOD = '#ffb14d';
export const WARN = '#f2d05a';
export const SAFE = '#48d597';
export const VIOLET = '#7c6bff';

export const G = { p0: '■', p1: '▲', p2: '◆', p3: '●' };

export const TIERS = {
  P0: { color: HIGH, glyph: G.p0, label: 'runtime exposed',
        help: 'Installed, confirmed by the lockfile, and reachable from application code.' },
  P1: { color: MOD, glyph: G.p1, label: 'reachable',
        help: 'Reachable through app code, but no confirmed exploit path to a user-facing entry point.' },
  P2: { color: WARN, glyph: G.p2, label: 'build only',
        help: 'Present in build or tooling scope only; never shipped to users.' },
  P3: { color: SAFE, glyph: G.p3, label: 'not reachable',
        help: 'Installed somewhere in the tree, but no call path reaches it.' },
};

export const TONES = {
  hot:   { dot: HIGH, glyph: G.p0, bg: 'rgba(255,93,93,0.07)',  border: 'rgba(255,93,93,0.32)' },
  path:  { dot: MOD,  glyph: G.p1, bg: 'rgba(255,177,77,0.08)', border: 'rgba(255,177,77,0.36)' },
  build: { dot: WARN, glyph: G.p2, bg: 'rgba(242,208,90,0.06)', border: 'rgba(242,208,90,0.26)' },
  clean: { dot: SAFE, glyph: G.p3, bg: 'rgba(72,213,151,0.04)', border: 'rgba(255,255,255,0.1)' },
};

export const EDGE_COLOR = {
  hot: 'rgba(255,93,93,0.5)',
  path: 'rgba(255,177,77,0.62)',
  clean: 'rgba(255,255,255,0.13)',
};

export const TIER_OF_TONE = { hot: 'P0', path: 'P1', build: 'P2', clean: 'P3' };

export const WHY = {
  hot: 'Red because an advisory or incident is filed directly against this node.',
  path: 'Amber because a traced edge chain connects it to a compromised version.',
  build: 'Yellow because a declared range admits it, but no lockfile confirms it.',
  clean: 'Green because no traced edge chain reaches a compromised version.',
};

export const WHY_EDGES = {
  hot: ['ADVISORY_FOR', 'AFFECTS'],
  path: ['RESOLVES_VERSION', 'RESOLVED_IN'],
  build: ['REQUIRES', 'SATISFIED_BY'],
  clean: ['no exposing edge'],
};

/** Server node kinds -> the design's four tones. */
export const KIND_TONE = {
  threat: 'hot', advisory: 'hot', compromised: 'hot',
  subject: 'path', resolution: 'path', exposed: 'path',
  possible: 'build',
  related: 'clean',
};

/** Confidence -> tier.
 *
 * The engine's levels (blastradius/pkg/blast.py, class Confidence) already
 * encode the distinction the tiers draw, so this is a rename rather than a new
 * judgement layered on top:
 *
 *   CERTAIN      the version under review *is* the compromised one   -> P0
 *   HIGH         a lockfile resolves it, or it is transitively        -> P0
 *                exposed -- confirmed either way
 *   MEDIUM       a range provably admits this exact version, but no   -> P1
 *                lockfile confirms it
 *   LOW          a range names it, or it is merely installed          -> P2
 *   INVESTIGATE  relational only (shared maintainer, typosquat)       -> P3
 *
 * INVESTIGATE deliberately lands lowest: relational atoms never amount to a
 * verdict, and promoting them would train users to ignore the real ones.
 */
export const TIER_OF_CONFIDENCE = {
  CERTAIN: 'P0', HIGH: 'P0', MEDIUM: 'P1', LOW: 'P2', INVESTIGATE: 'P3',
};

export const EDGE_TYPES = [
  { id: 'REQUIRES', help: 'A manifest names this package with a version range. A lead, not a finding.' },
  { id: 'SATISFIED_BY', help: 'The range provably admits this exact version, frozen at ingest.' },
  { id: 'RESOLVES_VERSION', help: 'A lockfile actually selected this version. This is the confirmed claim.' },
  { id: 'RESOLVED_IN', help: 'Flattened transitive closure: this version reaches that project, at a known depth.' },
  { id: 'MAINTAINED_BY', help: 'Shared maintainer identity. Never a verdict on its own.' },
  { id: 'TYPOSQUAT_OF', help: 'Name sits within edit distance of a far more popular package.' },
];

export const NAV = [
  ['overview', 'Overview', '◱'],
  ['findings', 'Assessment', '▤'],
  ['supply', 'Supply chain', '◈'],
  ['code', 'Code reach', '⌗'],
  ['advisories', 'Advisories', '⚑'],
  ['repos', 'Repositories', '◧'],
];

export const TITLES = {
  overview:   ['Overview', 'one narrative + the numbers behind it'],
  findings:   ['Assessment', 'tiered findings with their evidence chain'],
  supply:     ['Supply chain', 'dependency propagation graph'],
  code:       ['Code reach', 'call-graph tracing from entry points'],
  advisories: ['Advisories', 'published advisories in this graph'],
  repos:      ['Repositories', 'submit a GitHub repo for scanning'],
};

/** Which tone a server node draws in. */
export function toneOf(n) {
  if (!n) return 'clean';
  if (n.kind && KIND_TONE[n.kind]) return KIND_TONE[n.kind];
  return n.vuln ? 'path' : 'clean';
}

/** "name@version" from whatever shape /api/pkg/targets returned. */
export function specOf(t) {
  if (!t) return null;
  if (typeof t === 'string') return t;
  if (t.spec) return t.spec;
  if (t.name && t.version) return `${t.name}@${t.version}`;
  return t.key || t.label || null;
}
