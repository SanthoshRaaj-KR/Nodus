/* Explainability helpers.
 *
 * The engine already explains itself: every node carries `verdict` (the
 * conclusion in a sentence), `why` (which evidence atoms fired), `neg` (what
 * was checked and did *not* fire), `file` (the witness on disk) and `detail`.
 * The renderer's job is to show that, not to invent its own wording -- if the
 * UI paraphrases, the UI can drift from the engine and start asserting things
 * the graph never claimed.
 *
 * Everything here is presentation-only: expanding an abbreviation, decoding a
 * CVSS vector, formatting a timestamp. No finding is derived in this file. */

/** What each evidence atom means, in one plain sentence. */
export const ATOMS = {
  DIRECTLY_COMPROMISED: 'This exact version is the one named by the threat.',
  RESOLVES_COMPROMISED_VERSION: 'A lockfile here resolved the compromised version — installed, not theoretical.',
  LIVE_WINDOW_OVERLAP: 'The install window overlaps the window the compromise was live.',
  TRANSITIVELY_EXPOSED: 'Reached through the dependency tree, not declared directly.',
  KNOWN_VULNERABILITY: 'A published advisory names this exact version.',
  POSSIBLE_EXACT: 'A declared range provably admits this version — but nothing confirms it was installed.',
  POSSIBLE: 'A manifest names this package, without proof this version was selected.',
  RESOLVES_SUBJECT_VERSION: 'A lockfile resolved the version under review. True, but not a threat by itself.',
  SHARES_MAINTAINER: 'Shares a maintainer account with the subject. A lead, never a verdict.',
  SHARES_REPOSITORY: 'Published from the same source repository.',
  SHARES_PUBLISHER: 'Published by the same publishing identity.',
  TYPOSQUAT_NEIGHBOUR: 'The name sits within a short edit distance of a far more popular package.',
};

/** Column meanings, keyed by the server's own column headings. */
export const COLUMN_HELP = {
  'THREAT': 'Published advisories and simulated incidents. The starting point — what we are tracing from.',
  'COMPROMISED VERSION': 'The exact release the threat names. Marking 4.17.21 never touches 4.17.20.',
  'RANGE ADMITS - UNCONFIRMED': 'Declared ranges that provably admit this version. This is what a range-only tool reports in full — a lead, not a finding.',
  'LOCKFILE RESOLVES - CONFIRMED': 'A lockfile actually selected this version. This is the confirmed claim, and the one worth acting on.',
  'EXPOSED PROJECTS': 'Projects reached over the precomputed closure, with the depth and the direct dependency the path ran through.',
  'RELATED BY IDENTITY': 'Shared maintainer, repository, publisher, or a typosquat neighbour. Never amounts to a verdict on its own.',
  'PROJECT': 'The projects in the fleet.',
  'DIRECT DEPENDENCIES': 'Packages a manifest names directly.',
  'DEPTH 2': 'Reached through one intermediate package.',
  'DEPTH 3': 'Reached through two intermediate packages.',
  'DEPTH 4': 'Reached through three intermediate packages.',
  'DEPTH 5+': 'Deeper than four hops. Real npm trees go deeper than any column strip; each node still carries its exact depth.',
};

/* -------------------------------------------------------------------- CVSS */

const CVSS_METRICS = {
  AV: ['Attack vector', { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' }],
  AC: ['Attack complexity', { L: 'Low', H: 'High' }],
  PR: ['Privileges required', { N: 'None', L: 'Low', H: 'High' }],
  UI: ['User interaction', { N: 'None', R: 'Required' }],
  S:  ['Scope', { U: 'Unchanged', C: 'Changed' }],
  C:  ['Confidentiality', { N: 'None', L: 'Low', H: 'High' }],
  I:  ['Integrity', { N: 'None', L: 'Low', H: 'High' }],
  A:  ['Availability', { N: 'None', L: 'Low', H: 'High' }],
};

/** "CVSS:3.1/AV:N/AC:L/..." -> [{key, label, value}], skipping the version. */
export function decodeCvss(vector) {
  if (!vector) return [];
  return vector
    .split('/')
    .map((part) => part.split(':'))
    .filter(([k]) => CVSS_METRICS[k])
    .map(([k, v]) => {
      const [label, values] = CVSS_METRICS[k];
      return { key: k, label, value: values[v] || v };
    });
}

/** The one-line "how bad, how reachable" gloss under a CVSS row. */
export function cvssHeadline(vector) {
  if (!vector) return '';
  const m = Object.fromEntries(
    vector.split('/').map((p) => p.split(':')).filter((p) => p.length === 2)
  );
  const remote = m.AV === 'N';
  const noAuth = m.PR === 'N';
  const noUser = m.UI === 'N';
  if (remote && noAuth && noUser) return 'Reachable over the network with no credentials and no user action.';
  if (remote && noAuth) return 'Reachable over the network without credentials, but needs user interaction.';
  if (remote) return 'Reachable over the network, but requires privileges or user action.';
  return 'Requires local or adjacent access.';
}

export const SEVERITY_ORDER = { critical: 0, high: 1, moderate: 2, medium: 2, low: 3, unknown: 4 };

export function fmtDate(ts) {
  if (!ts) return '';
  try {
    return new Date(ts * 1000).toLocaleDateString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
    });
  } catch {
    return '';
  }
}

/* ------------------------------------------------------------------- nodes */

/** Everything worth showing about one graph node, taken from the node itself. */
export function explainNode(n) {
  if (!n) return null;
  return {
    label: n.label,
    sub: n.sub || '',
    verdict: n.verdict || '',
    confidence: n.conf || '',
    severity: n.severity || '',
    flag: n.flag || '',
    why: (n.why || []).map((a) => ({ atom: a, text: ATOMS[a] || a })),
    negative: n.neg || [],
    witness: n.file || '',
    detail: n.detail || '',
    advisory: n.advisory || '',
    source: n.vulnSource || '',
    depth: n.hops >= 0 ? n.hops : null,
  };
}
