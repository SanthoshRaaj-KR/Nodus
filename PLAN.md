# Blast Radius v2 — npm Supply-Chain Package & Lockfile Graph on HydraDB

**Status:** proposed, awaiting approval
**Scope:** npm only. Package / PackageVersion / lockfile / project / maintainer / repository / typosquat.
**Explicitly out of scope:** code graph, AST, call graph, file graph, reachability-from-source. That is the other half of the team.

---

## 1. Context

Given a compromised or vulnerable npm package version, we must answer — fast and without lying —

1. Which packages can depend on it, and which actually do?
2. Which of our projects resolved that exact version?
3. Did they resolve it *while the bad version was live*?
4. Which packages share a maintainer, repository, org, or publisher with it?
5. Are there likely typosquats nearby?
6. What exact graph path explains each finding, and how confident are we?

Input is an OSV scan CSV (`osv_scan_results.csv`). Store and traversal engine is HydraDB.

There is an existing sample at `hackhydra/` (this repo, `master`). We build **on top of it**, reusing its
infrastructure and its hard-won HydraDB knowledge, but replacing its scope: we delete the AST/micro graph
and build out the package/ecosystem/maintainer/typosquat side it never had.

---

## 2. What was verified about HydraDB (not assumed)

Read from the source repo `hydra-db/hydradb`: `cypher-compat.md`, `src/query/path_procedure.rs`, `README.md`.

| Fact | Where confirmed | Consequence for us |
|---|---|---|
| Object-store-native distributed graph DB, Rust; Bolt + HTTP, OpenCypher subset | `README.md` | Use the `neo4j` driver / HTTP. No custom client to build. |
| **Node ids are non-negative integers only** | `cypher-compat.md` values section | PURL cannot be an id. Ids come from a persisted counter. |
| **No `IN`, `CONTAINS`, `ENDS WITH`, `IS NULL`, no regex, no string functions** | not-supported section | **Semver and typosquat distance can never run in the DB.** Both are precomputed into edges at ingest. |
| `WHERE` has `=` `<>` `<` `>` `<=` `>=` `STARTS WITH` on properties | WHERE section | **Integer time-window overlap IS expressible in-DB.** This is the one semantic filter we do not precompute. |
| Variable-length paths require an explicit max; `*` and `*1..` rejected | variable-length section | Any unbounded question must be answered by a precomputed closure, not a walk. |
| One relationship type per pattern, directed only | patterns section | Multi-type traversal only via `algo.*`, which takes `relTypes` as a **list**. |
| `algo.SPpaths` / `SSpaths` / `MSpaths`, yield whole `path` objects | path-procedures section | The only way to get paths back, i.e. the explainability payload. |
| **`relDirection` accepts `incoming`, `outgoing`, `both`** | `path_procedure.rs:143-148`, enum `NativePathDirection` | Reverse traversal **is** natively supported in the path procedures. See section 7 — a measurable improvement over the sample. |
| `MSpaths` also takes `sourceLabel`/`sourceProperty`/`sourceValues`, `pairwise`, `resultLimit` | `path_procedure.rs:864` | Multi-source blast radius in one call. |
| Aggregates limited to `count/sum/avg/collect`; **no `min`/`max`** | not-supported section | Any min/max is computed client-side. |
| `WITH` is pass-through only | WITH section | No multi-stage pipelines. Compose in Python. |
| Indexers are asynchronous; read modes `causal` (default) / `strong` | `README.md` | Benchmarks must state read mode and account for index lag. Ingest-then-immediately-query is not a fair warm number. |

**Additional constraints the sample discovered at runtime, not documented upstream** (`hackhydra/README.md`) — we
inherit these as given and re-verify each once against a live node:

- `UNWIND ... MATCH ... MERGE` (write) requires **exactly one label per endpoint** → batch edges per `(type, srcLabel, dstLabel)`.
- `UNWIND ... MATCH ... RETURN` (read) **forbids labels**, demands the first projection be the source field, exactly two unsorted projections → **reads never use UNWIND**; one plain `MATCH` per id with a scalar `$id`.
- A list parameter is accepted **only** as `UNWIND` input → `algo.MSpaths` `sourceValues` must be inlined as an escaped literal.
- Admission control caps `client_query_runtime_ms` (30 s stock); over-asking is HTTP 429.
- Relationships are reified with their own id in the **same integer space** as nodes → the id allocator must keep node and edge blocks disjoint.
- No transactions, one statement per request → writes are `UNWIND`-batched auto-commits, made idempotent by `MERGE` on id.

---

## 3. Gap analysis — what the sample has, what it lacks

**Reuse as-is (genuinely good, do not rewrite):**

| Component | Path | Why keep |
|---|---|---|
| Persisted id allocator | `blastradius/ids.py` | Dense integer ids, disjoint blocks, idempotent re-ingest. Exactly right given ids must be ints. |
| Id-block / sentinel scheme | `blastradius/schema.py` | `UNKNOWN_TS`, `STILL_LIVE=4102444800` — the no-`IS NULL` workaround. Extend, don't replace. |
| HTTP client + UNWIND batching + Bolt fallback | `blastradius/hydra_client.py` | Encodes the write/read asymmetry correctly. |
| Lockfile v2/v3 parser + nested resolution | `blastradius/ingest/lockfile.py` | Correct, and loudly rejects v1 rather than half-parsing. |
| Node lifecycle (Docker) | `blastradius/node.py`, `cli.py doctor/up` | Working dev loop. |
| Brute-force oracle test | `tests/test_oracle.py` | Independent re-implementation of resolution — the right way to prove closure correctness. Extend it. |
| Flattened-closure insight | `PRESENT_IN` in `schema.py` | A bounded walk silently under-reports deep npm trees. This reasoning is correct and becomes our core speed strategy. |

**Delete (out of our scope — the other half of the team owns it):**
`scanner/` (ts-morph), labels `File`/`Function`/`Route`/`ExternalImport`, edges `CALLS`/`CALLS_EXTERNAL`/`HANDLED_BY`/`CONTAINS`, and the `P1 REACHABLE`/`P2 IMPORTED` tiers that depend on them. Keep a documented seam so their graph can attach at `PackageVersion` later.

**Build — absent from the sample, required by the problem statement:**

1. `Package` vs `PackageVersion` split with `HAS_VERSION` — the sample has no `Package` node at all.
2. `REQUIRES` (declared semver range) as distinct from resolution — the sample only ever has resolved edges.
3. `SATISFIED_BY` — the materialized semver expansion (section 5).
4. Maintainer / Repository / Organization / PublisherIdentity graph — entirely missing.
5. Typosquat neighbourhood index — entirely missing.
6. Time-window "resolved while it was live" — the `STILL_LIVE` sentinel exists but nothing uses a lockfile observation window.
7. OSV CSV ingestion with **CVSS base score derived from the vector** and **alias de-duplication**.
8. `Incident` vs `Advisory` separation (`SUPPLY_CHAIN_COMPROMISED` vs `VULNERABLE`).
9. Evidence-atom model with deterministic confidence.
10. Interactive graph visualization.
11. A benchmark harness with honest numbers.

---

## 4. Architecture — two tiers joined at PackageVersion

The sample's thesis was "a lockfile *is* a resolved dependency graph, so we need no ecosystem graph." That is
true for *our* fleet and false for the problem statement, which also asks who else in the ecosystem is affected
and what shares infrastructure. So: two tiers, one join point.

```
   TIER 2 - ECOSYSTEM (npm registry + deps.dev)      "who CAN be affected"
   Package --HAS_VERSION--> PackageVersion --REQUIRES{range}--> Package
                                  |  |--SATISFIED_BY--> PackageVersion   (semver, precomputed)
                                  |  |--SOURCED_FROM--> Repository
                                  |  '--PUBLISHED_BY--> PublisherIdentity
   Package --MAINTAINED_BY--> Maintainer --MEMBER_OF--> Organization
   Package --TYPOSQUAT_OF{distance,technique}--> Package
                                  |
              ====================+====================  join
                                  |
   TIER 1 - FLEET (our lockfiles)                    "who ACTUALLY resolved it"
   Project --HAS_LOCKFILE--> Lockfile --CONTAINS--> LockfileEntry --RESOLVES_TO--> PackageVersion
   PackageVersion --PRESENT_IN{depth,via,first_seen,last_seen}--> Project   (closure, precomputed)

   SECURITY (OSV CSV + synthetic)
   Advisory --AFFECTS--> PackageVersion          => VULNERABLE
   Incident --COMPROMISES--> PackageVersion      => SUPPLY_CHAIN_COMPROMISED
```

Tier 1 is ground truth and small. Tier 2 is inference and large. **Findings from the two are never merged into
one number** — they are separate evidence atoms with separate confidence (section 9).

---

## 5. The accuracy core: three distinct dependency edges

This is the single most important design decision, and it is what stops the tool from over-reporting.

| Edge | Meaning | Source | Verdict it supports |
|---|---|---|---|
| `REQUIRES{range, dep_type, optional, peer}` | `A@1.0` declares a dependency on **Package** `lodash` at `^4.17.0`. Points at the *Package*, never a version. | `package.json` | `POSSIBLE` |
| `SATISFIED_BY{range, dep_type}` | `A@1.0` could resolve to **this exact** `lodash@4.17.21`. Materialized by evaluating the range in Python at ingest. | derived | `POSSIBLE_EXACT` |
| `RESOLVES_TO` | This project's lockfile **actually selected** `lodash@4.17.21`. | `package-lock.json` | `CONFIRMED` |

**Why `SATISFIED_BY` must be materialized:** HydraDB has no string functions and no regex, so `^4.17.0` can never
be evaluated against `4.17.21` inside a query. There is no alternative design. Semver runs in Python
(node-semver semantics), feeding exact integer ids to the graph.

**Why this prevents false positives:** "A requires lodash ^4" does **not** mean A is exposed — `^4` also matches
the safe `4.17.22`. Only `SATISFIED_BY` reaching the specific bad version makes A a candidate, and only
`RESOLVES_TO` makes a project confirmed. The three are never collapsed, and the API returns which one fired.

**Cost control:** `SATISFIED_BY` is the one edge type that can explode (a `^4` range x 80 published 4.x versions).
Mitigation, in order: (a) only materialize against versions we actually hold; (b) cap at the N newest satisfying
versions plus every version named by an advisory or incident, since those are the only ones anyone ever queries;
(c) store `range` on the edge so a client-side re-check can prove the expansion was right. Measure the real
fan-out on the seed corpus before tuning further.

---

## 6. Node and edge catalogue

**Nodes** — each with the reason it exists.

| Node | Why it exists |
|---|---|
| `Package` | The identity that persists across versions. Maintainers, repo, org and typosquat similarity attach here, not to a version. |
| `PackageVersion` | The unit security state actually applies to. `lodash@4.17.21` being bad must not condemn `4.17.22`. |
| `Project` | A real application we own. The thing an on-call engineer is paged about. |
| `Lockfile` | Carries the observation time — *when* we saw this resolution. Required for the "while it was live" question. |
| `LockfileEntry` | One resolved entry, with its own install path and dev/optional flags. Distinguishes "in the prod tree" from "dev only". |
| `Maintainer` | npm account with publish rights. Shared-maintainer is the classic lateral-movement signal. |
| `Repository` | Shared source infrastructure — a breached CI pipeline hits every package built from it. |
| `Organization` | npm scope / GitHub org — the blast radius of a compromised org token. |
| `PublisherIdentity` | The account that published *this specific version* (`_npmUser`), which is often not the listed maintainer. This is the account actually used in a compromise. |
| `Advisory` | A known vulnerability (CVE/GHSA/OSV). Yields `VULNERABLE`. |
| `Incident` | A supply-chain compromise. Yields `SUPPLY_CHAIN_COMPROMISED`. Deliberately a different node type: a compromise is not a CVE and must not be scored like one. |

**Edges:** `HAS_VERSION`, `REQUIRES`, `SATISFIED_BY`, `RESOLVES_TO`, `HAS_LOCKFILE`, `CONTAINS`, `PRESENT_IN`,
`MAINTAINED_BY`, `MEMBER_OF`, `SOURCED_FROM`, `OWNED_BY`, `PUBLISHED_BY`, `TYPOSQUAT_OF`, `AFFECTS`, `COMPROMISES`,
plus materialized inverses where section 7 shows they are needed.

No generic `RELATED_TO` edge. Every relationship is typed, per the problem statement.

**Identity:** canonical PURL `pkg:npm/{normalized_name}@{version}` (scoped: `pkg:npm/%40scope%2Fname@ver`) is the
**key property**; the node `id` is a dense integer from `ids.py` keyed on that PURL. Normalization (lowercase, scope
preserved) prevents casing duplicates. Re-ingesting the same PURL returns the same id, so ingestion is idempotent
by construction.

---

## 7. The speed strategy — four layers, cheapest first

The governing rule: **the headline answer never runs a graph traversal.** Traversal is reserved for on-demand path
explanation of nodes the user actually opens.

- **L0 — id lookup, no graph hit.** PURL to integer id from the local sqlite allocator. Answers "what is `X@Y`" and
  anchors every other query. Target: sub-millisecond, zero round trips.
- **L1 — one hop over the precomputed closure.** `PackageVersion --PRESENT_IN--> Project`, with `depth`,
  `via_direct` (the top-level dependency that leads to it), `first_seen`, `last_seen` **on the edge**. This answers
  the money question — which of our projects are exposed, how deep, through what, and when — in **one round trip
  with the path witness included**. Exact at any depth, unlike a bounded walk. Extends the sample's `PRESENT_IN`
  with the `via` and time properties it lacked.
- **L2 — bounded `algo.SSpaths` / `MSpaths`, lazy.** Full path objects for explainability, run only on expand.
  `relTypes` takes a list, so one call spans `SATISFIED_BY` + `RESOLVES_TO` + `CONTAINS`.
- **L3 — ecosystem reverse closure.** Bounded reverse walk over `SATISFIED_BY` for "which other npm packages could
  be affected". Bounded because this tier is inference, and an unbounded answer here is noise, not information.

**The `relDirection: incoming` experiment.** The sample writes **every edge twice** and states a backward walk is
"not expressible at all". That is true for plain `MATCH` var-length patterns — but `path_procedure.rs` defines
`NativePathDirection::Incoming` and parses `relDirection: 'incoming'`. So for any question answered exclusively via
`algo.*`, the materialized inverse may be unnecessary. If it holds, Tier 2 drops roughly half its edges and roughly
halves ingest time. **This is a benchmark, not an assumption** (section 12, experiment A) — we keep the inverse
edges for anything reached by plain `MATCH` either way.

---

## 8. The eight core queries

| # | Question | How | Round trips |
|---|---|---|---|
| Q1 | What is `X@Y`? | L0 id lookup + single `MATCH (p:PackageVersion {id:$id})` | 1 |
| Q2 | Who **directly** depends on it? | one hop `SATISFIED_BY` incoming (or materialized inverse) | 1 |
| Q3 | Who **transitively** depends on it? | L3 bounded reverse, depth reported in the response | 1 |
| Q4 | Which lockfiles resolve exactly it? | one hop `RESOLVES_TO` inverse to `LockfileEntry` to `Lockfile` | 1-2 |
| Q5 | Which projects are exposed? | **L1 single hop** over `PRESENT_IN`, incl. depth + via + window | **1** |
| Q6 | Which packages share maintainer / repo / org / publisher? | `Package` to `MAINTAINED_BY` to `Maintainer` to inverse to `Package`, one hop each way, per relationship type | 1 per type |
| Q7 | What path explains this? | `algo.SSpaths` from the bad version, `relDirection: incoming`, bounded, lazy | on demand |
| Q8 | Which projects resolved it **while it was live**? | Q5 plus in-DB integer overlap: `WHERE e.first_seen <= $live_until AND e.last_seen >= $live_from` | 1 |

Q8 is worth calling out: it is the one semantic predicate that runs **inside** HydraDB, because epoch-second
integers are comparable with the operators the subset does support. Everything else semantic is precomputed.

---

## 9. Evidence model — atoms, not a score

Each atom is derived from a specific graph fact and carries its own witness. Confidence is a deterministic
function of which atoms fired; **no LLM is involved in generating an explanation.**

| Atom | Fires when | Confidence |
|---|---|---|
| `DIRECTLY_COMPROMISED` | `Incident --COMPROMISES-->` this exact PackageVersion | CERTAIN |
| `RESOLVES_COMPROMISED_VERSION` | a lockfile `RESOLVES_TO` it | HIGH |
| `LIVE_WINDOW_OVERLAP` | resolution window overlaps the live window | HIGH (upgrades the above) |
| `TRANSITIVELY_EXPOSED` | `PRESENT_IN` with `depth > 1` | HIGH |
| `KNOWN_VULNERABILITY` | `Advisory --AFFECTS-->` it | scales with CVSS |
| `POSSIBLE_EXACT` | `SATISFIED_BY` reaches it, no lockfile confirms | MEDIUM |
| `POSSIBLE` | `REQUIRES` range only | LOW |
| `SHARED_MAINTAINER` | shares a `Maintainer` with a compromised package | **INVESTIGATE — never COMPROMISED** |
| `SHARED_REPOSITORY` / `SHARED_PUBLISHER` | shares repo / publishing identity | INVESTIGATE |
| `TYPOSQUAT_NEIGHBOR` | `TYPOSQUAT_OF` edge with popularity asymmetry | INVESTIGATE |

The hard rule from the problem statement: **relationship atoms never escalate to compromise.** A shared-maintainer
package renders as `RELATED / INVESTIGATE` with explicit negative evidence — "shares maintainer Alice with
compromised X; is *not* named by the incident; does *not* resolve a compromised version; no independent evidence."
Stating what we did **not** find is as important as what we did.

---

## 10. Typosquat detection

Cypher has no string functions, so this is entirely a precompute that writes `TYPOSQUAT_OF` edges.

**Candidate generation** against the top-N popular npm names (seeded from a downloads list, held locally):
Damerau-Levenshtein distance <= 2, keyboard-adjacency substitution, homoglyph folding (`rn`/`m`, `l`/`1`, `0`/`o`),
separator and case collapse (`node-fetch` / `nodefetch` / `node_fetch`), scope confusion (`lodash` vs
`@lodash/core` vs `@types/lodash`), and transposition (`lodahs`).

**Efficiency:** a trigram inverted index (or BK-tree) over normalized names for candidate generation, so we compare
against a few dozen names instead of all N. Built once at ingest.

**Accuracy guard — this is what stops the feature being useless:** an edge is only written when there is
**popularity asymmetry** (the suspected squatter has far fewer downloads than the target). Without it,
`lodash.merge` — a legitimate package — flags against `lodash`, and every scoped fork flags against its parent.
We store `distance`, `technique` and `popularity_delta` on the edge and let the UI show the signal. We label it
`INVESTIGATE`; we never assert "this is malicious."

---

## 11. Ingestion pipeline

```
OSV CSV --+
          +--> normalize --> dedupe --> MERGE nodes --> MERGE edges --> record provenance
lockfiles-+
registry -+
```

Idempotent throughout: `MERGE` by id, ids from a persisted PURL-to-int map. Re-running ingest is a no-op, never a
duplicate. Incremental — new data does not rebuild the graph.

**OSV CSV** (`osv_scan_results.csv`, 14 columns). Real quirks found in the supplied file, each handled explicitly:

- `severity_score` is **empty** while `cvss_vector` is populated, so we **compute the CVSS v3.1 base score from the
  vector ourselves** and store vector + derived score + band. Do not display an empty severity.
- `aliases` is pipe-separated (`CVE-2026-32597 | GHSA-752w-5fwx-jx9f`), so we run union-find over the alias graph to
  collapse aliases into one `Advisory`. The supplied file has 13 rows for `pyjwt@2.9.0` that are substantially the
  same advisories under different ids; without this the exposure count is inflated several-fold.
- `published` / `modified` are ISO-8601 and become epoch-second integers (HydraDB `sum`/`avg` are unsigned-int only).
- `fixed_version` may be empty, so it takes a sentinel, and when present it drives the remediation line.
- `source_file` links the finding to a `Project` or manifest.
- The supplied sample is **100% PyPI**. We treat the CSV as the **input contract (its columns)**, not its contents:
  the parser is ecosystem-generic and routes on the `ecosystem` column, while the graph and enrichment are npm.
  A PyPI row is ingested as an `Advisory` and reported as out-of-scope-for-enrichment rather than silently dropped.

**Registry metadata** — one `GET https://registry.npmjs.org/{pkg}` per package yields, in a single response: every
version, `time` (giving `published_at` per version, needed for the live-window question), `maintainers` (giving
`Maintainer`), `_npmUser` per version (giving `PublisherIdentity`), `repository` (giving `Repository`), plus
`dist.integrity` and `deprecated`. That one endpoint covers most of Tier 2. deps.dev is the fallback for dependents.

**Seed set, bounded deliberately:** the transitive closure of packages actually present in our lockfiles, plus the
top-N popular names needed as a typosquat baseline. **No whole-ecosystem crawl** — the corpus defines the frontier.
Target 2-5k packages, 50-200 projects.

**Provenance** on every node and edge: `source` (`npm-registry` / `package-lock.json` / `package.json` / `osv-csv` /
`synthetic`) and `ingested_at`. Required for explainability, and for telling derived edges from observed ones.

---

## 12. Benchmarks — measured, not claimed

The harness records per query: p50/p95/p99 latency, round trips, nodes visited, edges traversed, result size — cold
vs warm, and with the **read mode stated** (`causal` vs `strong`), since indexers are asynchronous and index lag
makes an ingest-then-query number meaningless otherwise.

**Experiment A — reverse traversal.** Materialized inverse edge (the sample's approach) vs `algo.SSpaths` with
`relDirection: incoming`. Measures latency **and** graph size and ingest time. Decides whether Tier 2 doubles its
edges.

**Experiment B — closure vs walk.** L1 one-hop `PRESENT_IN` vs bounded `[:REQUIRED_BY*1..8]`. Expected result: the
walk is both slower **and wrong** on deep trees. We report the disagreement count, not just the timing — a bounded
walk that silently under-reports is the failure mode that most flatters the tool.

**Experiment C — `SATISFIED_BY` fan-out.** Edge count and ingest time vs the version cap from section 5, to pick the
cap from data rather than by guess.

Plus the Q1-Q8 latency table, ingestion throughput, graph size, and a cache-warming curve (same query repeated N
times).

**Correctness harness:** extend `tests/test_oracle.py`. The graph's answer must equal an independently written
brute-force resolver's answer, over generated lockfiles including deep chains, cycles, dev/optional-only paths, and
scoped names. Two independent implementations agreeing is the only claim of correctness worth making.

---

## 13. Visualization

**Cytoscape.js.** Chosen over React Flow (built for hand-authored node editors, not derived graphs) and raw D3 (too
low-level for the time budget): Cytoscape gives graph-theoretic layouts (`cose-bilkent`, `dagre`), **compound nodes**
— so a `Package` can visually contain its `PackageVersion`s, which is exactly our central distinction — and handles
a few thousand elements without hand-written rendering.

Default view is a **focused neighbourhood** of the compromised version: the bad version, direct dependents, the
transitive paths that actually reach a project, affected lockfiles and projects, and shared-maintainer packages —
never the whole database. Expand on demand, with the node count shown before expanding.

Node types are distinguished by shape **and** colour (not colour alone — colour-blind safety, and it must survive a
screenshot). Supports zoom, pan, selection, edge labels, filter by node and edge type, path highlighting, and
expand/collapse.

Selecting a node opens **WHY FLAGGED?** — status, the exact path, the triggering evidence atoms, the incident or
advisory, confidence, and, for relationship-only findings, the explicit list of what we did *not* find. Rendered
from the evidence atoms of section 9; no generated prose.

---

## 14. Implementation order

| Phase | Deliverable | Proves |
|---|---|---|
| **0** | Branch off `master`; strip AST/micro graph; `doctor` and `up` green; re-verify the six inherited constraints against a live node | Clean base, constraints hold |
| **1** | `Package`/`PackageVersion`/`HAS_VERSION`/`REQUIRES`; registry ingest; Q1, Q2 | Version-aware core |
| **2** | Semver expansion into `SATISFIED_BY`; Q3; Experiment C | The accuracy core |
| **3** | `Project`/`Lockfile`/`LockfileEntry`/`RESOLVES_TO` + `PRESENT_IN` closure with via and time; Q4, Q5, Q8 | The money query |
| **4** | OSV CSV ingest: CVSS from vector, alias union-find, `Advisory` vs `Incident`; synthetic `SYNTHETIC-001` | Real input, correct counts |
| **5** | Maintainer / Repository / Organization / PublisherIdentity; Q6 | Lateral-movement signals |
| **6** | Typosquat index with popularity guard | The differentiator |
| **7** | Evidence atoms + confidence + `WHY FLAGGED` API; Q7 paths | Explainability |
| **8** | Cytoscape UI | Demo |
| **9** | Benchmarks A/B/C, oracle tests, honest write-up | Defensible claims |

Phases 1-3 are the spine; if time runs short, 5 and 6 degrade gracefully to "ingested but not visualized."

---

## 15. Demo

```
python -m blastradius.cli simulate lodash@4.17.21
```

Creates `SYNTHETIC-001` against **one ordinary public package version** — no real malicious package, nothing
downloaded, nothing executed, graph logic only — then prints direct dependents, transitive dependents, affected
projects, lockfiles resolving the exact version, live-window matches, shared-maintainer / repo / publisher packages,
typosquat neighbours, and per-query latency. `--fail-on` makes it a CI gate. Then `serve` for the graph UI.

---

## 16. Risks

| Risk | Mitigation |
|---|---|
| `SATISFIED_BY` fan-out explodes | Version cap plus advisory-named versions always kept; Experiment C picks the cap from data (section 5) |
| `relDirection: incoming` does not behave as the source suggests | Materialized inverse is the fallback and is already the sample's proven path; Experiment A decides |
| Registry rate limits | Local disk cache keyed by package and etag; ingest is resumable and idempotent |
| Typosquat false positives | Popularity-asymmetry guard; `INVESTIGATE` only, never a malice claim |
| Sample's undocumented constraints have drifted | Phase 0 re-verifies all six against a live node before anything is built on them |
| CSV is PyPI-only, npm enrichment untested on real input | Parser is ecosystem-generic; build an npm-shaped OSV CSV from the corpus for end-to-end testing |

---

## 17. Verification

1. `python -m blastradius.cli doctor` — every prerequisite named with its fix.
2. `pytest tests/` — oracle equality on generated lockfiles (deep, cyclic, dev-only, scoped); alias-collapse unit
   tests; CVSS-vector scoring against published reference vectors; semver expansion against node-semver fixtures.
3. Re-run `ingest` twice — node and edge counts identical (idempotence).
4. `simulate lodash@4.17.21` — every section populated, latencies printed.
5. **Negative control:** `simulate lodash@4.17.22` (the *safe* neighbour) must return **zero** compromised findings.
   This is the test that proves version-awareness rather than package-awareness, and it is the one most likely to
   catch a real bug.
6. UI: select a shared-maintainer node, confirm it renders `INVESTIGATE` with negative evidence and never
   `COMPROMISED`.

---

## 18. Git

Work on a new branch off `master` (`git switch -c blast-radius-v2`). `master` is untouched until reviewed.
