# Package Blast Radius

**Given a compromised npm package version, which projects are actually exposed, and why?**

This is the package/lockfile half of the project. It does not touch the code graph — that stays owned by
the AST half. The two meet at `PackageVersion` and at `Service`.

Everything lives under `blastradius/pkg/`. No file outside it was modified except an append-only block in
`schema.py` and one Docker fix in `node.py`.

---

## 1. The one idea

A dependency **range** and a dependency **resolution** are different facts, and almost every supply-chain
tool merges them.

```
express@4.18.2  --REQUIRES{range:"^4.17.21"}-->  Package lodash      "I need some lodash 4.17.21+"
express@4.18.2  --SATISFIED_BY-->  lodash@4.17.21                    "that range admits this exact version"
LockfileEntry   --RESOLVES_VERSION-->  lodash@4.17.21                "this project installed this version"
```

Only the third is exposure. The first two are possibilities.

Measured on the real corpus in this repo:

| | count |
|---|---|
| package versions whose declared range **admits** `lodash@4.17.21` | **25** |
| projects whose lockfile actually **resolved** it | **1** |

A range-only tool reports 25 leads. One is real. Run `compare` below to reproduce that.

The negative control is the proof that this is version-aware rather than package-aware:

```
lodash@4.17.21  ->  exposes legacy-pinned-service   (and nothing else)
lodash@4.17.20  ->  exposes legacy-pinned-older     (and nothing else)
```

Same package, adjacent versions, disjoint blast radii.

---

## 2. Why it is fast

HydraDB has no string functions, no regex, no `IN`, and rejects unbounded traversal. So **every semantic
decision is made at ingest and frozen into a typed edge**, and the query side is pure id-anchored lookup.

| layer | what it does | cost |
|---|---|---|
| **L0** | purl → integer id, from a local sqlite map | no graph hit at all |
| **L1** | "which projects are exposed" — **one hop** over a precomputed closure edge that already carries depth, the via-dependency, and the time window | ~3 ms |
| **L2** | whole-path reconstruction via `algo.SSpaths`, only for a node someone opens | on demand |

The headline answer never runs a traversal. That is the whole performance story.

The one semantic predicate that *does* run inside HydraDB is the live-window overlap, because epoch-second
integers compare with the operators the subset supports:

```cypher
WHERE e.first_seen <= $until AND e.last_seen >= $since
```

---

## 3. Graph model

```
  Package --HAS_VERSION--> PackageVersion --REQUIRES{range}--> Package
                                 |  |--SATISFIED_BY--> PackageVersion    (semver, precomputed)
                                 |  |--SOURCED_FROM--> Repository
                                 |  '--PUBLISHED_BY--> PublisherIdentity
  Package --MAINTAINED_BY--> Maintainer
  Package --TYPOSQUAT_OF{distance,technique}--> Package

  Service --HAS_LOCKFILE--> Lockfile --HAS_ENTRY--> LockfileEntry --RESOLVES_VERSION--> PackageVersion
  PackageVersion --RESOLVED_IN{depth,via_direct,dev_only,first_seen,last_seen}--> Service

  Advisory --AFFECTS-->     PackageVersion    =>  VULNERABLE
  Incident --COMPROMISES--> PackageVersion    =>  SUPPLY_CHAIN_COMPROMISED
```

`Advisory` and `Incident` are deliberately different node types. A known CVE and a tampered artifact are
not the same claim and must not share a severity scale.

`Maintainer` (who may publish) and `PublisherIdentity` (who did publish this artifact) are separate,
because in a credential compromise they differ — lodash lists `jdalton` as maintainer, but `4.17.21` was
published by `bnjmnt4n`. The graph shows both.

---

## 4. Evidence, not a score

Each finding carries the atoms that produced it, and the ones that did not fire.

```
DIRECTLY_COMPROMISED           an incident names this exact version      CERTAIN
RESOLVES_COMPROMISED_VERSION   a lockfile resolved it                    HIGH
TRANSITIVELY_EXPOSED           reached at depth > 1                      HIGH
LIVE_WINDOW_OVERLAP            resolved while the version was live       HIGH
POSSIBLE_EXACT                 a range admits it, no lockfile confirms   MEDIUM
POSSIBLE                       a range names the package                 LOW
SHARED_MAINTAINER / _REPOSITORY / _PUBLISHER / TYPOSQUAT_NEIGHBOR        INVESTIGATE
```

**Relational atoms can never raise a finding above INVESTIGATE**, however many fire. Sharing a maintainer
with a victim is a reason to look, not a verdict, and a tool that says otherwise trains people to ignore it.
Those findings render with explicit negative evidence — what we looked for and did not find.

---

## 5. Setup

```powershell
# 1. HydraDB (run Docker commands from PowerShell, never Git Bash --
#    Git Bash rewrites container-side paths and the node dies naming no path)
python -m blastradius.cli up

# 2. Generate the corpus. Drives real npm to resolve real lockfiles:
#    --package-lock-only downloads no tarballs, --ignore-scripts runs nothing.
python -m blastradius.pkg.cli corpus --count 12

# 3. Ingest: lockfiles + npm registry + advisories -> the graph
python -m blastradius.pkg.cli ingest --osv ../osv_scan_results.csv
```

Ingest is idempotent — ids are a persisted function of a natural key, so re-running `MERGE`s the same rows.
First run fetches ~77 MB of registry metadata and caches it; later runs are offline-fast (`--offline` forces
cache-only).

---

## 6. Using it

```powershell
# The demo. Creates a synthetic incident, then answers everything.
python -m blastradius.pkg.cli simulate lodash@4.17.21

# Explain one entity in full
python -m blastradius.pkg.cli simulate lodash@4.17.21 --why legacy-pinned-service

# The accuracy claim, measured: range-only leads vs lockfile truth
python -m blastradius.pkg.cli compare lodash@4.17.21

# Take the simulated incident back off
python -m blastradius.pkg.cli retract lodash@4.17.21

# Latency + the two experiments
python -m blastradius.pkg.cli bench lodash@4.17.21
```

Each simulated incident is keyed to its exact target (`SIM-pkg:npm/lodash@4.17.21`), so marking a second
version leaves the first alone. A single shared id used to mean the second `simulate` added another edge to
the same incident node, which then claimed two versions at once — the tool's own demo undoing the
distinction it exists to draw.

`simulate` prints direct dependents, transitive dependents, lockfiles resolving the exact version, exposed
projects with depth and witness, live-window matches, shared maintainer / repository / publisher, typosquat
neighbours, findings by confidence, and a per-query latency table.

**Safety:** the incident is synthetic and points at one ordinary, healthy public package. Nothing is
downloaded, nothing is executed, and no package is modified. We are testing graph logic.

---

## 7. Testing it

```powershell
npm install --prefix scanner                            # once: the oracle re-ingests, which runs the scanner
python -m pytest tests/ -q                              # 270 tests
python tests/verify_constraints.py                      # HydraDB behaviour vs assumptions
python tests/difftest_semver.py --semver-dir <dir with node_modules/semver>
```

`test_oracle.py` re-ingests the corpus, and ingest runs the ts-morph scanner. Without `scanner/node_modules`
the ingest aborts partway, so the brute-force oracle reports a project missing from the graph -- a real
failure with a misleading cause. Install the scanner deps once and both live tests pass.

The three that carry the most weight:

**`difftest_semver.py`** — our semver against the real npm `semver` package over 3,404
`(version, range, includePrerelease)` triples. Zero disagreements. This matters because HydraDB cannot
evaluate a range, so every admits/does-not-admit decision is frozen into an edge at ingest; a bug there is a
wrong security finding, not a slow query. The differential run found three divergences the unit tests could
not, including `^1.2.3` needing to expand to `<2.0.0-0` rather than `<2.0.0`.

**`test_closure.py`** — the transitive closure against an independent oracle that recomputes reachability by
relaxing depths to a fixed point instead of breadth-first. Two implementations built on different principles
are unlikely to be wrong identically. The lockfiles under test were written by npm, not by us.

**`verify_constraints.py`** — asks the running node whether each assumed constraint is real. 17/18 hold;
the one divergence is documented in §9.

**`test_findings.py`** — that a true fact never becomes a false claim. Looking up an ordinary, healthy
package used to flag every project holding it as EXPOSED, because "this lockfile resolved this version" is
the same graph row whether or not anything marks the version. It is not the same claim, and the atom whose
name asserts a compromise is now emitted only when an incident or an advisory actually names the version.

To check the version-awareness claim by hand:

```powershell
python -m blastradius.pkg.cli simulate lodash@4.17.21 | Select-String "EXPOSED PROJECTS" -A 3
python -m blastradius.pkg.cli simulate lodash@4.17.20 | Select-String "EXPOSED PROJECTS" -A 3
```

Different projects. If those ever return the same set, the version-awareness is broken.

---

## 8. Seeing it: the console's package view

> **Where this lives now.** This section describes the **Package · Blast Radius** view, which is served by
> `/console` (and by the React build in `ui/web`). It used to share a page with `/explorer`; `/explorer` has
> since been rebuilt around confirmed threats and code reach — see §10f. The six-column argument below is
> unchanged, it is just reached from the console tab rather than the Explorer.

`python -m blastradius.cli ui` serves the pages on port 8100. The console already had two tabs, both owned
by the code-graph half. **Package · Blast Radius** is the third, and it does not work the way they do.

The other two fetch the whole graph and compute the highlight in the browser by walking edges backwards from
whatever you typed. That is right for them. It would be wrong here: exposure is a fact already stored on an
edge, so re-deriving it client-side by matching package names would put the range-only guess back in on top
of the query built to replace it. **The server marks each node and says with which evidence atoms**, and the
browser only draws.

The six columns are the argument:

```
THREAT  ->  COMPROMISED VERSION  ->  RANGE ADMITS  ->  LOCKFILE RESOLVES
                                                   ->  EXPOSED PROJECTS  |  RELATED BY IDENTITY
```

`RANGE ADMITS` is a **dead end** — it connects to nothing on its right, because admitting a version is not
installing it. On `debug@4.4.3` that column holds 45 and the projects column holds 5. `RELATED BY IDENTITY`
sits directly beside the compromised node and stays cold, which is the evidence rule drawn rather than
described: a shared maintainer never raises a finding above INVESTIGATE.

### Marking something as vulnerable

Pick a target from the chips (each states the gap it will show: `45 admit · 5 installed`), or type
`name@version` and press Enter. Then press **mark compromised**.

```
POST   /api/pkg/incident?spec=debug@4.4.3     mark
DELETE /api/pkg/incident?spec=debug@4.4.3     retract
GET    /api/pkg/graph?spec=debug@4.4.3        the scoped view
GET    /api/pkg/targets                       suggestions, ranked by that gap
```

Before marking, the graph draws in normal colours and the badges read `RESOLVED` and `INSTALLED`. After,
a THREAT column appears, the confirmed chain turns red and animates, the 45 range-only leads dim, and the
badges become `CONFIRMED` and `EXPOSED`. **retract incident** puts it back. Marking is scoped to the exact
version, so `lodash@4.17.21` and `lodash@4.17.20` can be marked independently and light up different
projects.

That before/after is not cosmetic. An unmarked version used to render its projects as `EXPOSED` too, because
"this lockfile resolved this version" is the same row either way — see §7.

### Clicking a node

The panel shows the verdict, the evidence atoms that fired, and **what was looked for and not found**:

```
body-parser@2.2.1        range admits it — unconfirmed
  Unconfirmed — its declared range admits the version, but no lockfile resolved it
  declares ^4.4.3, which admits debug@4.4.3
  EVIDENCE               POSSIBLE_EXACT
  LOOKED FOR, NOT FOUND  no lockfile in the corpus resolved this pairing
```

The negative half is what makes an INVESTIGATE verdict safe to act on. A finding that only lists what fired
invites the reader to assume everything else fired too.

**Note on the other two tabs.** Macro and Micro read `PRESENT_IN`, `DEPENDS_ON`, `Function` and `Route`,
which this half does not write; the Package tab reads `RESOLVED_IN`, `SATISFIED_BY` and `RESOLVES_VERSION`,
which the code half does not write. The two ingests are independent and both are needed for a full Explorer:

```powershell
python -m blastradius.cli ingest        # services, files, functions, routes  -> Macro and Micro
python -m blastradius.pkg.cli ingest    # lockfiles, ranges, identity          -> Package
```

Run only one and the other tabs come up empty of the nodes they draw. Nothing in this half changed theirs.

---

## 9. What measurement changed

Three design decisions were settled by asking the database rather than by reasoning about it.

**Inverse edges are mostly unnecessary.** The sample writes every edge twice, on the grounds that "a
backward walk is not expressible at all". Against a live node that is true only of *variable-length*
patterns. A single hop with the destination pinned is accepted:

```cypher
MATCH (e:LockfileEntry)-[:RESOLVES_VERSION]->(v:PackageVersion {id: $id})   -- works, no inverse needed
```

Since nearly every query here is single-hop, only `SATISFIED_BY` — the one relationship walked backwards for
multiple hops — keeps its inverse. **Edges dropped from ~28,000 to 18,224, a 35% reduction, with no query
lost.**

**`algo.SSpaths` with `relDirection: 'incoming'` works, but is the wrong tool for a set.** It enumerates
paths, not nodes, and there are far more paths than nodes: 521 ms for 1,024 paths against 90 ms for 174
distinct nodes over the materialised inverse. So the inverse stays for reachability, and the path procedure
is used only where whole paths are the point — on-demand explanation.

**A bounded walk is not a substitute for the closure.** Measured on this corpus, a range-walk at depth 2
returns 8 projects, all of them wrong, and misses the one real exposure — a direct resolution has no
intermediate hop to walk along. At depth 4 and 8 it exceeds the admission-control cap and returns HTTP 408.
The closure answers in ~3 ms and is exact at any depth. A walk deep enough to be correct is a walk too slow
to answer.

---

## 10. Measured numbers

Corpus: 12 projects, 649 lockfile entries, 400 packages, 1,319 versions, 3,277 nodes, 18,224 edges.
Ingest 4.5 s warm (1.9 s writing, 23 statements).

| query | warm p50 | rows |
|---|---|---|
| L0 purl → id (local) | 0.01 ms | 1 |
| Q1 exact lookup | 2.2 ms | 1 |
| Q2 direct dependents | 10.5 ms | 25 |
| Q3 transitive (≤5) | 94 ms | 174 |
| Q4 lockfile entries | 16 ms | 1 |
| **Q5 exposed projects (1 hop)** | **3.0 ms** | 1 |
| Q6 shared maintainer | 8.2 ms | 1 |
| Q8 live-window overlap | 14.7 ms | 1 |

Full `simulate` run, every question answered: **310 ms**.

### The scale claim, now measured

That caveat used to end "has not been measured at 100k nodes and is not claimed". It has been measured.
`blastradius/pkg/scale.py` builds synthetic graphs through the real writer and times Q5 through the real
engine, asserting at every point that the query returned exactly the services attached to its probe — a
fast wrong answer cannot pass.

Two sweeps, because a flat line alone is unfalsifiable: it looks identical whether the query is genuinely
O(answer) or the harness is just dominated by fixed HTTP overhead.

**Sweep A — graph grows, answer held at 5 rows.** Versions and closure edges scale together:

| versions | closure edges | Q5 p50 | p95 |
|---:|---:|---:|---:|
| 5,000 | 5,015 | 1.02 ms | 1.37 ms |
| 50,000 | 50,015 | 1.59 ms | 1.91 ms |
| 500,000 | 500,015 | **1.95 ms** | 3.06 ms |

**Sweep B — one 500k graph, answer grows.** The control, and it must rise:

| answer rows | Q5 p50 | p95 |
|---:|---:|---:|
| 1 | 1.42 ms | 1.50 ms |
| 10 | 1.69 ms | 1.78 ms |
| 100 | 10.17 ms | 13.65 ms |
| 1,000 | 56.76 ms | 59.48 ms |

Expressed as elasticity — `d(log latency) / d(log input)`, so the two sweeps can be compared despite moving
different units over different spans:

    cost elasticity to graph size    0.14
    cost elasticity to answer size   0.53

**Answer size costs 3.8x what graph size does.** A 100x larger graph costs 1.9x; a 1000x larger answer costs
40x. The closure design holds. Reproduced independently at 100k and at 500k with the same two figures to two
decimal places.

**Graph size is not free, though**, and the honest form of the claim says so: 0.14 is above zero, so the
single-hop lookup does pay something as the store grows. "Flat" would be a stronger claim than the
experiment supports.

**A harder limit found on the way.** Admission control rejects a label-index scan above 250,000 candidates:

    MATCH (v:PackageVersion) RETURN v.name
    -> resource_exhausted: actual 250001 exceeds limit 250000

So past a quarter of a million versions, *any* query that is not id-pinned stops working — not slowly, but
with an HTTP 429. This is the strongest argument yet for the L0 id map: `keys_with_prefix` answers the same
question locally at any size, and every query on the read path is already pinned. It also means a label scan
is not a thing to optimise later; it is a thing that stops existing.

Run it with `python -m blastradius.pkg.cli scale --yes` — destructive, since each point needs a graph of a
known size and the only way to get one is to drop the store.

---

## 10b. Looking forwards: the blast frontier

Blast radius is backward-looking — a version is compromised, who already holds it. By the time that is
answered the artifacts are published. The TanStack worm did not spread by being depended upon; it spread by
**publishing**, and every one of its 42 packages was predictable the moment the first was known, because
publish rights are a graph the registry gives away:

```
compromised artifact --PUBLISHED_BY--> account --> everything else that account can publish
compromised package  --MAINTAINED_BY--> accounts with publish rights
compromised version  --SOURCED_FROM--> repository whose CI publishes
```

`blastradius/pkg/frontier.py` answers it in three one-hop queries over edges the ingest already writes, and
ranks the result by **fleet impact** — how many of your services resolve that package today — so the output
is ordered by what it would cost you rather than by how many rows there are.

```powershell
python -m blastradius.pkg.cli frontier pino@10.2.1
```

```
  34 package(s) reachable, 6 fleet service(s) behind them.

  LOOKED FOR, NOT FOLLOWED  published by GitHub Actions, which is a CI
  identity rather than an account. ...

  readable-stream
      fleet impact   3 service(s) resolve it today
      via maintainer matteo.collina
      confidence     INVESTIGATE
```

Every row is INVESTIGATE and cannot be anything else: all three routes map to relational atoms, and
`derive_confidence` caps those. The frontier is a list of accounts to rotate, not a list of compromises.

### The finding that shaped it: OIDC is not a shared credential

The first working version returned **77** packages for `pino@10.2.1`, most of them via one publisher
identity: `GitHub Actions`, email `npm-oidc-no-reply@github.com`. That is npm's OIDC trusted publishing
pseudo-identity, and it is stamped on every artifact pushed from a GitHub Actions workflow anywhere on npm.
`pino`, `cookie`, `semver` and `raw-body` all carry it and share no owner, no repository and no secret.

Following it was wrong twice: it invented a frontier out of unrelated packages, and it did so by reading a
*security improvement* as a risk — OIDC exists precisely so that no long-lived token is shared between
projects. `identity.is_service_identity` now recognises these, the frontier declines to draw a publisher
route from one, and says so as negative evidence. 77 rows became 34, all of them via real accounts.

## 10c. Publish-time anomalies

`blastradius/pkg/anomaly.py` reads metadata the ingest already fetches and nothing previously read back:
`has_install_script`, `published_at`, `publisher`, `repository`. Between them they describe the TanStack
compromise almost exactly — a burst of publishes, from an account outside the maintainer list, on packages
that had never carried an install script.

| signal | fires when |
|---|---|
| `INSTALL_SCRIPT_ADDED` | a version gains an install script its predecessor lacked |
| `PUBLISHER_NOT_MAINTAINER` | pushed by an account not in the maintainer list |
| `DORMANCY_BREAK` | published after a year of silence |
| `PUBLISH_BURST` | 3+ versions of one package inside 15 minutes |
| `REPOSITORY_REMOVED` / `_CHANGED` | provenance moved or disappeared |
| `CORRELATED_BURST` | **one account, many packages, one window** — the worm shape |

`CORRELATED_BURST` is the one no per-package check can see: each individual package looks like an ordinary
release, and only grouping by publishing account and sorting by time reveals it.

Two rules decide whether the output is usable, and both were learned by running it on real data:

**Unknown is not "no".** The abbreviated packument carries no maintainers, no publish times and no
repository. Treating missing data as a negative would report every package on a fast ingest as "published by
an unknown account". Each check states its preconditions and declines when they are unmet — the same
discipline `typosquat.py` applies to unknown download counts.

**Current state cannot be compared against historical publishes.** `maintainers` is the list as it stands
today; `chalk@0.5.1` was pushed in 2014 by `jbnicolai`, who was a maintainer then. Run without a recency
horizon over six ordinary packages, that check alone produced **290 rows**, none actionable. With the
90-day horizon (`RECENT_SECONDS`) the same six produced **one**. Over the full 398-package corpus it
produces one.

```powershell
python -m blastradius.pkg.cli anomalies --offline
```

---

## 10d. Real time: watching npm rather than waiting for an advisory

Everything above starts the clock when somebody else notices. `osv-scanner` reads a list of *known*
vulnerabilities, so the earliest it can tell you anything is whenever an advisory was published — which for
the TanStack worm was a good deal later than the six minutes it took to publish 84 artifacts.

npm replicates its registry as a public CouchDB change feed, and every publish lands there within seconds:

```
https://replicate.npmjs.com/_changes?since=<seq>
```

Measured here, the whole registry runs at roughly **0.85 changes per second** — a trivial volume to keep up
with, and the reason `blastradius/pkg/watcher.py` can be a poll loop rather than a pipeline. `seq` is a
resumable cursor, so a restarted watcher neither replays nor skips.

```
publish  ->  feed emits a name  ->  fetch packument (refresh=True)
         ->  is the newest version < 15 min old?  ->  it was a publish
         ->  anomaly.analyse_package  ->  is it in this fleet?  ->  SSE to the browser
```

**A change is not a publish.** The feed also fires for deprecations and dist-tag moves; measured live, about
two thirds of changes are not publishes. The recency check is what separates them, and it is why the
packument must be fetched with `refresh=True` — the registry cache has no expiry, which is right for ingest
(a published version is immutable) and fatal here, where a cache hit returns the state *before* the publish
and the watcher reports "nothing new" forever.

**Two tiers, because most of npm is not your problem.** An anomaly on a package nobody here has installed is
worth recording, not worth waking anyone. `Alert.kind` grades `publish` → `anomaly` → `fleet`, and fleet
membership is decided through the L0 id map, so it costs no graph query at 0.85 lookups a second.

### The finding that made the burst signal usable

Run against 500 consecutive live publishes, `CORRELATED_BURST` produced **seventeen** findings. The largest
was `metamaskbot` publishing **97 packages in 4.6 minutes** — quantitatively bigger than the TanStack
compromise, and entirely routine: one monorepo releasing.

So volume is necessary and nowhere near sufficient, and `CorrelatedBurst.cohesive` carries the rest. A burst
whose packages all sit under one npm scope, or all build out of one repository, is a monorepo doing what
monorepos do. A burst spread across unrelated scopes *and* repositories is an account reaching places it has
no reason to reach at once. Spread bursts sort above cohesive ones however much smaller they are.

On the same feed after the change: four bursts, **all four correctly classified as releases**, zero false
worm alerts. Unscoped packages from unknown repositories are explicitly *not* cohesive — treating absent
provenance as shared provenance would mark the widest possible spread as a tidy release.

## 10e. The console

`python -m blastradius.cli ui` serves three pages. `/graph` is the new one.

**Point it at any repository.** The path box takes any checkout with a `package-lock.json`; the server
validates it (refusing system directories and naming what was wrong), runs the whole pipeline on a thread,
and streams stage progress. Everything downstream — the graph, the watcher's notion of "your fleet", the
simulation — is defined by whatever was ingested. Pointed at this repository it finds 15 services and 22
advisory links in about 24 seconds.

**The whole graph as circles.** `/api/graph/full` sweeps every node and edge once and caches against
`read_epoch`; on the corpus that is ~3,200 nodes and ~11,500 edges in about 2.6 s cold, 60 ms warm. The
canvas lays them out with a two-scale force simulation — exact repulsion within a 3×3 grid neighbourhood,
plus a coarse cell-centroid term beyond it. The far term is not an optimisation: with near-field alone
nothing pushes one cluster away from another and the graph relaxes into a uniform disc, every node locally
well-spaced and the structure invisible.

Colour is assigned by job, and **three** categorical hues is not an arbitrary stop. This is a node-link
diagram, so any two classes can end up adjacent; under all-pairs validation the reference palette's first
three slots are the documented-safe set in both modes, and a fourth fails (violet collapses into blue in
dark at CVD ΔE 1.9). Everything finer is size, or filled-versus-ring. Status colours sit outside the
categorical set.

**Simulate a compromise.** Pick a package — or press the button and get a random one, with the range-only
over-report quoted next to it — and the server marks a synthetic incident, runs the blast radius, the
frontier and the advisories, and streams each stage. The affected nodes hold a pulsing highlight and the
camera frames them; *Reset* retracts the incident and the graph goes back as it was.

The incident is synthetic and points at an ordinary healthy public package: nothing is downloaded, nothing
is executed, and no package is modified.

---

## 10f. The Explorer: the last mile, from a threat to a function

`/explorer` answers two questions in order, and it exists because the second one is the one that decides
what you do on the morning of an incident.

**1 · What is confirmed wrong?** Published advisories, recorded incidents, registry deprecations — grouped
by *version*, not by advisory. Three CVEs on `lodash@4.17.20` are one thing to go and fix, and listing them
as three findings triples the apparent size of the problem without adding an action.

**2 · Can any of it be reached from a line of code here?** This repository resolves **1,703 package
versions** and contains **8 external imports**. Almost nothing in the tree is named by source. So the walk
continues past "installed":

```
Advisory -> PackageVersion -> (dependency chain) -> ExternalImport -> Function -> callers
```

Measured against this repository: **2 of 13** confirmed threats are reachable from its 180 scanned
functions. `vite@5.4.21` (CVE-2026-53571, high) is reached twice — directly as `import { defineConfig } from
"vite"`, and again one hop down through `@vitejs/plugin-react@4.7.0` — both landing in `vite.config.js`.
`esbuild@0.21.5` is reached through the same file at one and two hops. The other eleven are installed and
never imported.

**"Not reached" is not "not affected", and the wording has to carry that.** The package really is installed
and the advisory really does apply; nothing here imports it. That is the difference between *patch now* and
*patch Tuesday*, and a list that cannot draw it is the flat lockfile scan this project exists to improve on.
A test asserts the phrasing never says "false positive" or "not affected".

**Ordering puts reachability above severity.** A moderate finding a route handler calls is a worse Monday
than a critical one on a transitive dev dependency nothing imports. Sorting on severity alone buries the
finding that has a file to open, so `Threat.rank` sorts on code reach first and severity second.

**Why the diagram has three hues and not four.** The obvious split — red threat, aqua package, orange
import, blue function — **fails all-pairs validation in both modes**: red against orange lands at
normal-vision ΔE 7.1, well under the floor of 15, meaning full-colour readers cannot reliably separate them
either. No amount of secondary encoding excuses that. Orange was dropped and the fourth distinction is
carried by filled-versus-ring within a family. Red against aqua sits at ΔE 6.9 (light) / 6.5 (dark), inside
the 6–8 band that is legal *with* secondary encoding, and it has four: fixed column position, a text label
on every node, distinct radii, and a permanent legend.

Layout is a fixed layered DAG, not a force solver: the columns *are* the semantics, and letting physics
decide left-to-right order would scramble the one thing the picture is for. Within a column, two barycentre
passes cut edge crossings.

### The bug this surfaced: a drill that could not be retracted

Building the threat list turned up eight packages marked `SIMULATED_COMPROMISED` by one incident node whose
summary named only the last of them.

`create_incident` defaulted its `incident_id` to a shared literal `"SYNTHETIC-001"`. `clear_incident`
defaulted to `incident_id_for(package, version)` — the per-version id. The two defaults disagreed, silently
and cumulatively: every drill hung another `COMPROMISES` edge off the one shared node and overwrote its
summary, while every *Reset* looked up an id that had never been written, found nothing, and reported
success. Eight drills against this repository left eight packages permanently compromised in the graph.

`incident_id_for` was correct, and had been unit-tested since it was written. That was not enough, because
the generator was never the part that was wrong — nothing pinned that `create_incident` *used* it. The
defaults now agree, and a test pins the pairing itself rather than the generator.

---

## 11. Known gaps

- **CVSS base score is not derived from the vector.** The OSV CSV leaves `severity_score` empty while
  populating `cvss_vector`. The score stays at its sentinel and the UI shows the vector; showing a number
  nobody computed would be worse than showing none. Deferred by agreement.
- **The supplied OSV CSV is 100% PyPI.** The reader is ecosystem-generic and routes on the `ecosystem`
  column; the graph and enrichment are npm. PyPI rows ingest as advisories and are reported as
  out-of-scope-for-enrichment rather than silently dropped. An npm-shaped CSV exercises the full path.
- **The package view is scoped to one version at a time.** That is deliberate — the answer is a single-hop
  lookup, and a whole-graph package sweep would be 3,277 nodes of DOM. But it means there is no "show me
  every marked version at once" overview yet.
- **The relational columns are capped at 24 drawn nodes.** The count in the header and the footer metric is
  the true one, so the cap never understates; but a package with 300 siblings shows 24 of them.
- **Typosquat coverage depends on download data.** npm's bulk endpoint declines scoped packages; unknown
  popularity is treated as unknown, not zero, so scoped packages are not assessed for asymmetry. Correct,
  but it means scoped squats are currently out of reach.
- **`PUBLISH_BURST` cannot tell a coordinated backport from a worm.** On the real corpus it fires on
  `@types/node` shipping 22.x, 24.x and 25.x in the same second, and on `ws` publishing 5.2.5 / 6.2.4 /
  7.5.11 within a minute — a security fix backported across maintained majors. The *shape* is exactly right
  and the cause is benign, which is why it is INVESTIGATE rather than a finding. Distinguishing them needs
  the diff, not the metadata.
- **`CORRELATED_BURST` cohesion is a heuristic, not proof.** Scope and repository separate a monorepo
  release from a spread, and on the live feed that took seventeen findings down to zero false alarms. But an
  attacker who compromises one maintainer of one monorepo produces a *cohesive* burst and is graded a
  release; conversely a maintainer who genuinely owns unrelated projects and releases them together is
  graded a spread. The rule buys precision at a known cost in recall.
- **The watcher sees npm, not your registry.** A private or proxied registry publishes nothing to
  `replicate.npmjs.com`, so an internal package is invisible to the live path. The static ingest still
  covers it.
- **Live alerts are memory only.** The watcher is an early-warning surface, not a system of record: alerts
  live in a 500-entry ring buffer and a restart loses them. Anything that matters is also written to the
  graph by an ingest.
- **The recency horizon means the tool has no memory.** A compromise older than 90 days is invisible to
  the anomaly checks by default. That is the right default for incident response and the wrong one for
  forensics; `horizon_seconds=None` assesses the whole history.
- **The scale harness is synthetic.** It answers a complexity question, which does not need real names, and
  it drives the real writer and the real engine. It does not tell you how a 500k-node graph built from
  *actual* npm data would behave — dependency fan-out there is heavily skewed, and this generator's is not.
- **`.blastradiusignore` is trusted, not verified.** A repository declares which of its directories are not
  its own code, and the scan believes it. That is the right default — nobody else can know that `corpus/` is
  a demo — but it means a mis-scoped ignore silently narrows the graph. Skips are reported everywhere they
  happen (`repo/inspect`, `doctor`, the scan notes) precisely because the failure would otherwise look like
  a small repo rather than a wrong one.
- **The OSV binary scanner cannot be scoped, only filtered afterwards.** `osv-scanner scan --recursive`
  walks the tree itself with no knowledge of the ignore file, so findings from ignored paths are dropped
  *after* the scan by matching each row's `source_file`. A row with no source attribution is kept rather
  than guessed at. It costs a little scan time on directories whose results are then discarded.
- **"Not reached from code" is only as true as the code scan.** The Explorer's second section reads the
  micro tier, so a repository ingested *without* the AST scanner has zero functions and zero imports — and
  every finding then reports "installed only". That failure mode reads as good news and is not; the header
  states the denominator (`… of the 180 function(s) scanned in this repository`) precisely so a zero is
  visible rather than reassuring. Treat an unscanned repo as unknown, not clean.
- **Import reach is per-specifier, not per-export.** A file that imports `lodash` and uses only `_.map`
  reports reach for a CVE in `_.template`. The graph records which module a function imports, not which
  binding it touched, so this over-reports within a reached package. It never under-reports.
- **The caller walk stops at two hops.** Deeper callers are counted and reported, never silently dropped,
  but they are not drawn: a caller tree that runs off the canvas hides the first two hops that matter.
