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

# Latency + the two experiments
python -m blastradius.pkg.cli bench lodash@4.17.21
```

`simulate` prints direct dependents, transitive dependents, lockfiles resolving the exact version, exposed
projects with depth and witness, live-window matches, shared maintainer / repository / publisher, typosquat
neighbours, findings by confidence, and a per-query latency table.

**Safety:** the incident is synthetic and points at one ordinary, healthy public package. Nothing is
downloaded, nothing is executed, and no package is modified. We are testing graph logic.

---

## 7. Testing it

```powershell
python -m pytest tests/ -q                              # 246 tests
python tests/verify_constraints.py                      # HydraDB behaviour vs assumptions
python tests/difftest_semver.py --semver-dir <dir with node_modules/semver>
```

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
the one divergence is documented in §8.

To check the version-awareness claim by hand:

```powershell
python -m blastradius.pkg.cli simulate lodash@4.17.21 | Select-String "EXPOSED PROJECTS" -A 3
python -m blastradius.pkg.cli simulate lodash@4.17.20 | Select-String "EXPOSED PROJECTS" -A 3
```

Different projects. If those ever return the same set, the version-awareness is broken.

---

## 8. What measurement changed

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

## 9. Measured numbers

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

Scale caveat, stated rather than buried: this is a 12-project, 3.3k-node graph. The L1 design means the
headline query is a single-hop adjacency lookup whose cost tracks the number of projects resolving one
version, not graph size — but that has not been measured at 100k nodes and is not claimed.

---

## 10. Known gaps

- **CVSS base score is not derived from the vector.** The OSV CSV leaves `severity_score` empty while
  populating `cvss_vector`. The score stays at its sentinel and the UI shows the vector; showing a number
  nobody computed would be worse than showing none. Deferred by agreement.
- **The supplied OSV CSV is 100% PyPI.** The reader is ecosystem-generic and routes on the `ecosystem`
  column; the graph and enrichment are npm. PyPI rows ingest as advisories and are reported as
  out-of-scope-for-enrichment rather than silently dropped. An npm-shaped CSV exercises the full path.
- **No visualization yet for the package graph.** The Explorer UI on `master` renders the macro/micro code
  graph and its `KIND` registry is a fixed set, so package-graph node types (Maintainer, Repository,
  Incident) cannot be expressed without editing it. Next step, and worth agreeing on the approach first.
- **Typosquat coverage depends on download data.** npm's bulk endpoint declines scoped packages; unknown
  popularity is treated as unknown, not zero, so scoped packages are not assessed for asymmetry. Correct,
  but it means scoped squats are currently out of reach.
