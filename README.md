# Blast Radius

**Track 2A / problem A — supply chain blast radius.**

A package is compromised at 09:00. Which of your services are exposed by 09:06,
and does your code actually *run* the poisoned dependency?

`npm audit` answers the first half of that for one repo. This answers both
halves across a fleet, and tells you which alerts you can safely ignore.

---

## The idea in one paragraph

The problem statement frames this as a traversal over the npm ecosystem graph —
tens of millions of versioned nodes. We do not build that graph, because we do
not need it. **A `package-lock.json` v3 already is a fully-resolved dependency
graph**: every entry under `packages` names its own resolved dependencies. So
scanning a fleet of repos yields an exact dependency graph with no registry
crawl, no semver re-resolution and no approximation.

That gets you the macro graph. On its own it is still just a lockfile scanner.
The differentiator is the second graph, built with `ts-morph` over the real
TypeScript compiler API, and the bridge between them:

```
[Service: payment-api]
       |
       +--> (macro / lockfile) ----> [PackageVersion: vulnerable-pkg@1.0.5]
       |                                          ^
       +--> (micro / AST)                         | RESOLVES_TO
            [File: src/token.ts]                  |
               +- [Function: verify()] --CALLS_EXTERNAL--+
                     ^
                     +--CALLS-- [Function: handleLogin()]
                                      ^
                                      +--HANDLED_BY-- [Route: POST /login]
```

The macro graph says *you have it*. The micro graph says *an HTTP request can
reach it*. Those are very different incidents.

---

## Severity tiers

| Tier | Meaning |
|---|---|
| **P0 CONFIRMED** | Exposed **and** a persistence artifact is on disk. The worm wrote into `.claude/` or `.vscode/`, so `npm uninstall` does not clear it. |
| **P1 REACHABLE** | Exposed **and** an HTTP route reaches the calling function. |
| **P2 IMPORTED** | Exposed and imported from source, but no route path found. |
| **P3 INSTALLED** | In the lockfile, never imported. **Safe to deprioritise.** |

P3 is not filler. Telling a team which 30 of 40 alerts they can ignore at 09:06
is where most of the saved time in a real incident comes from, and it is the one
thing a flat lockfile scan structurally cannot do.

---

## Quick start

Everything runs through one Python entry point — no `.ps1` required, so you
never have to touch PowerShell's execution policy.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # cmd.exe: .\.venv\Scripts\activate.bat
pip install -r requirements.txt
cd scanner; npm install; cd ..        # ts-morph, once

python -m blastradius.cli doctor      # checks every prerequisite, names the fix
python -m blastradius.cli up          # start the HydraDB container
python -m blastradius.cli ingest      # scan the corpus into the graph
python -m blastradius.cli ui          # Blast Radius Explorer, port 8100
```

If `Activate.ps1` is blocked, either use the `.bat` above or run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once. Nothing else in
this project needs it.

`hydra.ps1` still exists and does the same job, but `blastradius.node` drives
Docker from Python and is the supported path.

Then open <http://127.0.0.1:8000>, pick an advisory, and hit **Simulate 09:00**.

## The Explorer

`ui/` is a separate frontend server from `blastradius/api/`. That one is the
machine-facing assessment API a CI job would call; this is the human-facing
explorer. Keeping them apart means the demo surface can be restarted or
re-skinned without touching what other tools depend on, and it reads HydraDB
directly rather than proxying — one fewer moving part to fail on stage.

**Macro — the supply chain.** Services, then packages by resolved depth. The
queried package and everything that reaches it burn red; the rest dims.

![Macro view](docs/screens/macro.png)

**Micro — the call graph.** The claim no lockfile scanner can make:
`src/index.ts → POST /login → handleLogin() → verify() → import 'vulnerable-pkg'`.

![Micro view](docs/screens/micro.png)

Note what is *dimmed* there: `GET /health`, `unusedHelper()`, `import 'express'`.
That is the "safe to ignore" signal, and it is the half of an incident response
that actually saves time.

Edges carry arrowheads and the column gutters carry chevrons, so the direction
the graph reads is stated rather than implied. On the hot path the dashes flow
along the arrow.

Clicking any node opens metadata and the reachability path:

![Detail panel](docs/screens/detail-panel.png)

It is responsive down to phone width: the graph auto-fits (shrink only — a
four-node graph blown up to fill a monitor implies more than is there), the
detail drawer becomes a bottom sheet, chips and metrics scroll sideways, and
the legend drops since the column headers already carry the colours. A
zoom/fit control sits bottom-right; touching it hands you manual control and
stops the auto-fit from fighting you on resize.

![Phone width](docs/screens/mobile.png)

The whole graph is sent to the browser once per view and the blast radius is a
reverse BFS in JS, so typing in the search box costs no round trips. That only
works because the graph is small; at fleet scale the highlighting moves server
side, onto the same `PRESENT_IN` and `CALLED_BY` edges the CLI already uses.

The design came from a Claude Design project and is implemented here in vanilla
JS — the source `.dc.html` targets a React template runtime we do not ship.

### Scanning any Node app (micro graph only)

The macro graph needs a resolved lockfile. The call graph needs only source, so
it has its own entry point that skips the lockfile and the bridge entirely:

```powershell
python -m blastradius.cli reset                    # clear graph + id map together
python -m blastradius.cli scan ..\some-node-app
python -m blastradius.cli ui
```

![Real application](docs/screens/real-app.png)

Without the bridge an import carries no resolved version, so searching by
package name still highlights but "which version" stays a macro-graph question.

**Clearing state:** `reset` drops every node *and* deletes `data/ids.sqlite`.
Those must go together. Deleting the Docker volume alone is harmless (ids just
continue from a higher counter), but deleting `ids.sqlite` while the graph
still holds data gives every node a fresh id and duplicates the lot.

### Or from the terminal

```powershell
python -m blastradius.cli stats                            # what is in the graph
python -m blastradius.cli services                         # ingested services
python -m blastradius.cli check vulnerable-pkg@1.0.5       # one package
python -m blastradius.cli check express --range ">=4.18.0 <4.19.0"
python -m blastradius.cli advisory advisories\GHSA-vuln-pkg-2026.json
```

`check` prints the macro answer, the micro answer, and the verdict in one pass,
and exits non-zero when anything lands in P0 or P1 — so it doubles as a CI gate.

Run everything Docker-related from **PowerShell, never Git Bash**. Git Bash
rewrites container-side absolute paths — `/data/store` arrives as
`C:/Program Files/Git/data/store` — and the node dies with a bare
`PermissionDenied` that names no path.

---

## The graph model

**Macro (lockfile)**

| Edge | From → To |
|---|---|
| `DEPENDS_ON` | Service → PackageVersion, PackageVersion → PackageVersion |
| `REQUIRED_BY` | materialised inverse |
| `PRESENT_IN` | PackageVersion → Service — the flattened transitive closure |
| `HAS_PACKAGE` | materialised inverse |

**Micro (ts-morph AST)**

| Edge | From → To |
|---|---|
| `CONTAINS` | File → Function |
| `CALLS` / `CALLED_BY` | Function → Function, and its inverse |
| `CALLS_EXTERNAL` / `IMPORT_USED_BY` | Function → ExternalImport, and its inverse |
| `HANDLED_BY` / `HANDLES` | Route → Function, and its inverse |

**Bridge**

| Edge | From → To |
|---|---|
| `RESOLVES_TO` / `IMPORTED_AS` | ExternalImport → PackageVersion, and its inverse |

`ExternalImport` is keyed per **(service, specifier)**, not globally, because two
services can resolve `lodash` to different versions — and that difference is
exactly what the tool exists to surface.

---

## Two decisions that are not obvious

### Every edge is written twice

HydraDB requires a variable-length traversal to **pin the source id**; `*` and
`*1..` are rejected and patterns are directed with exactly one type. A backward
walk is therefore not expressible at all. Every "who reaches this" question is a
forward walk over a materialised inverse edge, written at ingest. See
`INVERSE_OF` in `blastradius/schema.py` — it is the reason ingest writes each
edge in both directions, not an optimisation.

### `PRESENT_IN` is a flattened closure, not a traversal

A variable-length walk must declare a maximum depth. Real npm trees are
routinely deeper than any bound worth hardcoding, so answering "is this package
in that service" with `[:REQUIRED_BY*1..8]` would **silently under-report** deep
exposure — the failure mode that most flatters the tool. The closure is computed
in Python at ingest instead, which makes the query exact at any depth *and*
turns it into a single hop. Call-graph walks still use a bound (`MAX_CALL_DEPTH`,
8) because call chains genuinely are short; the bound is returned in the API
response so nobody mistakes a truncated answer for a complete one.

---

## HydraDB constraints worth knowing before you edit a query

These were all found the hard way, by being rejected at runtime. They are not
in `cypher-compat.md`, so they are written down here.

| Constraint | Consequence |
|---|---|
| Variable-length needs a pinned source and an upper bound | materialised inverse edges; flattened closure |
| **`UNWIND … MATCH … MERGE` (write) requires exactly one label per endpoint** | edges are batched per `(type, src label, dst label)`, since `REQUIRED_BY` spans two label pairs |
| **`UNWIND … MATCH … RETURN` (read) forbids labels**, demands the first projection be the source field, and accepts exactly two unsorted projections | reads never use `UNWIND` — they issue one plain `MATCH` per id with a scalar `$id`, where labels and full projections both work |
| **A list parameter is accepted only as `UNWIND` input** | `algo.MSpaths` cannot take `sourceValues` as `$param`; the list is inlined as a literal (escaped in `_literal_list`) |
| **Admission control caps `client_query_runtime_ms`** (30 s stock) | asking for more is an HTTP 429; the client defaults to 25 s |
| No `IN`, `CONTAINS`, `ENDS WITH`, `IS NULL` in `WHERE` | every property is always written, using sentinels |
| No string functions | semver matching happens in Python, which feeds exact ids to the graph |
| Relationships are reified with their own global `id` | a persisted id allocator is mandatory — `blastradius/ids.py` |
| `sum`/`avg` unsigned ints only | timestamps are epoch-second integers |
| No transactions, one statement per request | writes are `UNWIND`-batched auto-commits; `MERGE` by id makes re-runs idempotent |

The write/read asymmetry on `UNWIND` is the one that will bite an editor:
**writes are label-qualified, reads are not.** Do not make them match — the
server rejects whichever one you change.

Base list: `../hydradb/cypher-compat.md`.

---

## The advisory contract

Advisory discovery is the other half of the team. They produce this, we consume
it — samples live in `advisories/`:

```json
{
  "advisory_id": "GHSA-xxxx-yyyy-zzzz",
  "ecosystem": "npm",
  "package": "@tanstack/react-query",
  "affected_versions": ["5.62.3", "5.62.4"],
  "affected_range": ">=5.62.3 <5.62.5",
  "published_at": 1747900800,
  "withdrawn_at": 1747901160,
  "severity": "critical",
  "iocs": {
    "paths": [".claude/hooks/*.js"],
    "content_markers": ["eval(atob("]
  }
}
```

`affected_versions` is preferred. When only `affected_range` is given, it is
resolved against the versions we actually hold (`blastradius/query/advisory.py`)
— so an advisory covering 400 versions costs the same as one covering two.

---

## Layout

```
hydra.ps1                    node lifecycle + query CLI
scanner/scan.mjs             ts-morph AST scanner -> micro graph JSON
blastradius/
  schema.py                  labels, edge types, id blocks, sentinels
  ids.py                     persisted key -> id allocator (data/ids.sqlite)
  hydra_client.py            HTTP client, UNWIND batching, Bolt fallback
  ingest/
    lockfile.py              package-lock v2/v3 + npm nested resolution
    bridge.py                ExternalImport -> PackageVersion
    persistence.py           .claude/ .vscode/ IOC scan
    load.py                  orchestration, closure, batched writes
  query/
    advisory.py              semver ranges -> exact PackageVersion keys
    blast.py                 Q1..Q5 and the severity composition
  api/main.py                FastAPI
  api/static/index.html      single-page UI, self-contained
corpus/                      target repos
advisories/                  the teammate contract, as files
tests/test_oracle.py         graph answer == brute-force answer
```

---

## Verification

```powershell
python -m pytest tests/test_oracle.py -v
```

The suite compares our closure against a deliberately stupid brute-force oracle
that re-implements npm resolution independently, so an error in one is unlikely
to be mirrored in the other. Two tests need a live node and skip themselves when
HydraDB is not reachable: the graph-vs-brute-force check and the idempotent
re-ingest check.

**Known limitations, stated rather than papered over:**

- Route detection is Express/Fastify-shaped and pattern-based. A route
  registered by decorator or built from a dynamic table is missed; the scanner
  reports its counts in `stats` rather than claiming to be exhaustive.
- Dynamic dispatch (`obj[name]()`, callbacks through a registry) cannot be
  resolved by any static analyser and is counted in `stats.dynamicCalls`.
- `P2 IMPORTED` means the package is imported by *your* source. A transitive
  dependency is imported by an intermediate package's code, not yours, so for
  deep dependencies the reachability signal comes from the direct dependency
  that leads to it.
- Lockfile v1 is rejected loudly rather than parsed partially — a half-parsed
  lockfile would read as "this repo is clean", which is the worst possible way
  to be wrong.
