# Blast Radius pipeline log

generated 2026-08-19 13:38:57

- repository: `C:\Users\santh\.vscode\Programming\Hackathons\Luma-Hydra\blastradius\corpus`
- scanner engine: `osv-scanner`
- findings: 5 rows -> 3 advisories after alias merge
- Advisory nodes in graph: 3
- AFFECTS edges: 5

## Timing

```
step                           seconds   share  detail
---------------------------  ---------  ------  --------------------------------------------
preflight                        0.100    0.5%  node ready
reset                            2.873   14.8%  store dropped, id map cleared, node back up
osv scan                         1.432    7.4%  5 finding(s), 3 advisory(ies) via osv-scanner
  scan: discover manifests       0.003    0.0%  package-lock=1, requirements=0
  scan: osv scan (binary)        1.353    7.0%  5 row(s) via osv-scanner
  scan: write csv                0.001    0.0%  osv_scan_results.csv (21,586 bytes)
  scan: merge aliases            0.032    0.2%  5 findings -> 3 advisories after alias merge (npm=5)
  scan: write advisory json      0.003    0.0%  3 file(s)
code graph ingest                1.535    7.9%  755 nodes, 3,139 edges
package tier ingest             13.116   67.5%  984 versions, 3 advisories, 338 closure edges
verify                           0.381    2.0%  3 Advisory nodes, 5 AFFECTS edges
---------------------------  ---------  ------
TOTAL                           19.437  100.0%
```

## Scan detail

```
repo            C:\Users\santh\.vscode\Programming\Hackathons\Luma-Hydra\blastradius\corpus
engine          osv-scanner
manifests       package-lock=1
findings        5
advisories      3  (after alias merge)
vulnerable pkgs 3
ecosystems      npm=5
csv             C:\Users\santh\.vscode\Programming\Hackathons\Luma-Hydra\blastradius\data\osv\corpus\osv_scan_results.csv
advisory json   3 file(s) in C:\Users\santh\.vscode\Programming\Hackathons\Luma-Hydra\blastradius\advisories\generated

most-affected versions
    brace-expansion@1.1.17                   1 advisory row(s)
    brace-expansion@2.1.3                    1 advisory row(s)
    brace-expansion@5.0.8                    1 advisory row(s)
    fast-uri@3.1.4                           1 advisory row(s)
    js-yaml@4.3.0                            1 advisory row(s)

step                   seconds   share  detail
-------------------  ---------  ------  --------------------------------------------
discover manifests       0.003    0.2%  package-lock=1, requirements=0
osv scan (binary)        1.353   96.7%  5 row(s) via osv-scanner
write csv                0.001    0.1%  osv_scan_results.csv (21,586 bytes)
merge aliases            0.032    2.3%  5 findings -> 3 advisories after alias merge (npm=5)
write advisory json      0.003    0.2%  3 file(s)
-------------------  ---------  ------
TOTAL                    1.400  100.0%
```

## Graph contents

| label | nodes |
|---|---:|
| Service | 2 |
| PackageVersion | 1,322 |
| File | 11 |
| Function | 384 |
| ExternalImport | 15 |
| PersistenceArtifact | 6 |
| Package | 294 |
| Lockfile | 1 |
| LockfileEntry | 338 |
| Maintainer | 217 |
| Repository | 290 |
| Organization | 12 |
| PublisherIdentity | 123 |
| Advisory | 3 |

## Package tier

```
projects        1
lockfiles       1
lock entries    338
packages        294
versions        984
REQUIRES        2,287
SATISFIED_BY    3,187
closure         338
maintainers     217
repositories    290
typosquat       1
advisories      3

bounds: newest 3 version(s) per package, <= 8 SATISFIED_BY per requirement

ingest took 13.1s
```
