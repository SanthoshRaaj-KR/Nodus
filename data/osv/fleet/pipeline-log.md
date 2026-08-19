# Blast Radius pipeline log

generated 2026-08-19 11:04:48

- repository: `C:\Users\santh\.vscode\Programming\Hackathons\Luma-Hydra\blastradius\corpus\fleet`
- scanner engine: `osv-scanner`
- findings: 14 rows -> 8 advisories after alias merge
- Advisory nodes in graph: 8
- AFFECTS edges: 11

## Timing

```
step                           seconds   share  detail
---------------------------  ---------  ------  --------------------------------------------
preflight                        0.122    0.7%  node ready
reset                            2.936   17.2%  store dropped, id map cleared, node back up
osv scan                         1.783   10.5%  14 finding(s), 8 advisory(ies) via osv-scanner
  scan: discover manifests       0.002    0.0%  package-lock=12, requirements=0
  scan: osv scan (binary)        1.699   10.0%  14 row(s) via osv-scanner
  scan: write csv                0.001    0.0%  osv_scan_results.csv (20,099 bytes)
  scan: merge aliases            0.043    0.3%  14 findings -> 8 advisories after alias merge (npm=14)
  scan: write advisory json      0.007    0.0%  8 file(s)
code graph ingest                8.236   48.4%  447 nodes, 2,662 edges
package tier ingest              3.555   20.9%  1,317 versions, 8 advisories, 649 closure edges
verify                           0.392    2.3%  8 Advisory nodes, 11 AFFECTS edges
---------------------------  ---------  ------
TOTAL                           17.025  100.0%
```

## Scan detail

```
repo            C:\Users\santh\.vscode\Programming\Hackathons\Luma-Hydra\blastradius\corpus\fleet
engine          osv-scanner
manifests       package-lock=12
findings        14
advisories      8  (after alias merge)
vulnerable pkgs 4
ecosystems      npm=14
csv             C:\Users\santh\.vscode\Programming\Hackathons\Luma-Hydra\blastradius\data\osv\fleet\osv_scan_results.csv
advisory json   8 file(s) in C:\Users\santh\.vscode\Programming\Hackathons\Luma-Hydra\blastradius\advisories\generated

most-affected versions
    lodash@4.17.20                           5 advisory row(s)
    fastify@4.29.1                           3 advisory row(s)
    lodash@4.17.21                           3 advisory row(s)
    find-my-way@8.2.2                        1 advisory row(s)
    uuid@8.3.2                               1 advisory row(s)
    uuid@9.0.1                               1 advisory row(s)

step                   seconds   share  detail
-------------------  ---------  ------  --------------------------------------------
discover manifests       0.002    0.1%  package-lock=12, requirements=0
osv scan (binary)        1.699   96.6%  14 row(s) via osv-scanner
write csv                0.001    0.1%  osv_scan_results.csv (20,099 bytes)
merge aliases            0.043    2.5%  14 findings -> 8 advisories after alias merge (npm=14)
write advisory json      0.007    0.4%  8 file(s)
-------------------  ---------  ------
TOTAL                    1.759  100.0%
```

## Graph contents

| label | nodes |
|---|---:|
| Service | 24 |
| PackageVersion | 1,752 |
| Package | 398 |
| Lockfile | 12 |
| LockfileEntry | 649 |
| Maintainer | 305 |
| Repository | 389 |
| Organization | 13 |
| PublisherIdentity | 166 |
| Advisory | 8 |

## Package tier

```
projects        12
lockfiles       12
lock entries    649
packages        398
versions        1,317
REQUIRES        2,952
SATISFIED_BY    4,262
closure         649
maintainers     305
repositories    389
typosquat       0
advisories      8
unresolved deps 5

bounds: newest 3 version(s) per package, <= 8 SATISFIED_BY per requirement

ingest took 3.5s
```
