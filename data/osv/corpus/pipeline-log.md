# Blast Radius pipeline log

generated 2026-08-19 13:29:33

- repository: `C:\Users\santh\.vscode\Programming\Hackathons\Luma-Hydra\blastradius\corpus`
- scanner engine: `osv-scanner`
- findings: 19 rows -> 13 advisories after alias merge
- Advisory nodes in graph: 13
- AFFECTS edges: 16

## Timing

```
step                           seconds   share  detail
---------------------------  ---------  ------  --------------------------------------------
preflight                        0.135    0.3%  node ready
reset                            2.845    6.7%  store dropped, id map cleared, node back up
osv scan                         1.798    4.2%  19 finding(s), 13 advisory(ies) via osv-scanner
  scan: discover manifests       0.008    0.0%  package-lock=15, requirements=0
  scan: osv scan (binary)        1.700    4.0%  19 row(s) via osv-scanner
  scan: write csv                0.001    0.0%  osv_scan_results.csv (26,775 bytes)
  scan: merge aliases            0.048    0.1%  19 findings -> 13 advisories after alias merge (npm=19)
  scan: write advisory json      0.008    0.0%  13 file(s)
code graph ingest                8.333   19.6%  2,380 nodes, 12,058 edges
package tier ingest             28.592   67.1%  4,250 versions, 13 advisories, 1,769 closure edges
verify                           0.905    2.1%  13 Advisory nodes, 16 AFFECTS edges
---------------------------  ---------  ------
TOTAL                           42.609  100.0%
```

## Scan detail

```
repo            C:\Users\santh\.vscode\Programming\Hackathons\Luma-Hydra\blastradius\corpus
engine          osv-scanner
manifests       package-lock=15
findings        19
advisories      13  (after alias merge)
vulnerable pkgs 7
ecosystems      npm=19
csv             C:\Users\santh\.vscode\Programming\Hackathons\Luma-Hydra\blastradius\data\osv\corpus\osv_scan_results.csv
advisory json   13 file(s) in C:\Users\santh\.vscode\Programming\Hackathons\Luma-Hydra\blastradius\advisories\generated

most-affected versions
    lodash@4.17.20                           5 advisory row(s)
    fastify@4.29.1                           3 advisory row(s)
    lodash@4.17.21                           3 advisory row(s)
    body-parser@1.20.1                       2 advisory row(s)
    express@4.18.2                           2 advisory row(s)
    find-my-way@8.2.2                        1 advisory row(s)
    ua-parser-js@0.7.29                      1 advisory row(s)
    uuid@8.3.2                               1 advisory row(s)

step                   seconds   share  detail
-------------------  ---------  ------  --------------------------------------------
discover manifests       0.008    0.5%  package-lock=15, requirements=0
osv scan (binary)        1.700   95.8%  19 row(s) via osv-scanner
write csv                0.001    0.0%  osv_scan_results.csv (26,775 bytes)
merge aliases            0.048    2.7%  19 findings -> 13 advisories after alias merge (npm=19)
write advisory json      0.008    0.5%  13 file(s)
-------------------  ---------  ------
TOTAL                    1.774  100.0%
```

## Graph contents

| label | nodes |
|---|---:|
| Service | 30 |
| PackageVersion | 5,632 |
| File | 45 |
| Function | 892 |
| ExternalImport | 36 |
| Route | 3 |
| PersistenceArtifact | 7 |
| Package | 1,197 |
| Lockfile | 15 |
| LockfileEntry | 1,769 |
| Maintainer | 749 |
| Repository | 877 |
| Organization | 70 |
| PublisherIdentity | 393 |
| Advisory | 13 |

## Package tier

```
projects        15
lockfiles       15
lock entries    1,769
packages        1,197
versions        4,250
REQUIRES        17,373
SATISFIED_BY    24,123
closure         1,769
maintainers     749
repositories    877
typosquat       7
advisories      13
unresolved deps 27

bounds: newest 3 version(s) per package, <= 8 SATISFIED_BY per requirement

ingest took 28.5s
```
