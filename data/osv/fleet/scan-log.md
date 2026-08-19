# OSV scan log

generated 2026-08-19 11:04:00

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
osv scan (binary)        2.235   97.1%  14 row(s) via osv-scanner
write csv                0.001    0.0%  osv_scan_results.csv (20,099 bytes)
merge aliases            0.049    2.1%  14 findings -> 8 advisories after alias merge (npm=14)
write advisory json      0.007    0.3%  8 file(s)
-------------------  ---------  ------
TOTAL                    2.301  100.0%
```
