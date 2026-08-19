# OSV scan log

generated 2026-08-19 13:29:00

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
discover manifests       0.009    0.5%  package-lock=15, requirements=0
osv scan (binary)        1.717   95.2%  19 row(s) via osv-scanner
write csv                0.001    0.1%  osv_scan_results.csv (26,775 bytes)
merge aliases            0.052    2.9%  19 findings -> 13 advisories after alias merge (npm=19)
write advisory json      0.012    0.6%  13 file(s)
-------------------  ---------  ------
TOTAL                    1.803  100.0%
```
