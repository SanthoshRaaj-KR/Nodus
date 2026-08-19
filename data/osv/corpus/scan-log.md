# OSV scan log

generated 2026-08-19 13:38:29

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
discover manifests       0.005    0.3%  package-lock=1, requirements=0
osv scan (binary)        1.430   96.8%  5 row(s) via osv-scanner
write csv                0.002    0.1%  osv_scan_results.csv (21,586 bytes)
merge aliases            0.030    2.0%  5 findings -> 3 advisories after alias merge (npm=5)
write advisory json      0.004    0.2%  3 file(s)
-------------------  ---------  ------
TOTAL                    1.478  100.0%
```
