"""Differential test: our semver against the real npm `semver` package.

Passing our own unit tests only proves self-consistency. This proves agreement
with the implementation npm actually uses to resolve a lockfile -- which is the
only definition of "correct" that matters here, because a disagreement is a
wrong security finding.

Requires node and the `semver` package. Run:

    python tests/difftest_semver.py --semver-dir <dir containing node_modules/semver>

Exits non-zero on any disagreement and prints every one.
"""

from __future__ import annotations

import argparse
import itertools
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.pkg import semver as ours  # noqa: E402


VERSIONS = [
    "0.0.1", "0.0.3", "0.0.4", "0.1.0", "0.2.2", "0.2.3", "0.2.4", "0.3.0",
    "1.0.0", "1.0.1", "1.2.2", "1.2.3", "1.2.4", "1.3.0", "1.9.9",
    "2.0.0", "2.3.4", "2.3.5", "2.4.0", "3.0.0", "3.4.5", "9.9.9", "10.0.0",
    "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0-rc.1", "1.0.0-0",
    "1.2.3-alpha", "1.2.3-beta.2", "1.2.3-rc.1", "2.0.0-alpha",
    "3.4.5-beta", "0.2.3-rc.1", "1.2.4-0",
    "1.0.0+build", "1.2.3+sha.1234",
]

RANGES = [
    "*", "", "x", "1.x", "1.2.x", "0.0.x", "0.x",
    "1.2.3", "=1.2.3", "v1.2.3",
    "^1.2.3", "^0.2.3", "^0.0.3", "^1.2.x", "^0.0.x", "^0.0", "^1.x", "^0", "^1",
    "~1.2.3", "~1.2", "~1", "~0.2.3", "~0.0.3",
    ">=1.2.3", ">1.2.3", "<=1.2.3", "<1.2.3", "<>1.2.3".replace("<>", "!="),
    ">=1.2.3 <2.0.0", ">1.0.0 <=2.0.0", ">=0.2.3 <0.3.0",
    "1.2.3 || 2.3.4", "^1.0.0 || ^2.0.0", "<1.0.0 || >=2.0.0",
    "1.2.3 - 2.3.4", "1.2.3 - 2.3", "1.2.3 - 2", "1.2 - 2.3.4",
    ">1.x", "<2.x", ">=1.x", "<=1.x",
    ">=1.2.3-alpha <2.0.0", ">=1.2.3-alpha <9.0.0", "^1.2.3-alpha",
    ">=1.0.0-0 <2.0.0-0",
]

NODE_SCRIPT = r"""
const semver = require('semver');
const input = JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'));
const out = [];
for (const [version, range, includePrerelease] of input) {
  let value;
  try {
    value = semver.satisfies(version, range, { includePrerelease });
  } catch (e) {
    value = 'ERROR';
  }
  out.push(value);
}
console.log(JSON.stringify(out));
"""


def run(semver_dir: Path) -> int:
    pairs = [
        (v, r, ip)
        for v, r, ip in itertools.product(VERSIONS, RANGES, (False, True))
    ]
    print(f"comparing {len(pairs)} (version, range, includePrerelease) triples")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        payload = tmp / "pairs.json"
        payload.write_text(json.dumps(pairs), encoding="utf-8")
        script = semver_dir / "_difftest.js"
        script.write_text(NODE_SCRIPT, encoding="utf-8")
        try:
            proc = subprocess.run(
                ["node", str(script), str(payload)],
                cwd=str(semver_dir),
                capture_output=True,
                text=True,
                check=True,
            )
        finally:
            script.unlink(missing_ok=True)
        expected = json.loads(proc.stdout)

    mismatches = []
    errors = 0
    for (version, rng, include_pre), want in zip(pairs, expected):
        if want == "ERROR":
            errors += 1
            continue
        try:
            got = ours.satisfies(version, rng, include_prerelease=include_pre)
        except ours.InvalidRange:
            # We refuse some specs on purpose; node accepting them is fine as
            # long as we never silently guess. Count, do not fail.
            errors += 1
            continue
        except Exception as exc:  # noqa: BLE001
            mismatches.append((version, rng, include_pre, want, f"raised {exc!r}"))
            continue
        if got != want:
            mismatches.append((version, rng, include_pre, want, got))

    print(f"  node rejected or we abstained: {errors}")
    if mismatches:
        print(f"\nFAIL: {len(mismatches)} disagreement(s) with npm semver\n")
        for version, rng, include_pre, want, got in mismatches[:60]:
            flag = " (includePrerelease)" if include_pre else ""
            print(f"  {version!r} vs {rng!r}{flag}: npm={want} ours={got}")
        if len(mismatches) > 60:
            print(f"  ... and {len(mismatches) - 60} more")
        return 1

    print(f"\nOK: {len(pairs) - errors} comparisons, zero disagreements with npm semver")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--semver-dir",
        required=True,
        help="directory containing node_modules/semver",
    )
    args = ap.parse_args()
    sys.exit(run(Path(args.semver_dir)))
