"""Verify HydraDB's actual behaviour against what the design assumes.

Every constraint below was either read out of the upstream repo or inherited
from the sample's README. Both are secondhand. This script asks the running
node directly, so an assumption that has drifted shows up here rather than
halfway through an ingest.

The one that matters most is EXPERIMENT A: `algo.SSpaths` documents
`relDirection: 'incoming'`, which would make the materialised inverse edges
redundant and halve the edge count. The sample states a backward walk is "not
expressible at all". Both cannot be right, and the answer changes the schema.

    python tests/verify_constraints.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.hydra_client import HydraClient, HydraError  # noqa: E402

PASS, FAIL, INFO = "PASS", "FAIL", "INFO"
results: list[tuple[str, str, str]] = []


def check(name: str, expectation: str, fn) -> None:
    try:
        outcome = fn()
    except HydraError as exc:
        outcome = f"rejected: {str(exc).splitlines()[-1][:120]}"
        status = PASS if expectation == "reject" else FAIL
    except Exception as exc:  # noqa: BLE001
        outcome, status = f"error: {exc}", FAIL
    else:
        status = PASS if expectation != "reject" else FAIL
        outcome = str(outcome)
    results.append((name, status, outcome))
    print(f"  [{status}] {name}\n         {outcome[:150]}")


def main() -> int:
    client = HydraClient()
    if not client.ready():
        print("HydraDB is not reachable at http://127.0.0.1:8443")
        return 2

    print("\n=== seeding a tiny fixture graph ===")
    # A -> B -> C over CHAIN, so directionality is unambiguous.
    client.query(
        "UNWIND $rows AS row MERGE (n {id: row.id}) SET n:Probe, n.name = row.name",
        {"rows": [
            {"id": 900001, "name": "A"},
            {"id": 900002, "name": "B"},
            {"id": 900003, "name": "C"},
        ]},
    )
    client.query(
        "UNWIND $rows AS row "
        "MATCH (s:Probe {id: row.src}), (d:Probe {id: row.dst}) "
        "MERGE (s)-[r:CHAIN {id: row.rel}]->(d) SET r.weight = row.weight",
        {"rows": [
            {"src": 900001, "dst": 900002, "rel": 950001, "weight": 1},
            {"src": 900002, "dst": 900003, "rel": 950002, "weight": 1},
        ]},
    )
    print("  seeded Probe A->B->C")

    print("\n=== write-path constraints ===")

    check(
        "MERGE by id then SET (the documented node upsert)",
        "accept",
        lambda: client.query(
            "UNWIND $rows AS row MERGE (n {id: row.id}) SET n:Probe, n.name = row.name",
            {"rows": [{"id": 900004, "name": "D"}]},
        ) and "accepted",
    )
    check(
        "properties folded into the MERGE pattern",
        "reject",
        lambda: client.query(
            "UNWIND $rows AS row MERGE (n:Probe {id: row.id, name: row.name})",
            {"rows": [{"id": 900005, "name": "E"}]},
        ),
    )
    check(
        "UNWIND MATCH MERGE edge with one label per endpoint",
        "accept",
        lambda: client.query(
            "UNWIND $rows AS row "
            "MATCH (s:Probe {id: row.src}), (d:Probe {id: row.dst}) "
            "MERGE (s)-[r:CHAIN {id: row.rel}]->(d)",
            {"rows": [{"src": 900001, "dst": 900004, "rel": 950003}]},
        ) and "accepted",
    )
    check(
        "inline list parameter (not via UNWIND)",
        "reject",
        lambda: client.query(
            "MATCH (n:Probe) WHERE n.id = $ids RETURN n.id AS id",
            {"ids": [900001, 900002]},
        ),
    )

    print("\n=== read-path constraints ===")

    check(
        "plain MATCH with a scalar $id and a label",
        "accept",
        lambda: client.query(
            "MATCH (n:Probe {id: $id}) RETURN n.name AS name", {"id": 900001}
        ).scalar("name"),
    )
    check(
        "IN operator in WHERE",
        "reject",
        lambda: client.query("MATCH (n:Probe) WHERE n.id IN [1,2] RETURN n.id AS id"),
    )
    check(
        "CONTAINS in WHERE",
        "reject",
        lambda: client.query(
            "MATCH (n:Probe) WHERE n.name CONTAINS 'A' RETURN n.id AS id"
        ),
    )
    check(
        "IS NULL in WHERE",
        "reject",
        lambda: client.query(
            "MATCH (n:Probe) WHERE n.name IS NULL RETURN n.id AS id"
        ),
    )
    check(
        "STARTS WITH in WHERE",
        "accept",
        lambda: f"{len(client.query('MATCH (n:Probe) WHERE n.name STARTS WITH \'A\' RETURN n.id AS id'))} row(s)",
    )
    check(
        "integer comparison in WHERE (the live-window predicate)",
        "accept",
        lambda: f"{len(client.query('MATCH (n:Probe) WHERE n.id >= 900001 AND n.id <= 900002 RETURN n.id AS id'))} row(s)",
    )
    check(
        "unbounded variable-length *",
        "reject",
        lambda: client.query(
            "MATCH (a:Probe {id: $id})-[:CHAIN*]->(b) RETURN b.id AS id", {"id": 900001}
        ),
    )
    check(
        "bounded variable-length *1..3",
        "accept",
        lambda: f"{len(client.query('MATCH (a:Probe {id: $id})-[:CHAIN*1..3]->(b) RETURN b.id AS id', {'id': 900001}))} reachable",
    )
    check(
        "RETURN *",
        "reject",
        lambda: client.query("MATCH (n:Probe {id: $id}) RETURN *", {"id": 900001}),
    )
    check(
        "min() aggregate",
        "reject",
        lambda: client.query("MATCH (n:Probe) RETURN min(n.id) AS m"),
    )

    print("\n=== EXPERIMENT A: is reverse traversal expressible? ===")

    check(
        "plain MATCH backwards without an inverse edge",
        "accept",
        lambda: f"{len(client.query('MATCH (c:Probe {id: $id})<-[:CHAIN*1..3]-(a) RETURN a.id AS id', {'id': 900003}))} row(s) "
                "(0 rows means a backward pattern parses but finds nothing)",
    )
    sspaths = (
        "CALL algo.SSpaths({{sourceNode: $id, relTypes: [{types}], maxLen: 3, "
        "relDirection: '{direction}'}}) YIELD path RETURN path"
    )

    check(
        "algo.SSpaths relDirection outgoing (A -> ...)",
        "accept",
        lambda: f"{len(client.query(sspaths.format(types=chr(39) + 'CHAIN' + chr(39), direction='outgoing'), {'id': 900001}))} path(s) from A",
    )
    check(
        "algo.SSpaths relDirection INCOMING (C <- ...)",
        "accept",
        lambda: f"{len(client.query(sspaths.format(types=chr(39) + 'CHAIN' + chr(39), direction='incoming'), {'id': 900003}))} path(s) into C -- nonzero means the inverse edges are redundant",
    )
    check(
        "algo.SSpaths with multiple relTypes",
        "accept",
        lambda: f"{len(client.query(sspaths.format(types=chr(39) + 'CHAIN' + chr(39) + ', ' + chr(39) + 'OTHER' + chr(39), direction='outgoing'), {'id': 900001}))} path(s)",
    )

    print("\n=== cleanup ===")
    for node_id in (900001, 900002, 900003, 900004, 900005):
        try:
            client.query("MATCH (n:Probe {id: $id}) DETACH DELETE n", {"id": node_id})
        except HydraError:
            pass
    print("  probe nodes removed")

    print("\n" + "=" * 68)
    failed = [r for r in results if r[1] == FAIL]
    print(f"{len(results) - len(failed)}/{len(results)} constraints behaved as assumed")
    if failed:
        print("\nDIVERGENCES (the design assumes otherwise):")
        for name, _, outcome in failed:
            print(f"  - {name}\n      {outcome[:200]}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
