"""Writer tests: statement shape and idempotence, without a live node.

HydraDB rejects a malformed write at parse time with a clear message, but only
once it is running. These tests assert the shapes the server is known to
require, so a mistake surfaces here rather than halfway through an ingest.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pytest

from blastradius import schema
from blastradius.ids import IdAllocator
from blastradius.pkg.writer import NODE_PROPS, PackageGraphWriter


class RecordingClient:
    """Stands in for HydraClient, capturing statements and rows."""

    def __init__(self):
        self.calls: list[tuple[str, list[dict]]] = []

    def batch(self, statement, rows, param="rows", size=500, progress=False, label=""):
        rows = list(rows)
        self.calls.append((statement, rows))
        return len(rows)

    def query(self, statement, parameters=None, **kw):  # pragma: no cover
        self.calls.append((statement, [parameters or {}]))
        return None

    def statements(self) -> list[str]:
        return [s for s, _ in self.calls]


@pytest.fixture
def writer():
    tmp = Path(tempfile.mkdtemp()) / "ids.sqlite"
    return PackageGraphWriter(
        RecordingClient(), IdAllocator(tmp), source="test",
        verbose=False, parallelism=1,
    )


def _build(writer):
    pkg = writer.node(schema.PACKAGE, "pkg:npm/lodash", name="lodash")
    v1 = writer.node(
        schema.PACKAGE_VERSION, "pkg:npm/lodash@4.17.21",
        name="lodash", version="4.17.21",
    )
    writer.edge(schema.HAS_VERSION, pkg, v1)
    return pkg, v1


# -- statement shape -------------------------------------------------------


def test_node_write_is_merge_by_id_then_set(writer):
    _build(writer)
    writer.flush()
    node_stmts = [s for s in writer.client.statements() if "MERGE (n {id: row.id})" in s]
    assert node_stmts
    for statement in node_stmts:
        # Folding properties into the MERGE pattern is rejected by the server:
        # the pattern is the identity being matched on.
        assert re.search(r"MERGE \(n \{id: row\.id\}\) SET", statement)
        assert "MERGE (n {id: row.id, " not in statement


def test_edge_endpoints_carry_exactly_one_label(writer):
    _build(writer)
    writer.flush()
    edge_stmts = [s for s in writer.client.statements() if "MATCH (s:" in s]
    assert edge_stmts
    for statement in edge_stmts:
        match = re.search(
            r"MATCH \(s:(\w+) \{id: row\.src\}\), \(d:(\w+) \{id: row\.dst\}\)",
            statement,
        )
        assert match, statement


def test_relationship_carries_an_explicit_id(writer):
    _build(writer)
    writer.flush()
    edge_stmts = [s for s in writer.client.statements() if "MERGE (s)-[r:" in s]
    assert edge_stmts
    for statement in edge_stmts:
        assert re.search(r"MERGE \(s\)-\[r:\w+ \{id: row\.rel\}\]->\(d\)", statement)


def test_every_write_is_an_unwind_over_a_parameter(writer):
    _build(writer)
    writer.flush()
    for statement in writer.client.statements():
        assert statement.startswith("UNWIND $rows AS row"), statement


def test_no_unsupported_clauses_are_emitted(writer):
    _build(writer)
    writer.flush()
    banned = (" IN ", " CONTAINS ", " ENDS WITH ", "IS NULL", "RETURN *", "CREATE UNIQUE",
              "ON CREATE", "ON MATCH")
    for statement in writer.client.statements():
        for clause in banned:
            assert clause not in statement, f"{clause} in {statement}"


def test_relationship_patterns_are_directed_and_single_type(writer):
    _build(writer)
    writer.flush()
    for statement in writer.client.statements():
        assert "--" not in statement, "undirected patterns are rejected"
        assert not re.search(r"\[r:\w+\|", statement), "one type per pattern"


# -- completeness ----------------------------------------------------------


def test_every_property_of_a_label_is_always_written(writer):
    # `WHERE` has no IS NULL, so an omitted property is unqueryable, not null.
    writer.node(schema.PACKAGE, "pkg:npm/lodash", name="lodash")  # most props absent
    writer.flush()
    statement, rows = writer.client.calls[0]
    for prop in NODE_PROPS[schema.PACKAGE]:
        assert f"n.{prop} = row.{prop}" in statement
        assert prop in rows[0], f"{prop} missing from row"


def test_unknowns_become_sentinels_not_none(writer):
    writer.node(schema.PACKAGE_VERSION, "pkg:npm/x@1.0.0", name="x", version="1.0.0")
    writer.flush()
    _, rows = writer.client.calls[0]
    assert None not in rows[0].values()
    assert rows[0]["published_at"] == schema.UNKNOWN_TS
    assert rows[0]["withdrawn_at"] == schema.STILL_LIVE


def test_booleans_are_written_as_integers(writer):
    writer.node(
        schema.PACKAGE_VERSION, "pkg:npm/x@1.0.0",
        name="x", version="1.0.0", deprecated=True, has_install_script=False,
    )
    writer.flush()
    _, rows = writer.client.calls[0]
    assert rows[0]["deprecated"] == 1
    assert rows[0]["has_install_script"] == 0


def test_list_values_are_joined_not_left_as_lists(writer):
    writer.node(
        schema.ADVISORY, "CVE-1", advisory_id="CVE-1",
        aliases=["GHSA-b", "PYSEC-a"],
    )
    writer.flush()
    _, rows = writer.client.calls[0]
    assert rows[0]["aliases"] == "GHSA-b|PYSEC-a"


# -- inverse edges ---------------------------------------------------------


def test_each_edge_is_written_in_both_directions(writer):
    _build(writer)
    writer.flush()
    types = {
        re.search(r"MERGE \(s\)-\[r:(\w+)", s).group(1)
        for s in writer.client.statements()
        if "MERGE (s)-[r:" in s
    }
    assert schema.HAS_VERSION in types
    assert schema.VERSION_OF in types, "inverse is required, not optional"


def test_inverse_carries_the_same_properties(writer):
    pkg = writer.node(schema.PACKAGE, "pkg:npm/lodash", name="lodash")
    ver = writer.node(schema.PACKAGE_VERSION, "pkg:npm/a@1.0.0", name="a", version="1.0.0")
    writer.edge(schema.REQUIRES, ver, pkg, range="^4.17.0", dep_type="prod")
    writer.flush()
    forward = next(r for s, r in writer.client.calls if f"r:{schema.REQUIRES} " in s)
    inverse = next(r for s, r in writer.client.calls if f"r:{schema.REQUIRED_BY} " in s)
    assert forward[0]["range"] == inverse[0]["range"] == "^4.17.0"


def test_edge_before_node_fails_loudly(writer):
    with pytest.raises(KeyError, match="never staged"):
        writer.edge(schema.HAS_VERSION, 1, 2)


# -- idempotence -----------------------------------------------------------


def test_restaging_the_same_key_reuses_the_id(writer):
    a = writer.node(schema.PACKAGE, "pkg:npm/lodash", name="lodash")
    b = writer.node(schema.PACKAGE, "pkg:npm/lodash", name="lodash")
    assert a == b
    writer.flush()
    _, rows = writer.client.calls[0]
    assert len(rows) == 1, "one node, not two"


def test_enrichment_fills_sentinels_without_clobbering(writer):
    writer.node(schema.PACKAGE, "pkg:npm/lodash", name="lodash")
    writer.node(schema.PACKAGE, "pkg:npm/lodash", name="lodash", downloads=50_000_000)
    writer.flush()
    _, rows = writer.client.calls[0]
    assert rows[0]["downloads"] == 50_000_000
    assert rows[0]["name"] == "lodash"


def test_ids_stable_across_writer_instances():
    tmp = Path(tempfile.mkdtemp()) / "ids.sqlite"
    w1 = PackageGraphWriter(RecordingClient(), IdAllocator(tmp), verbose=False)
    first = w1.node(schema.PACKAGE_VERSION, "pkg:npm/lodash@4.17.21")
    w1.flush()

    w2 = PackageGraphWriter(RecordingClient(), IdAllocator(tmp), verbose=False)
    second = w2.node(schema.PACKAGE_VERSION, "pkg:npm/lodash@4.17.21")
    assert first == second, "re-ingest must MERGE, not duplicate"


def test_edges_bucketed_by_label_pair(writer):
    """RESOLVED_IN spans more than one label pair, and a write UNWIND takes
    exactly one label per endpoint, so the buckets must be separate."""
    svc = writer.node(schema.SERVICE, "svc:a", name="a")
    v1 = writer.node(schema.PACKAGE_VERSION, "pkg:npm/a@1.0.0", name="a", version="1.0.0")
    pkg = writer.node(schema.PACKAGE, "pkg:npm/a", name="a")
    writer.edge(schema.RESOLVED_IN, v1, svc, depth=1)
    writer.edge(schema.HAS_VERSION, pkg, v1)
    writer.flush()
    resolved = [s for s in writer.client.statements() if f"r:{schema.RESOLVED_IN} " in s]
    assert len(resolved) == 1
    assert f"(s:{schema.PACKAGE_VERSION} " in resolved[0]
    assert f"(d:{schema.SERVICE} " in resolved[0]
