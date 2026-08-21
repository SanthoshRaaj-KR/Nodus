"""The whole-graph payload: what it draws, and what it admits it left out.

This view has no query to be wrong about, so the failure mode is different
from the rest of the project: it is not "reports the wrong answer", it is
"quietly shows you three quarters of the graph". Every bound here therefore
has to be *stated in the payload*, and that is most of what is tested below.

The other property worth holding is that an edge never survives its endpoints.
The browser looks its endpoints up in a map built from `nodes`; an edge naming
a node that was not sent draws a line to the origin, which reads as a real
relationship pointing at nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius import schema  # noqa: E402
from blastradius.pkg.fullgraph import (  # noqa: E402
    DEFAULT_LABELS,
    EDGE_SWEEPS,
    NODE_FIELDS,
    GraphSpec,
    build_full_graph,
)


def _live_client():
    from blastradius.hydra_client import HydraClient, HydraError

    client = HydraClient()
    try:
        return client if client.ready() else None
    except HydraError:
        return None


live = pytest.mark.skipif(_live_client() is None, reason="HydraDB is not reachable")


class FakeRows(list):
    @property
    def rows(self):
        return self


class FakeClient:
    """Answers node scans and edge sweeps from a fixture."""

    def __init__(self, nodes: dict, edges: dict):
        self.nodes = nodes          # label -> [dict]
        self.edges = edges          # etype -> [(src, dst)]
        self.statements: list[str] = []

    def query(self, statement, parameters=None):
        self.statements.append(statement)
        for label, rows in self.nodes.items():
            if f"(n:{label})" in statement:
                return FakeRows(rows)
        for etype, pairs in self.edges.items():
            if f"[e:{etype}]" in statement:
                return FakeRows(
                    [{"source": a, "target": b} for a, b in pairs]
                )
        return FakeRows([])


# -- the schema itself ------------------------------------------------------


def test_every_default_label_has_fields():
    """A label with no projection would ship ids and nothing to show on hover."""
    for label in DEFAULT_LABELS:
        assert label in NODE_FIELDS, f"{label} has no NODE_FIELDS entry"
        assert NODE_FIELDS[label], f"{label} projects no properties"


def test_edge_sweeps_only_reference_known_labels():
    """A sweep naming a label we never draw yields edges to nowhere."""
    drawable = set(DEFAULT_LABELS) | {schema.LOCKFILE_ENTRY}
    for etype, src, dst in EDGE_SWEEPS:
        assert src in drawable, f"{etype} sources from undrawn {src}"
        assert dst in drawable, f"{etype} targets undrawn {dst}"


# -- the payload contract ---------------------------------------------------


def test_edges_never_outlive_their_endpoints():
    """An edge to a node that was not sent draws a line to the origin.

    That renders as a real relationship pointing at nothing, which is worse
    than the edge being absent.
    """
    client = FakeClient(
        nodes={
            schema.SERVICE: [{"id": 1, "name": "svc"}],
            schema.PACKAGE: [{"id": 2, "name": "pkg"}],
        },
        edges={
            schema.RESOLVED_IN: [(2, 1), (2, 999), (777, 1)],
        },
    )
    g = build_full_graph(client, GraphSpec(labels=(schema.SERVICE, schema.PACKAGE)))
    assert len(g["edges"]) == 1
    assert g["edges"][0]["source"] == 2 and g["edges"][0]["target"] == 1


def test_omissions_are_declared_by_default():
    """The two held-back sweeps must always announce themselves."""
    client = FakeClient(nodes={schema.SERVICE: [{"id": 1, "name": "a"}]}, edges={})
    g = build_full_graph(client, GraphSpec(labels=(schema.SERVICE,)))
    what = {o["what"] for o in g["omitted"]}
    assert schema.SATISFIED_BY in what
    assert schema.LOCKFILE_ENTRY in what
    for entry in g["omitted"]:
        assert entry["why"], "an omission without a reason is just a gap"


def test_asking_for_the_optional_sweeps_removes_their_caveats():
    client = FakeClient(nodes={schema.SERVICE: [{"id": 1, "name": "a"}]}, edges={})
    g = build_full_graph(
        client,
        GraphSpec(
            labels=(schema.SERVICE,),
            include_satisfied_by=True,
            include_lockfile_entries=True,
        ),
    )
    what = {o["what"] for o in g["omitted"]}
    assert schema.SATISFIED_BY not in what
    assert schema.LOCKFILE_ENTRY not in what


def test_the_node_ceiling_is_reported_not_silent():
    """A map missing a third of itself with no warning is worse than no map."""
    client = FakeClient(
        nodes={schema.PACKAGE: [{"id": i, "name": f"p{i}"} for i in range(50)]},
        edges={},
    )
    g = build_full_graph(
        client, GraphSpec(labels=(schema.PACKAGE,), max_nodes=10)
    )
    assert g["stats"]["nodes"] == 10
    dropped = [o for o in g["omitted"] if "max_nodes" in o["what"]]
    assert dropped, "truncation must be declared"
    assert "40" in dropped[0]["why"]


def test_an_absent_label_is_zero_rows_not_an_error():
    """The case the old swallow was written for does not raise in the first place.

    A scan of a label the graph has never held comes back empty, so nothing has
    to be caught for it -- which is why the catch is gone.
    """
    client = FakeClient(
        nodes={schema.SERVICE: [{"id": 1, "name": "svc"}]}, edges={}
    )
    g = build_full_graph(
        client, GraphSpec(labels=(schema.SERVICE, schema.ADVISORY))
    )
    assert g["stats"]["nodes"] == 1
    assert g["stats"]["by_label"][schema.ADVISORY] == 0


def test_a_failed_sweep_raises_rather_than_drawing_an_empty_graph():
    """A silent empty map reads as "you are not exposed", which is the worst lie.

    Every sweep used to be wrapped in a bare `except`, so one stale token turned
    twelve 401s into `{"nodes": [], "edges": []}` with a 200 on it. The failure
    has to reach the caller, which turns it into a 503 that names the cause.
    """

    class Flaky(FakeClient):
        def query(self, statement, parameters=None):
            if f"(n:{schema.ADVISORY})" in statement:
                raise RuntimeError("HTTP 401 from HydraDB")
            return super().query(statement, parameters)

    client = Flaky(
        nodes={schema.SERVICE: [{"id": 1, "name": "svc"}]}, edges={}
    )
    with pytest.raises(RuntimeError, match="401"):
        build_full_graph(client, GraphSpec(labels=(schema.SERVICE, schema.ADVISORY)))


def test_a_failed_edge_sweep_raises_too():
    """Nodes without their edges is a map of unconnected dots, not a smaller map."""

    class Flaky(FakeClient):
        def query(self, statement, parameters=None):
            if f"[e:{schema.HAS_VERSION}]" in statement:
                raise RuntimeError("HTTP 401 from HydraDB")
            return super().query(statement, parameters)

    client = Flaky(
        nodes={schema.PACKAGE: [{"id": 1, "name": "p"}]}, edges={}
    )
    with pytest.raises(RuntimeError, match="401"):
        build_full_graph(client, GraphSpec(labels=(schema.PACKAGE,)))


def test_display_name_falls_back_rather_than_showing_an_id():
    client = FakeClient(
        nodes={schema.REPOSITORY: [{"id": 5, "url": "https://github.com/a/b"}]},
        edges={},
    )
    g = build_full_graph(client, GraphSpec(labels=(schema.REPOSITORY,)))
    assert g["nodes"][0]["name"] == "https://github.com/a/b"


def test_empty_properties_are_stripped_from_meta():
    """Sentinels are how absence is stored; they are not worth sending."""
    client = FakeClient(
        nodes={schema.SERVICE: [{"id": 1, "name": "svc", "repo": "", "path": None}]},
        edges={},
    )
    g = build_full_graph(client, GraphSpec(labels=(schema.SERVICE,)))
    meta = g["nodes"][0]["meta"]
    assert meta["name"] == "svc"
    assert "repo" not in meta and "path" not in meta


# -- against the real graph -------------------------------------------------


@live
def test_full_graph_against_the_ingested_corpus():
    from blastradius.hydra_client import HydraClient

    g = build_full_graph(HydraClient())
    if not g["stats"]["nodes"]:
        pytest.skip("nothing ingested")

    ids = {n["id"] for n in g["nodes"]}
    assert len(ids) == len(g["nodes"]), "node ids must be unique"
    for e in g["edges"]:
        assert e["source"] in ids and e["target"] in ids

    # Every drawn node carries the two fields the browser renders with.
    for n in g["nodes"]:
        assert n["label"] and n["name"]
