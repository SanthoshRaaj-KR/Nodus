"""One vulnerability model, shared by the package view and the code view.

Both views ask the same question in different vocabularies -- "how close is
this thing to a known vulnerability?" -- so both get their answer from here.
Computing it twice would let the two views disagree about the same package,
which is precisely the failure this module exists to prevent.

The shape of the answer is a *heat*: a float in ``[0, 1]`` where 1.0 is a
critical advisory naming this exact node, and 0 is far enough away to be worth
drawing but not worth worrying about. A node with no vulnerability anywhere in
its radius has no heat at all (``None``), which is what the UI draws green.

    heat = severity_base - hops * DECAY

Two inputs, deliberately. Distance alone says a low-severity advisory on a
direct dependency is as alarming as a critical one; severity alone says a
critical advisory five hops down a dev-only chain deserves the same red as one
in a route handler. Neither is true, and grading on both means a critical two
hops out still outranks a low-severity hit at the source -- which is the
judgement an incident responder actually makes.

Traversal happens in Python, not in Cypher. The whole graph is a few thousand
edges, HydraDB needs a pinned source for a variable-length walk (so a reverse
walk would be one query per node), and one sweep per edge type is a handful of
round trips against hundreds. The graph is fetched once and walked in memory.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ..hydra_client import HydraClient

#: Where a severity word starts on the ramp. Keep in step with
#: ``pkg/osv.py::SEVERITY_RANK`` -- same vocabulary, different scale.
SEVERITY_BASE = {
    "critical": 1.00,
    "high": 0.85,
    "moderate": 0.65,
    "medium": 0.65,
    "low": 0.45,
}

#: An advisory the feed never rated. Placed between low and moderate: it is a
#: real published finding, so it must outrank "clean", but inventing a high
#: severity for it would be a number nobody computed.
UNRATED_BASE = 0.55

#: Cost of one hop. 0.14 puts a critical advisory into orange at three hops and
#: a low one into yellow at one, which is what the ramp is tuned for. Raising
#: it makes the radius tighter, not shorter.
DECAY = 0.14

#: Below this a node is drawn as unaffected. Without a floor the radius is the
#: whole graph, which says nothing.
FLOOR = 0.05


def severity_base(label) -> float:
    """Ramp start for a severity word. Unknown words are unrated, not clean."""
    if not isinstance(label, str):
        # HydraDB returns a missing property as {"type": "null"}, not None.
        return UNRATED_BASE
    return SEVERITY_BASE.get(label.strip().lower(), UNRATED_BASE)


def severity_word(label) -> str:
    return label.strip().lower() if isinstance(label, str) and label.strip() else "unknown"


@dataclass
class Heat:
    """How hot one node is, and the evidence for it."""

    heat: float
    hops: int
    severity: str
    #: Human-readable origin, e.g. ``vite@6.3.6``.
    source: str
    #: The advisory id that produced the highest heat on this node.
    advisory: str = ""

    def as_dict(self) -> dict:
        return {
            "heat": round(self.heat, 4),
            "hops": self.hops,
            "severity": self.severity,
            "source": self.source,
            "advisory": self.advisory,
        }


@dataclass
class Seed:
    """A node an advisory names directly."""

    node_id: int
    label: str
    severity: str
    advisory: str
    base: float


@dataclass
class ExposureModel:
    """Heat per node id, plus the seeds that produced it."""

    heat: dict = field(default_factory=dict)
    seeds: dict = field(default_factory=dict)

    def payload(self) -> dict:
        """Keyed by *string* id, ready for JSON."""
        return {str(k): v.as_dict() for k, v in self.heat.items()}

    def worst(self):
        return max(self.heat.values(), key=lambda h: h.heat, default=None)

    def offer(self, node_id: int, candidate: Heat) -> bool:
        """Keep the hottest claim on a node. True if it changed."""
        current = self.heat.get(node_id)
        if current is not None and current.heat >= candidate.heat:
            return False
        self.heat[node_id] = candidate
        return True


# --------------------------------------------------------------------------
# Reading the graph
# --------------------------------------------------------------------------


def advisory_seeds(client: HydraClient) -> list:
    """Every PackageVersion an advisory names, with its worst severity.

    One advisory can name a version several times through aliases, and one
    version can carry several advisories; the worst wins, because a package is
    as dangerous as the worst thing known about it.
    """
    rows = client.query(
        "MATCH (a:Advisory)-[:AFFECTS]->(v:PackageVersion) "
        "RETURN v.id AS id, v.name AS name, v.version AS version, "
        "a.advisory_id AS advisory_id, a.severity AS severity"
    ).rows

    best: dict = {}
    for row in rows:
        node_id = row.get("id")
        if node_id is None:
            continue
        base = severity_base(row.get("severity"))
        existing = best.get(node_id)
        if existing is None or base > existing.base:
            best[node_id] = Seed(
                node_id=node_id,
                label="{}@{}".format(row.get("name"), row.get("version")),
                severity=severity_word(row.get("severity")),
                advisory=row.get("advisory_id") or "",
                base=base,
            )
    return list(best.values())


def _edge_pairs(client: HydraClient, statement: str) -> list:
    rows = client.query(statement).rows
    return [
        (row["src"], row["dst"])
        for row in rows
        if row.get("src") is not None and row.get("dst") is not None
    ]


def package_edges(client: HydraClient) -> list:
    """``parent -> child`` over the resolved dependency tree, plus the root."""
    edges = _edge_pairs(
        client,
        "MATCH (a:PackageVersion)-[:DEPENDS_ON]->(b:PackageVersion) "
        "RETURN a.id AS src, b.id AS dst",
    )
    edges += _edge_pairs(
        client,
        "MATCH (s:Service)-[:DEPENDS_ON]->(v:PackageVersion) "
        "RETURN s.id AS src, v.id AS dst",
    )
    return edges


def bridge_edges(client: HydraClient) -> list:
    """``ExternalImport -> PackageVersion``: the one join between the tiers.

    This single edge type is what lets a CVE on a package become a fact about
    a source file. It is also what was silently empty while the two ingest
    tiers keyed ``PackageVersion`` differently.
    """
    return _edge_pairs(
        client,
        "MATCH (e:ExternalImport)-[:RESOLVES_TO]->(v:PackageVersion) "
        "RETURN e.id AS src, v.id AS dst",
    )


def code_edges(client: HydraClient) -> list:
    """Every edge inside the code graph, in caller->callee form.

    Direction matters and is easy to get backwards. These are written the way
    control flows -- a file reaches the functions it defines, a route reaches
    its handler, a function reaches what it calls, a function reaches the
    package it imports -- and :func:`propagate` inverts them, because exposure
    travels the opposite way to control.
    """
    edges = _edge_pairs(
        client,
        "MATCH (f:Function)-[:CALLS_EXTERNAL]->(e:ExternalImport) "
        "RETURN f.id AS src, e.id AS dst",
    )
    edges += _edge_pairs(
        client,
        "MATCH (a:Function)-[:CALLS]->(b:Function) RETURN a.id AS src, b.id AS dst",
    )
    edges += _edge_pairs(
        client,
        "MATCH (r:Route)-[:HANDLED_BY]->(f:Function) RETURN r.id AS src, f.id AS dst",
    )
    edges += _edge_pairs(
        client,
        "MATCH (fl:File)-[:CONTAINS]->(f:Function) RETURN fl.id AS src, f.id AS dst",
    )
    return edges


# --------------------------------------------------------------------------
# The walk
# --------------------------------------------------------------------------


def propagate(seeds: list, edges: list) -> ExposureModel:
    """Breadth-first outward from each seed, against the edge direction.

    Edges point the way control or dependency flows (``importer -> imported``,
    ``caller -> callee``); exposure flows the other way, so the walk is over
    the reversed adjacency. That inversion is the whole idea: a vulnerable
    package is a fact about the package, but the blast radius is everything
    that reaches it.

    "Hottest claim wins" rather than plain first-visit, because two seeds of
    different severity can reach the same node and the node must show the worse
    of them, not whichever the queue happened to pop first. Re-queueing on
    improvement is what makes that correct; the floor is what makes it
    terminate.
    """
    incoming: dict = {}
    for src, dst in edges:
        incoming.setdefault(dst, []).append(src)

    model = ExposureModel(seeds={s.node_id: s for s in seeds})

    for seed in seeds:
        start = Heat(
            heat=seed.base,
            hops=0,
            severity=seed.severity,
            source=seed.label,
            advisory=seed.advisory,
        )
        model.offer(seed.node_id, start)
        queue = deque([(seed.node_id, 0)])
        while queue:
            node_id, hops = queue.popleft()
            nxt = hops + 1
            heat = seed.base - nxt * DECAY
            if heat < FLOOR:
                continue
            for parent in incoming.get(node_id, ()):
                claim = Heat(
                    heat=heat,
                    hops=nxt,
                    severity=seed.severity,
                    source=seed.label,
                    advisory=seed.advisory,
                )
                if model.offer(parent, claim):
                    queue.append((parent, nxt))

    return model


#: (read_epoch, model). The model is a pure function of the graph, and both
#: views want the same one on the same request cycle -- the code view and the
#: package view each used to rebuild it from scratch, paying ~3s of unpinned
#: sweeps twice for an identical answer. Keyed on the node's own read epoch, so
#: it expires exactly when the data changes and never one request later.
_cache: tuple = (None, None)


def _read_epoch(client: HydraClient):
    """The node's current read snapshot, or None if it did not report one.

    None disables caching rather than risking a stale answer: for a tool that
    reports exposure, serving yesterday's model is worse than being slow.
    """
    try:
        return client.query("MATCH (n {id: 0}) RETURN n.id AS id").read_epoch
    except Exception:
        return None


def full_exposure(client: HydraClient, use_cache: bool = True) -> ExposureModel:
    """One heat model over both tiers at once. This is the only entry point.

    Package tree, bridge and code graph are walked as a *single* edge set
    rather than two models, for two reasons.

    Correctness: a module rarely imports the vulnerable package itself. The
    project here imports ``react-router-dom``, which is clean; the thirteen
    advisories are on ``react-router``, one hop below it in the tree. Walking
    the code graph alone stops at the bridge and reports that module safe.
    Walking one joined set lets the heat climb the dependency tree, cross the
    bridge, and land on the file that will actually ship the vulnerable code.

    Agreement: with two models the same package could be hot in one view and
    cool in the other, and a user flipping tabs would be shown two answers to
    one question. There is one number, and both views read it.
    """
    global _cache

    epoch = _read_epoch(client) if use_cache else None
    if epoch is not None and _cache[0] == epoch and _cache[1] is not None:
        return _cache[1]

    seeds = advisory_seeds(client)
    if not seeds:
        model = ExposureModel()
    else:
        edges = package_edges(client) + bridge_edges(client) + code_edges(client)
        model = propagate(seeds, edges)

    if epoch is not None:
        _cache = (epoch, model)
    return model


#: Older name kept because both views want the same model. Neither is a
#: separate computation any more; see :func:`full_exposure`.
package_exposure = full_exposure
code_exposure = full_exposure
