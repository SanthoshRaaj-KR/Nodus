"""The blast frontier, and the ceiling that keeps it honest.

The frontier is a *prediction*: these are the packages the credentials behind a
compromise could publish to next. Predictions are the easiest place in a
security tool to overclaim, and the damage from overclaiming is specific --
a maintainer who shares an account with a victim is not compromised, and a tool
that says otherwise gets muted.

So the property under test is not really "does it find the right packages". It
is **can any combination of evidence push a frontier row above INVESTIGATE**,
and the answer has to be no. Everything else here supports that.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.pkg.blast import Confidence, Evidence  # noqa: E402
from blastradius.pkg.frontier import (  # noqa: E402
    Frontier,
    FrontierEngine,
    FrontierTarget,
    Route,
)


def _live_client():
    from blastradius.hydra_client import HydraClient, HydraError

    client = HydraClient()
    try:
        return client if client.ready() else None
    except HydraError:
        return None


live = pytest.mark.skipif(_live_client() is None, reason="HydraDB is not reachable")


def target(package="x", routes=None, services=(), measured=True):
    return FrontierTarget(
        package=package,
        package_id=1,
        routes=routes or {},
        exposed_services=set(services),
        impact_measured=measured,
    )


# -- the ceiling ------------------------------------------------------------


@pytest.mark.parametrize("routes", [
    {Route.PUBLISHER: {"a"}},
    {Route.MAINTAINER: {"a"}},
    {Route.REPOSITORY: {"git+https://github.com/o/r"}},
    {Route.PUBLISHER: {"a"}, Route.MAINTAINER: {"b"}},
    {Route.PUBLISHER: {"a"}, Route.MAINTAINER: {"b"},
     Route.REPOSITORY: {"git+https://github.com/o/r"}},
])
def test_no_combination_of_routes_exceeds_investigate(routes):
    """Every route, and every combination of them, stays a lead.

    This is the whole safety argument for the feature. Three independent
    publish paths to the same package is a stronger reason to look and still
    not evidence that anything was published.
    """
    assert target(routes=routes).confidence == Confidence.INVESTIGATE


def test_frontier_atoms_are_all_relational():
    """The ceiling holds because of which atoms these are, not a special case.

    If a future route ever mapped to a non-relational atom, the confidence rule
    would silently start returning something higher. Asserting the membership
    is what makes that a test failure rather than a surprise in production.
    """
    every = {Route.PUBLISHER, Route.MAINTAINER, Route.REPOSITORY}
    atoms = target(routes={r: {"w"} for r in every}).atoms
    assert atoms == {
        Evidence.SHARED_PUBLISHER,
        Evidence.SHARED_MAINTAINER,
        Evidence.SHARED_REPOSITORY,
    }
    assert atoms <= Evidence.RELATIONAL


# -- witnesses --------------------------------------------------------------


def test_identities_collects_every_witness():
    """"Rotate these accounts" is the action, so the names must survive."""
    t = target(routes={
        Route.PUBLISHER: {"alice"},
        Route.MAINTAINER: {"alice", "bob"},
    })
    assert t.identities == {"alice", "bob"}


def test_at_risk_services_unions_rather_than_sums():
    """One service behind six frontier packages is one service at risk.

    Summing would report six and inflate the headline number precisely when
    the frontier is widest, which is when it is most likely to be read.
    """
    f = Frontier(target="x@1", exists=True, targets=[
        target("a", services=["svc-1", "svc-2"]),
        target("b", services=["svc-2", "svc-3"]),
        target("c", services=["svc-1"]),
    ])
    assert f.at_risk_services == {"svc-1", "svc-2", "svc-3"}
    assert len(f.at_risk_services) == 3


# -- reporting --------------------------------------------------------------


def test_unmeasured_impact_is_not_reported_as_zero():
    """"Not asked" and "nothing found" must not render identically."""
    measured = target("a", routes={Route.PUBLISHER: {"x"}}, services=[])
    skipped = target("b", routes={Route.PUBLISHER: {"x"}}, measured=False)
    assert "nothing in the fleet uses it" in measured.explain()
    assert "not measured" in skipped.explain()


def test_render_states_when_the_frontier_is_empty():
    """An empty frontier is a real answer and must say so explicitly."""
    f = Frontier(target="lonely@1.0.0", exists=True)
    text = f.render()
    assert "No reachable packages" in text


def test_render_states_when_the_version_is_absent():
    """Absent from the graph is a different answer from having no frontier."""
    f = Frontier(target="ghost@9.9.9", exists=False)
    assert "not in the graph" in f.render()


def test_render_surfaces_the_impact_cap():
    """A truncated ranking must announce itself."""
    f = Frontier(
        target="x@1", exists=True, impact_skipped=7,
        targets=[target("a", routes={Route.PUBLISHER: {"x"}})],
    )
    text = f.render()
    assert "not measured for 7" in text
    assert "not dropped" in text


def test_render_lists_identities_to_rotate():
    f = Frontier(
        target="x@1", exists=True,
        targets=[target("a", routes={Route.PUBLISHER: {"alice"}})],
        implicated={Route.PUBLISHER: {"alice"}, Route.MAINTAINER: {"bob"}},
    )
    text = f.render()
    assert "ROTATE THESE FIRST" in text
    assert "alice" in text and "bob" in text


# -- CI identities are declined, and said so --------------------------------


def test_declined_publisher_route_is_stated_not_silent():
    """"No publisher route" and "we declined to follow one" differ.

    Following npm's OIDC identity produced a 77-package frontier for
    `pino@10.2.1` built out of packages sharing only a build system. Dropping
    it silently would leave a reader thinking no publish path was found.
    """
    f = Frontier(
        target="pino@10.2.1", exists=True,
        service_identities=["GitHub Actions"],
    )
    text = f.render()
    assert "LOOKED FOR, NOT FOLLOWED" in text
    assert "GitHub Actions" in text
    assert "not a credential" in text


def test_no_note_when_no_ci_identity_was_seen():
    """The caveat must not appear on packages it does not apply to."""
    f = Frontier(target="x@1", exists=True)
    assert "NOT FOLLOWED" not in f.render()


@live
def test_oidc_published_version_draws_no_publisher_frontier():
    """End to end: a real OIDC-published version must not fan out by publisher.

    `pino`, `cookie`, `semver` and `raw-body` all carry npm's OIDC identity in
    this corpus and share nothing else.
    """
    from blastradius import schema
    from blastradius.hydra_client import HydraClient
    from blastradius.ids import IdAllocator
    from blastradius.pkg.identity import is_service_identity, version_key

    client = HydraClient()
    with IdAllocator() as ids:
        engine = FrontierEngine(client, ids)
        vid = ids.lookup(schema.PACKAGE_VERSION, version_key("pino", "10.2.1"))
        if vid is None:
            pytest.skip("pino@10.2.1 not in this corpus")

        rows = client.query(
            "MATCH (v:PackageVersion {id: $id})-[:PUBLISHED_BY]->"
            "(p:PublisherIdentity) RETURN p.username AS username, p.email AS email",
            {"id": vid},
        )
        if not any(
            is_service_identity(r["username"], r["email"]) for r in rows
        ):
            pytest.skip("pino@10.2.1 was not published by a CI identity here")

        f = engine.analyse("pino", "10.2.1", measure_impact=False)
        assert f.service_identities, "the declined identity must be recorded"
        for t in f.targets:
            assert Route.PUBLISHER not in t.routes, (
                f"{t.package} was reached by the CI publisher route, which "
                f"links a build system rather than a credential"
            )


# -- the live half ----------------------------------------------------------


@live
def test_frontier_against_the_real_corpus():
    """A real package with real maintainers must project a real frontier."""
    from blastradius import schema
    from blastradius.hydra_client import HydraClient
    from blastradius.ids import IdAllocator
    from blastradius.pkg.identity import parse_purl

    client = HydraClient()
    with IdAllocator() as ids:
        engine = FrontierEngine(client, ids)
        # Candidates come from the local id map, not a label scan. `MATCH
        # (v:PackageVersion) RETURN ...` is the obvious way to write this and
        # it is rejected outright once the graph passes 250k versions --
        # admission control caps label-index candidates. The id map is the L0
        # layer the design prescribes for exactly this, and it costs no graph
        # hit at all.
        keys = ids.keys_with_prefix(schema.PACKAGE_VERSION, "pkg:npm/")
        if not keys:
            pytest.skip("no package versions ingested")

        found = None
        for key, _ in keys[:400]:
            parsed = parse_purl(key)
            if parsed is None or not parsed.version:
                continue
            f = engine.analyse(parsed.name, parsed.version)
            if f.exists and f.targets:
                found = f
                break
        if found is None:
            pytest.skip("no version in this corpus has a shared publish path")

        assert found.reachable_packages > 0
        for t in found.targets:
            assert t.routes, "a frontier row must carry the route that found it"
            assert t.confidence == Confidence.INVESTIGATE
            assert t.package != found.target.split("@")[0]


@live
def test_absent_version_yields_an_empty_frontier():
    """A name the graph does not hold must not raise or invent rows."""
    from blastradius.hydra_client import HydraClient
    from blastradius.ids import IdAllocator

    client = HydraClient()
    with IdAllocator() as ids:
        f = FrontierEngine(client, ids).analyse("no-such-package-xyzzy", "0.0.1")
    assert not f.exists
    assert f.targets == []
    assert "not in the graph" in f.render()
