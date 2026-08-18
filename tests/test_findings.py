"""Findings: what the graph facts are allowed to claim.

`_build_findings` turns rows into verdicts, and it is the one place where a
true fact can become a false claim. These tests pin the two rules that
matter -- exposure needs something to be exposed to, and a relational match
never becomes one.

No live node is needed: the method reads an already-populated result.
"""

from __future__ import annotations

import pytest

from blastradius import schema
from blastradius.pkg.blast import (
    BlastRadius,
    BlastRadiusEngine,
    Confidence,
    Evidence,
    derive_confidence,
)


@pytest.fixture
def engine():
    return BlastRadiusEngine(client=None, ids=None)


def _result(**kw) -> BlastRadius:
    result = BlastRadius(target="lodash@4.17.21", target_id=1, exists=True)
    result.metadata = {"name": "lodash", "version": "4.17.21"}
    for key, value in kw.items():
        setattr(result, key, value)
    return result


def _project(service="rest-api", depth=schema.DIRECT_DEPTH, **kw) -> dict:
    row = {"service": service, "depth": depth, "via_direct": "", "dev_only": 0}
    row.update(kw)
    return row


INCIDENT = [{"incident_id": "SIM-1", "live_from": 0, "live_until": 0}]


# -- exposure needs something to be exposed to -----------------------------


def test_unmarked_version_does_not_produce_an_exposure_finding(engine):
    """The bug this pins: looking up a healthy package flagged its users.

    A project resolving a version is the same graph fact whether or not the
    version is compromised. The claim is not the same, and an atom whose name
    asserts a compromise must not be emitted when nothing asserts one -- or
    every project in the corpus turns red the moment somebody types a package
    name into the box.
    """
    findings = engine._build_findings(_result(exposed_projects=[_project()]))
    project = next(f for f in findings if f.entity_type == "Project")

    assert Evidence.RESOLVES_COMPROMISED_VERSION not in project.atoms
    assert project.atoms == {Evidence.RESOLVES_SUBJECT_VERSION}
    assert project.status == "RESOLVES_VERSION"
    assert project.confidence == Confidence.LOW
    assert "no incident" not in project.reason  # it still says what it found


def test_the_same_project_is_exposed_once_an_incident_names_the_version(engine):
    findings = engine._build_findings(
        _result(exposed_projects=[_project()], incidents=INCIDENT)
    )
    project = next(f for f in findings if f.entity_type == "Project")

    assert project.atoms == {Evidence.RESOLVES_COMPROMISED_VERSION}
    assert project.status == "DIRECTLY_EXPOSED"
    assert project.confidence == Confidence.HIGH


def test_an_advisory_alone_is_enough_to_make_it_exposure(engine):
    """A published CVE is a real threat even with no incident recorded."""
    findings = engine._build_findings(
        _result(
            exposed_projects=[_project()],
            advisories=[{"advisory_id": "GHSA-x", "summary": ""}],
        )
    )
    project = next(f for f in findings if f.entity_type == "Project")
    assert project.atoms == {Evidence.RESOLVES_COMPROMISED_VERSION}
    assert project.confidence == Confidence.HIGH


def test_transitive_and_live_window_atoms_need_a_threat_too(engine):
    """Both elevate to HIGH, so neither may fire on an unmarked version."""
    findings = engine._build_findings(
        _result(
            exposed_projects=[_project(depth=3, via_direct="sequelize@6")],
            live_window_projects=[_project()],
        )
    )
    project = next(f for f in findings if f.entity_type == "Project")
    assert Evidence.TRANSITIVELY_EXPOSED not in project.atoms
    assert Evidence.LIVE_WINDOW_OVERLAP not in project.atoms
    assert project.confidence == Confidence.LOW


def test_depth_still_reaches_the_reason_when_unmarked(engine):
    """Downgrading the claim must not throw the detail away."""
    findings = engine._build_findings(
        _result(exposed_projects=[_project(depth=3, via_direct="sequelize@6")])
    )
    project = next(f for f in findings if f.entity_type == "Project")
    assert "depth 3" in project.reason
    assert "sequelize@6" in project.reason


# -- a relational match is never a verdict ---------------------------------


def test_relational_atoms_cannot_be_raised_by_piling_them_up():
    every = {
        Evidence.SHARED_MAINTAINER,
        Evidence.SHARED_REPOSITORY,
        Evidence.SHARED_PUBLISHER,
        Evidence.TYPOSQUAT_NEIGHBOR,
    }
    assert derive_confidence(every) == Confidence.INVESTIGATE


def test_shared_maintainer_stays_investigate_beside_a_real_incident(engine):
    findings = engine._build_findings(
        _result(
            incidents=INCIDENT,
            exposed_projects=[_project()],
            shared_maintainer=[{"package": "lodash.merge", "maintainer": "jdalton"}],
        )
    )
    sibling = next(f for f in findings if f.entity == "lodash.merge")
    assert sibling.confidence == Confidence.INVESTIGATE
    assert sibling.negative_evidence, "an INVESTIGATE verdict must say what is absent"


def test_the_subject_itself_is_certain_only_when_an_incident_names_it(engine):
    unmarked = engine._build_findings(_result())
    assert not [f for f in unmarked if f.confidence == Confidence.CERTAIN]

    marked = engine._build_findings(_result(incidents=INCIDENT))
    certain = [f for f in marked if f.confidence == Confidence.CERTAIN]
    assert len(certain) == 1
    assert certain[0].entity == "lodash@4.17.21"


# -- dev-only stays a caveat, not a downgrade ------------------------------


def test_a_dev_only_route_is_reported_as_negative_evidence_not_silence(engine):
    findings = engine._build_findings(
        _result(exposed_projects=[_project(dev_only=1)], incidents=INCIDENT)
    )
    project = next(f for f in findings if f.entity_type == "Project")
    assert project.confidence == Confidence.HIGH, "still a finding"
    assert any("devDependency" in note for note in project.negative_evidence)
