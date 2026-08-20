"""Synthetic incidents: identity and scope.

Nothing here touches a real package or a live node. The one property being
pinned is that an incident is keyed to an exact version, because the whole
version-awareness claim collapses if two targets can share an incident node.
"""

from __future__ import annotations

from blastradius.pkg.incident import SIMULATED_COMPROMISED, SyntheticIncident, incident_id_for


def test_each_target_gets_its_own_incident_id():
    """The bug this pins: a constant id, and a second run that never replaced
    the first.

    ``create_incident`` MERGEs the Incident node by id and then adds a
    COMPROMISES edge. With one id shared by every run, simulating a second
    version left the first edge in place, so a single node claimed two
    different versions and both reported as compromised -- the exact
    distinction the tool exists to draw, undone by its own demo command.
    """
    a = incident_id_for("lodash", "4.17.21")
    b = incident_id_for("lodash", "4.17.20")
    assert a != b
    assert "4.17.21" in a and "4.17.20" in b


def test_the_id_is_stable_across_calls():
    """Re-marking has to land on the same node, or MERGE mints a duplicate."""
    assert incident_id_for("lodash", "4.17.21") == incident_id_for("lodash", "4.17.21")


def test_create_and_clear_default_to_the_same_id():
    """The bug the test above did not catch: a correct id nobody called.

    ``incident_id_for`` was right, and pinned, and ``clear_incident``
    defaulted to it -- while ``create_incident`` defaulted to a literal
    ``"SYNTHETIC-001"``. So a caller that passed no id wrote one node and
    retracted another. Every drill hung a further COMPROMISES edge off the
    shared node, its summary was overwritten by the newest target, and the
    retraction reported success having deleted nothing. Eight runs against
    this repo left eight packages permanently marked compromised.

    Testing the generator was not enough, because the generator was never
    the part that was wrong. This pins the pairing itself.
    """
    import inspect

    from blastradius.pkg.incident import clear_incident, create_incident

    create_default = inspect.signature(create_incident).parameters["incident_id"].default
    clear_default = inspect.signature(clear_incident).parameters["incident_id"].default
    assert create_default is None, (
        "create_incident must fall through to incident_id_for, not pin a "
        "literal id that clear_incident will never look up"
    )
    assert clear_default is None
    assert create_default == clear_default


def test_scoped_packages_keep_their_scope_in_the_id():
    scoped = incident_id_for("@angular/core", "17.0.0")
    assert scoped != incident_id_for("core", "17.0.0")


def test_the_id_survives_a_name_that_differs_only_in_case():
    """npm folds case on lookup, so the key has to fold it too -- otherwise
    `Lodash` and `lodash` would mark two nodes for one package."""
    assert incident_id_for("LoDash", "4.17.21") == incident_id_for("lodash", "4.17.21")


def test_the_target_is_a_version_never_a_package():
    incident = SyntheticIncident(
        incident_id="SIM-1", package="lodash", version="4.17.21"
    )
    assert incident.target_key.endswith("@4.17.21")
    assert incident.status == SIMULATED_COMPROMISED


def test_the_summary_says_it_is_synthetic():
    """The demo marks an ordinary healthy public package. Anything that reads
    the graph later has to be able to tell that from a real compromise."""
    from blastradius.pkg import incident as mod

    text = mod.SyntheticIncident(
        incident_id="SIM-1", package="lodash", version="4.17.21",
        summary="Simulated supply-chain compromise of lodash@4.17.21. Synthetic: "
                "no real malicious package is involved.",
    ).summary
    assert "synthetic" in text.lower()
