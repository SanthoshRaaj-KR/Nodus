"""Who published it, and what the chatbot is allowed to say about that.

Provenance is the one class of answer where the tempting failure is not an
invention but an *overclaim*. The graph knows which account pushed an
artifact and which accounts are listed as maintainers; the gap between those
two is the signature of a stolen publish token, and it is equally the
signature of a bot, an OIDC pipeline and a maintainer who left last year. So
the tests here are mostly about wording and about absence:

* a version with no publisher edge must read as "not recorded", never as
  "published anonymously", and must not name anybody;
* a publisher outside the maintainer list must be reported as a lead, with
  the word INVESTIGATE and without the word attacker;
* and the specs these tools report must not then be flagged by the grounding
  audit as invented, which is the regression that shipped the first time.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.chat import guardrails as G  # noqa: E402
from blastradius.chat import tools as T  # noqa: E402
from blastradius.chat.workspaces import WorkspaceRegistry  # noqa: E402


def _live():
    from blastradius.hydra_client import HydraClient, HydraError

    try:
        client = HydraClient()
        return client if client.ready() else None
    except HydraError:
        return None


live = pytest.mark.skipif(_live() is None, reason="HydraDB is not reachable")


@pytest.fixture
def scope():
    """The widest chatbot registered.

    Widest rather than first: a workspace over one service can easily hold
    only enriched packages, which silently skips exactly the absence cases
    this file exists to pin down.
    """
    from blastradius.hydra_client import HydraClient
    from blastradius.ids import IdAllocator

    workspaces = sorted(
        (w for w in WorkspaceRegistry().list() if w.service_ids),
        key=lambda w: len(w.service_ids),
        reverse=True,
    )
    if not workspaces:
        pytest.skip("no chatbots registered")
    client, ids = HydraClient(), IdAllocator()
    for workspace in workspaces:
        candidate = T.Scope(client=client, ids=ids, workspace=workspace)
        if T.workspace_packages(candidate):
            return candidate
    pytest.skip("no chatbot owns any resolved package")


def _partition(scope):
    """Held versions split by whether a publisher edge exists, in one query.

    The obvious form -- call `package_provenance` per held version until one
    matches -- is five graph reads times five hundred versions, and pays all
    of it before skipping when the answer is "none". One sweep of the publish
    edges and a set intersection does the same work in a single round trip.
    """
    from blastradius import schema

    published = {
        (str(row.get("name")), str(row.get("version")))
        for row in scope.client.query(
            f"MATCH (v:{schema.PACKAGE_VERSION})"
            f"-[:{schema.PUBLISHED_BY}]->(p:{schema.PUBLISHER}) "
            "RETURN DISTINCT v.name AS name, v.version AS version"
        ).rows
    }
    held = [(row["name"], row["version"]) for row in T.workspace_packages(scope)]
    with_pub = [pair for pair in held if pair in published]
    without = [pair for pair in held if pair not in published]
    return with_pub, without


def _with_publisher(scope):
    """One held version that actually carries a publisher edge."""
    with_pub, _ = _partition(scope)
    for name, version in with_pub:
        found = T.package_provenance(scope, f"{name}@{version}")
        if found.get("publisher_known"):
            return found
    return None


# --------------------------------------------------------------------------
# package_provenance
# --------------------------------------------------------------------------


@live
def test_a_recorded_publisher_is_named(scope):
    found = _with_publisher(scope)
    if found is None:
        pytest.skip("no version in this workspace carries publisher metadata")
    assert found["found"] is True
    assert found["published_by"]
    who = found["published_by"][0]
    assert who["username"]
    # Whether the pusher is on the maintainer list is the whole point of the
    # answer, so it is always decided rather than left for the model to infer.
    assert isinstance(who["is_listed_maintainer"], bool)
    assert isinstance(who["is_automation"], bool)


@live
def test_a_missing_publisher_reads_as_not_recorded_and_names_nobody(scope):
    """The overclaim this tool exists to avoid.

    An ingest run without registry metadata leaves the edge unwritten. That is
    an absence of data, and rendering it as an empty finding -- or worse, as
    an anonymous publish -- would invent a fact out of a gap.
    """
    _, blank = _partition(scope)
    if not blank:
        pytest.skip("every held version carries publisher metadata")

    name, version = blank[0]
    found = T.package_provenance(scope, f"{name}@{version}")
    assert found["publisher_known"] is False
    assert found["published_by"] == []
    note = found["note"].lower()
    assert "not recorded" in note
    assert "anonymous" in note  # says explicitly that this is NOT that
    assert "never fetched" in note or "was never" in note


@live
def test_publisher_not_maintainer_is_worded_as_a_lead(scope):
    """A shared shape between a compromise and a routine release.

    Reporting it as a verdict is the failure mode: it points an incident at a
    named human on evidence that does not support it.
    """
    with_pub, _ = _partition(scope)
    for name, version in with_pub:
        found = T.package_provenance(scope, f"{name}@{version}")
        flagged = [s for s in found.get("signals", []) if "PUBLISHER_NOT_MAINTAINER" in s]
        if not flagged:
            continue
        text = flagged[0]
        assert "INVESTIGATE" in text
        assert "not a verdict" in text
        assert "attacker" not in text.lower()
        assert "malicious" not in text.lower()
        return
    pytest.skip("no publisher-not-maintainer version in this workspace")


@live
def test_a_package_this_workspace_does_not_resolve_has_no_provenance(scope):
    found = T.package_provenance(scope, "evil-corp-sdk@6.6.6")
    assert found["found"] is False
    assert "resolves" in found["note"]


@live
def test_a_bare_name_asks_for_an_exact_version(scope):
    """Guessing a version here would attribute a publish to the wrong artifact."""
    rows = T.workspace_packages(scope)
    multi = {}
    for row in rows:
        multi.setdefault(row["name"], set()).add(row["version"])
    name = next((n for n, v in multi.items() if len(v) > 1), None)
    if name is None:
        pytest.skip("no package is held at more than one version")

    found = T.package_provenance(scope, name)
    assert found["found"] is False
    assert "exact name@version" in found["note"]
    assert len(found["suggestions"]) > 1


# --------------------------------------------------------------------------
# publish_anomalies
# --------------------------------------------------------------------------


@live
def test_publish_anomalies_reports_signals_and_never_asserts_malice(scope):
    report = T.publish_anomalies(scope)
    assert report["packages_assessed"] >= 0
    for row in report["signals"]:
        assert row["signal"]
        assert row["spec"].count("@") >= 1
        assert row["detail"]
    note = report["note"].lower()
    assert "investigate" in note
    assert "none of them says a package is malicious" in note


@live
def test_packages_the_cache_never_saw_are_reported_not_dropped(scope):
    """A package nobody could read is not a package with nothing to report."""
    report = T.publish_anomalies(scope)
    if not report["packages_unassessed"]:
        pytest.skip("the metadata cache covers every package here")
    assert "not exhaustive" in report["note"]


@live
def test_narrowing_to_one_package_filters_the_rows(scope):
    report = T.publish_anomalies(scope)
    if not report["signals"]:
        pytest.skip("no publish-time signals in this workspace")
    name = report["signals"][0]["package"]
    narrowed = T.publish_anomalies(scope, name)
    assert narrowed["signals"]
    assert {row["package"] for row in narrowed["signals"]} == {name}


# --------------------------------------------------------------------------
# the grounding audit, against what these tools legitimately report
# --------------------------------------------------------------------------


@live
def test_a_reported_release_is_not_flagged_as_invented(scope):
    """The regression this shipped with.

    `publish_anomalies` reports versions the repository does not *resolve* --
    that is what a publish-history signal is. Without them in `known_specs`
    the audit reports the tool's own output back as a hallucination, and the
    UI puts an "unverified" warning under a fact the graph produced.
    """
    report = T.publish_anomalies(scope)
    if not report["signals"]:
        pytest.skip("no publish-time signals in this workspace")
    spec = report["signals"][0]["spec"]
    assert G.ungrounded_specs(f"{spec} was pushed by a non-maintainer.", scope) == []


@live
def test_an_invented_package_is_still_caught_alongside_them(scope):
    """Widening the allowed set must not blunt the check it is widening."""
    T.publish_anomalies(scope)
    flagged = G.ungrounded_specs("Rotate now, evil-corp-sdk@6.6.6 is affected.", scope)
    assert "evil-corp-sdk@6.6.6" in flagged


@live
def test_the_grounding_audit_never_builds_the_publish_report(scope):
    """The audit runs on every answer; the report costs seconds to build cold.

    An answer can only name one of these specs if the tool already ran during
    the turn, so reading the cache without filling it is both cheaper and
    sufficient.
    """
    T.clear_caches()
    assert T.cached_publish_specs(scope) == set()
    T.publish_anomalies(scope)
    # Warm, the same call now answers from what the tool left behind.
    assert isinstance(T.cached_publish_specs(scope), set)
