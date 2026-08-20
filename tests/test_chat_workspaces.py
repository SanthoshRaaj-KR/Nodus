"""One chatbot per repository, and the promise that they do not mix.

These run against a temporary registry file and a stub id allocator, so they
need neither a graph nor an API key. The isolation guarantee is a property of
this module alone -- every tool downstream trusts `service_ids` completely --
which makes it the right place to pin the behaviour down.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius import schema  # noqa: E402
from blastradius.chat.workspaces import (  # noqa: E402
    Workspace,
    WorkspaceRegistry,
    _slugify,
)


class StubIds:
    """An id map that knows about a fixed set of services."""

    def __init__(self, known: dict[str, int]):
        self.known = known

    def lookup(self, kind: str, key: str):
        assert kind == schema.SERVICE
        return self.known.get(key)


@pytest.fixture
def registry(tmp_path):
    ids = StubIds({
        "svc:api": 1, "svc:web": 2, "svc:worker": 3,
        "svc:billing": 4, "svc:jobs": 5,
    })
    return WorkspaceRegistry(path=tmp_path / "workspaces.json", ids=ids)


def test_slugify_makes_url_tokens():
    assert _slugify("Blast Radius Console!") == "blast-radius-console"
    assert _slugify("  ---  ") == ""
    assert len(_slugify("x" * 200)) <= 48


def test_register_resolves_names_to_graph_ids(registry):
    workspace = registry.register("Backend", "/repos/backend", ["api", "worker"])
    assert workspace.id == 1
    assert workspace.service_ids == [1, 3]
    assert workspace.url == "/chat/1"


def test_unknown_services_are_dropped_not_counted(registry):
    """A name with no id is a phantom -- every query would silently ignore it.

    Keeping it would make `len(service_ids)` overstate what the chatbot can
    actually see, which is the wrong direction for a tool that reports
    exposure.
    """
    workspace = registry.register("Mixed", "/repos/mixed", ["api", "does-not-exist"])
    assert workspace.service_ids == [1]
    assert "does-not-exist" in workspace.service_names


def test_ids_increment_per_repository(registry):
    first = registry.register("A", "/repos/a", ["api"])
    second = registry.register("B", "/repos/b", ["web"])
    assert (first.id, second.id) == (1, 2)
    assert {w.id for w in registry.list()} == {1, 2}


def test_reregistering_the_same_path_replaces_rather_than_stacks(registry):
    """A repo re-scanned after a fix is the same repo.

    Two chatbots over one path would disagree the moment one was refreshed.
    """
    registry.register("Backend", "/repos/backend", ["api"])
    again = registry.register("Backend renamed", "/repos/backend", ["api", "worker"])
    assert again.id == 1
    assert len(registry.list()) == 1
    assert again.service_ids == [1, 3]


def test_lookup_by_id_or_slug(registry):
    registry.register("Web app", "/repos/web", ["web"])
    assert registry.get(1).label == "Web app"
    assert registry.get("1").label == "Web app"
    assert registry.get("web-app").label == "Web app"
    assert registry.get("nope") is None


def test_slug_collisions_are_disambiguated(registry):
    first = registry.register("Web", "/repos/one", ["web"])
    second = registry.register("Web", "/repos/two", ["api"])
    assert first.slug != second.slug


def test_service_name_collision_is_reported_not_merged(registry):
    """The one hazard the design cannot paper over.

    `service_key` is `svc:<name>`, so two repositories that both contain a
    service called `api` collapse into one graph node and no downstream filter
    can separate their exposure again. Detecting it is the whole mitigation --
    silently merging two teams' findings is exactly what must not happen.
    """
    registry.register("First", "/repos/first", ["api"])
    second = registry.register("Second", "/repos/second", ["api", "billing"])
    assert second.collisions == ["api"]


def test_no_collision_when_names_are_distinct(registry):
    registry.register("First", "/repos/first", ["api"])
    second = registry.register("Second", "/repos/second", ["web", "worker"])
    assert second.collisions == []


def test_reregistering_does_not_collide_with_itself(registry):
    """A repo re-registered must not be reported as clashing with its own name."""
    registry.register("First", "/repos/first", ["api"])
    again = registry.register("First", "/repos/first", ["api", "web"])
    assert again.collisions == []


def test_owned_names_maps_back_to_the_claiming_chatbot(registry):
    registry.register("First", "/repos/first", ["api"])
    registry.register("Second", "/repos/second", ["web"])
    assert registry.owned_names() == {"api": 1, "web": 2}
    assert registry.owned_names(exclude_id=1) == {"web": 2}


def test_remove_forgets_only_the_named_chatbot(registry):
    registry.register("First", "/repos/first", ["api"])
    registry.register("Second", "/repos/second", ["web"])
    assert registry.remove(1) is True
    assert [w.id for w in registry.list()] == [2]
    assert registry.remove("gone") is False


def test_refresh_reresolves_ids_after_a_rebuild(registry):
    """`reset` clears data/ids.sqlite and the next ingest renumbers everything.

    A workspace still pointing at the old ids would match no nodes at all,
    which reads exactly like a clean bill of health.
    """
    workspace = registry.register("Backend", "/repos/backend", ["api"])
    assert workspace.service_ids == [1]
    registry._ids = StubIds({"svc:api": 99})
    refreshed = registry.refresh_ids(workspace.id)
    assert refreshed.service_ids == [99]
    assert registry.get(1).service_ids == [99]


def test_registry_survives_a_corrupt_file(tmp_path):
    """A bad registry degrades to "no chatbots", never a 500 on every route."""
    path = tmp_path / "workspaces.json"
    path.write_text("{not json", encoding="utf-8")
    assert WorkspaceRegistry(path=path, ids=StubIds({})).list() == []


def test_registry_round_trips_through_disk(registry):
    registry.register("Backend", "/repos/backend", ["api", "worker"])
    reloaded = WorkspaceRegistry(path=registry.path, ids=StubIds({}))
    workspace = reloaded.get(1)
    assert workspace.service_ids == [1, 3]
    assert workspace.service_names == ["api", "worker"]


def test_workspace_dict_round_trip():
    workspace = Workspace(
        id=3, slug="s", label="L", repo_path="/p",
        service_names=["a"], service_ids=[7], created_at=1, collisions=["a"],
    )
    assert Workspace.from_dict(workspace.to_dict()) == workspace
