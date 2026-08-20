"""The HTTP surface, exercised without a model.

Routing, scoping and the failure messages are the parts a user meets first
when something is misconfigured, and none of them need a key -- so all of it
is asserted here rather than being discovered live during a demo.

The one thing these must prove is that there is no unscoped way in. Every
answer route is keyed by workspace, and a request for a chatbot that does not
exist has to say which ones do rather than quietly answering as some default.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from blastradius.chat import router as R  # noqa: E402
from blastradius.chat.config import config  # noqa: E402
from blastradius.chat.workspaces import WorkspaceRegistry  # noqa: E402


class StubIds:
    def __init__(self, known=None):
        self.known = known or {}

    def lookup(self, kind, key):
        return self.known.get(key)


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A server whose registry is a scratch file, so tests never touch data/."""
    registry = WorkspaceRegistry(
        path=tmp_path / "workspaces.json",
        ids=StubIds({"svc:alpha": 11, "svc:beta": 12}),
    )
    R.wire(registry=registry)
    monkeypatch.setattr(R, "_ids", StubIds({"svc:alpha": 11, "svc:beta": 12}))

    app = FastAPI()
    app.include_router(R.router)
    with TestClient(app) as test_client:
        yield test_client, registry
    R.wire(registry=None)
    R._registry = None


def test_workspaces_start_empty(client):
    api, _ = client
    assert api.get("/api/chat/workspaces").json() == {"workspaces": []}


def test_register_and_list_a_chatbot(client):
    api, _ = client
    created = api.post("/api/chat/workspaces", json={
        "repo_path": "/repos/alpha", "label": "Alpha", "service_names": ["alpha"],
    }).json()
    assert created["id"] == 1
    assert created["url"] == "/chat/1"
    assert created["services"] == 1

    listed = api.get("/api/chat/workspaces").json()["workspaces"]
    assert [w["label"] for w in listed] == ["Alpha"]


def test_registering_without_a_repo_path_is_rejected(client):
    api, _ = client
    assert api.post("/api/chat/workspaces", json={"label": "x"}).status_code == 400


def test_registering_a_missing_path_names_the_path(client):
    api, _ = client
    response = api.post("/api/chat/workspaces", json={"repo_path": "/nope/nowhere"})
    assert response.status_code == 400
    assert "nowhere" in response.json()["detail"]


def test_a_name_collision_comes_back_as_a_warning(client):
    """Registering must not silently merge two repositories' findings."""
    api, _ = client
    api.post("/api/chat/workspaces", json={
        "repo_path": "/repos/one", "service_names": ["alpha"],
    })
    second = api.post("/api/chat/workspaces", json={
        "repo_path": "/repos/two", "service_names": ["alpha", "beta"],
    }).json()
    assert second["collisions"] == ["alpha"]
    assert "already claimed" in second["warning"]


def test_registering_services_the_graph_lacks_warns_rather_than_pretending(client):
    api, _ = client
    created = api.post("/api/chat/workspaces", json={
        "repo_path": "/repos/ghost", "service_names": ["not-ingested"],
    }).json()
    assert created["services"] == 0
    assert "Ingest the repository first" in created["warning"]


def test_an_unknown_chatbot_404s_and_names_the_real_ones(client):
    """Never answer as a default -- that is the mixing this design prevents."""
    api, _ = client
    api.post("/api/chat/workspaces", json={
        "repo_path": "/repos/alpha", "label": "Alpha", "service_names": ["alpha"],
    })
    response = api.get("/api/chat/99/health")
    assert response.status_code == 404
    assert "Alpha" in response.json()["detail"]


def test_unknown_chatbot_with_none_registered_says_how_to_add_one(client):
    api, _ = client
    response = api.get("/api/chat/1/health")
    assert response.status_code == 404
    assert "None registered" in response.json()["detail"]


def test_a_chatbot_is_reachable_by_slug_as_well_as_number(client):
    api, _ = client
    api.post("/api/chat/workspaces", json={
        "repo_path": "/repos/alpha", "label": "Alpha", "service_names": ["alpha"],
        "slug": "alpha",
    })
    by_id = api.get("/api/chat/1/health")
    by_slug = api.get("/api/chat/alpha/health")
    assert by_id.status_code == by_slug.status_code
    assert by_id.json()["workspace"]["id"] == by_slug.json()["workspace"]["id"] == 1


def test_asking_without_a_key_explains_exactly_what_is_missing(client, monkeypatch):
    api, _ = client
    api.post("/api/chat/workspaces", json={
        "repo_path": "/repos/alpha", "service_names": ["alpha"],
    })
    monkeypatch.setenv("OPENAI_API_KEY", "")
    config.cache_clear()
    try:
        response = api.post("/api/chat/1/ask", json={"message": "what is affected?"})
        assert response.status_code == 503
        assert "OPENAI_API_KEY" in response.json()["detail"]
        assert ".env" in response.json()["detail"]
    finally:
        config.cache_clear()


def test_a_full_size_model_is_refused(client, monkeypatch):
    """The project restricts itself to mini-class models."""
    api, _ = client
    api.post("/api/chat/workspaces", json={
        "repo_path": "/repos/alpha", "service_names": ["alpha"],
    })
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")
    monkeypatch.setenv("CHAT_MODEL", "gpt-5.4-pro")
    config.cache_clear()
    try:
        response = api.post("/api/chat/1/ask", json={"message": "hi"})
        assert response.status_code == 503
        assert "mini-class" in response.json()["detail"]
    finally:
        config.cache_clear()


def test_an_empty_question_is_rejected(client, monkeypatch):
    api, _ = client
    api.post("/api/chat/workspaces", json={
        "repo_path": "/repos/alpha", "service_names": ["alpha"],
    })
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")
    config.cache_clear()
    try:
        assert api.post("/api/chat/1/ask", json={"message": "   "}).status_code == 400
    finally:
        config.cache_clear()


def test_health_lists_every_problem_at_once(client, monkeypatch):
    """One round trip should say everything that is wrong, not the first thing."""
    api, _ = client
    api.post("/api/chat/workspaces", json={
        "repo_path": "/repos/ghost", "service_names": ["not-ingested"],
    })
    monkeypatch.setenv("OPENAI_API_KEY", "")
    config.cache_clear()
    try:
        body = api.get("/api/chat/1/health").json()
        assert body["ok"] is False
        joined = " ".join(body["problems"])
        assert "OPENAI_API_KEY" in joined
        assert "owns no graph services" in joined
        assert "key_present" in body["config"]
        assert "sk-" not in str(body)  # the key itself never appears
    finally:
        config.cache_clear()


def test_deleting_a_chatbot_leaves_the_others(client):
    api, _ = client
    api.post("/api/chat/workspaces", json={
        "repo_path": "/repos/a", "service_names": ["alpha"]})
    api.post("/api/chat/workspaces", json={
        "repo_path": "/repos/b", "service_names": ["beta"]})
    assert api.delete("/api/chat/workspaces/1").json()["removed"] is True
    remaining = api.get("/api/chat/workspaces").json()["workspaces"]
    assert [w["id"] for w in remaining] == [2]
