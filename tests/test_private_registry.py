"""Pointing the tool at a registry that is not public npm.

The gap this closes: every read was hardcoded to `registry.npmjs.org`, so an
internal package resolved its metadata against a registry where it does not
exist, and the live watcher tailed a feed that will never mention it. A fleet
built on a private or proxied registry was invisible to the half of the tool
that watches, and wrong in the half that ingests.

The part worth testing hardest is the credential. A token for an internal
registry must never travel to npmjs.org because a package happened to resolve
there, and "it usually doesn't" is not a property -- so it is asserted.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.pkg import registry as reg  # noqa: E402
from blastradius.pkg import watcher as wat  # noqa: E402


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in (reg.ENV_REGISTRY, reg.ENV_TOKEN, wat.ENV_CHANGES):
        monkeypatch.delenv(name, raising=False)


def client(tmp_path, **kw):
    return reg.RegistryClient(cache_dir=tmp_path, offline=True, **kw)


# -- configuration ----------------------------------------------------------

def test_defaults_to_public_npm(tmp_path):
    assert client(tmp_path).registry == reg.REGISTRY


def test_environment_overrides_the_default(tmp_path, monkeypatch):
    monkeypatch.setenv(reg.ENV_REGISTRY, "https://npm.internal.example/")
    assert client(tmp_path).registry == "https://npm.internal.example"


def test_an_explicit_argument_beats_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv(reg.ENV_REGISTRY, "https://from-env.example")
    assert client(tmp_path, registry="https://explicit.example").registry == \
        "https://explicit.example"


def test_a_trailing_slash_does_not_produce_a_double_slash(tmp_path):
    c = client(tmp_path, registry="https://npm.internal.example/")
    assert c.registry == "https://npm.internal.example"


# -- the credential ---------------------------------------------------------

def test_the_token_reaches_the_configured_registry_and_nowhere_else(
    tmp_path, monkeypatch
):
    """The one that matters. A private-registry token leaking to npmjs.org
    because a package resolved there is a credential disclosure, not a bug."""
    c = client(tmp_path, registry="https://npm.internal.example", token="s3cret")

    captured = []

    class FakeResponse:
        headers = {}

        def read(self):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(request, timeout=None):
        captured.append((request.full_url, dict(request.headers)))
        return FakeResponse()

    monkeypatch.setattr(reg.urllib.request, "urlopen", fake_urlopen)
    c.offline = False

    c._get_json("https://npm.internal.example/lodash")
    c._get_json("https://registry.npmjs.org/lodash")

    internal, public = captured
    assert any(k.lower() == "authorization" for k in internal[1]), \
        "the configured registry should receive the token"
    assert not any(k.lower() == "authorization" for k in public[1]), \
        "a different host must never receive it"


def test_no_token_means_no_authorization_header(tmp_path, monkeypatch):
    c = client(tmp_path, registry="https://npm.internal.example", token="")
    captured = []

    class FakeResponse:
        headers = {}
        def read(self): return b"{}"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(reg.urllib.request, "urlopen",
                        lambda r, timeout=None: (captured.append(dict(r.headers)),
                                                 FakeResponse())[1])
    c.offline = False
    c._get_json("https://npm.internal.example/lodash")
    assert not any(k.lower() == "authorization" for k in captured[0])


def test_the_token_is_not_part_of_the_cache_key(tmp_path):
    """It is a credential and it rotates. Keying on it would throw the whole
    cache away every time somebody refreshed one."""
    a = client(tmp_path, registry="https://r.example", token="one")
    b = client(tmp_path, registry="https://r.example", token="two")
    assert a._cache_path("https://r.example/x", "") == \
        b._cache_path("https://r.example/x", "")


def test_two_registries_do_not_share_cache_entries(tmp_path):
    """Same package name, different registry, different content."""
    a = client(tmp_path, registry="https://a.example")
    b = client(tmp_path, registry="https://b.example")
    assert a._cache_path("https://a.example/lodash", "") != \
        b._cache_path("https://b.example/lodash", "")


# -- download counts --------------------------------------------------------

def test_public_npm_still_uses_the_api_host_for_downloads(tmp_path):
    assert client(tmp_path).downloads_base == "https://api.npmjs.org"


def test_a_private_registry_does_not_get_rewritten_to_api(tmp_path):
    """`registry.` -> `api.` is an npm-specific trick and would invent a
    hostname that does not exist anywhere else."""
    c = client(tmp_path, registry="https://npm.internal.example")
    assert c.downloads_base == "https://npm.internal.example"


# -- the watcher ------------------------------------------------------------

def test_the_watcher_defaults_to_the_public_feed():
    w = wat.Watcher(ids=None)
    assert w.changes_url == wat.CHANGES_URL
    assert w.status()["public_feed"] is True


def test_the_watcher_feed_is_configurable(monkeypatch):
    monkeypatch.setenv(wat.ENV_CHANGES, "https://npm.internal.example/_changes")
    w = wat.Watcher(ids=None)
    assert w.changes_url == "https://npm.internal.example/_changes"
    assert w.status()["public_feed"] is False


def test_the_status_names_the_registry_being_watched(tmp_path):
    """A user who configured an internal registry and is in fact being shown
    public npm has been misled by their own tool."""
    w = wat.Watcher(
        registry=reg.RegistryClient(cache_dir=tmp_path, offline=True,
                                    registry="https://npm.internal.example"),
        ids=None,
    )
    assert w.status()["registry"] == "https://npm.internal.example"
