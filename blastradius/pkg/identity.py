"""Canonical identity for npm packages, versions, repositories and people.

Every entity in the graph is reached by a deterministic key, and the key is
what the id allocator hashes to an integer. Two consequences follow, and both
are correctness properties rather than tidiness:

* **Ingestion is idempotent.** The same package seen twice produces the same
  key, so ``MERGE`` finds the existing node instead of minting a second one.
* **A blast radius cannot be split.** If ``Lodash`` and ``lodash`` became two
  nodes, half the dependents would hang off each, and every query would
  under-report by an amount nobody could see. Normalisation is the only thing
  standing between us and that.

The identifiers follow the Package URL (purl) spec, so ``lodash@4.17.21`` is
``pkg:npm/lodash@4.17.21`` and a scoped package keeps its scope as the purl
namespace: ``@angular/core`` is ``pkg:npm/%40angular/core@17.0.0``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote, unquote

__all__ = [
    "ECOSYSTEM",
    "InvalidPackageName",
    "normalize_name",
    "split_scope",
    "package_key",
    "version_key",
    "service_key",
    "parse_purl",
    "normalize_repo_url",
    "repository_key",
    "maintainer_key",
    "organization_key",
    "publisher_key",
    "RepoRef",
]

ECOSYSTEM = "npm"


class InvalidPackageName(ValueError):
    """A string that cannot be an npm package name."""


# npm's own rules: at most 214 characters, no leading dot or underscore, no
# uppercase for new packages (but old ones exist, so we fold rather than
# reject), URL-safe. A scope is `@scope/`.
_NAME_RE = re.compile(r"^(?:@([^/]+)/)?([^/]+)$")
_ILLEGAL_RE = re.compile(r"[^a-z0-9._~@/-]")
_MAX_NAME = 214


def normalize_name(name: str) -> str:
    """Fold a package name to its canonical form.

    npm treats names case-insensitively for the purposes of collision -- you
    cannot publish ``LoDash`` alongside ``lodash`` -- but historical packages
    with uppercase letters still exist and appear verbatim in old lockfiles.
    Folding to lowercase is therefore a merge, not a rename, and it is what
    keeps one package from becoming two nodes.
    """
    if not isinstance(name, str):
        raise InvalidPackageName(f"expected a string, got {type(name).__name__}")
    text = name.strip()
    if not text:
        raise InvalidPackageName("empty package name")
    if len(text) > _MAX_NAME:
        raise InvalidPackageName(f"package name exceeds {_MAX_NAME} characters")

    text = text.lower()
    match = _NAME_RE.match(text)
    if not match:
        raise InvalidPackageName(f"not a valid npm package name: {name!r}")
    scope, bare = match.groups()
    if bare.startswith((".", "_")):
        raise InvalidPackageName(f"package name may not start with . or _: {name!r}")
    illegal = _ILLEGAL_RE.search(text)
    if illegal:
        raise InvalidPackageName(
            f"illegal character {illegal.group()!r} in package name: {name!r}"
        )
    return f"@{scope}/{bare}" if scope else bare


def split_scope(name: str) -> tuple[str | None, str]:
    """``@angular/core`` -> ``("@angular", "core")``; ``lodash`` -> ``(None, "lodash")``."""
    normalized = normalize_name(name)
    if normalized.startswith("@") and "/" in normalized:
        scope, bare = normalized.split("/", 1)
        return scope, bare
    return None, normalized


def package_key(name: str) -> str:
    """Canonical purl for a package, with no version.

    ``pkg:npm/lodash`` / ``pkg:npm/%40angular/core``.
    """
    scope, bare = split_scope(name)
    if scope:
        return f"pkg:{ECOSYSTEM}/{quote(scope, safe='')}/{bare}"
    return f"pkg:{ECOSYSTEM}/{bare}"


def version_key(name: str, version: str) -> str:
    """Canonical purl for one released version.

    The version is *not* normalised through the semver parser here. A registry
    may hold a version string we cannot parse, and rewriting it would break the
    join back to the registry and to the lockfile that named it. Identity is
    the literal published string; comparison is semver's job.
    """
    if not isinstance(version, str) or not version.strip():
        raise InvalidPackageName(f"empty version for package {name!r}")
    return f"{package_key(name)}@{version.strip()}"


def service_key(name: str) -> str:
    """Canonical key for a deployable unit, e.g. ``svc:web``.

    Both ingest tiers write ``Service`` nodes -- the lockfile loader in
    ``blastradius/ingest/load.py`` and the package tier in
    ``blastradius/pkg/ingest.py`` -- and they must agree, for exactly the
    reason spelled out on :func:`version_key`. A service name is a human
    label, not an npm name, so it is only stripped and lowercased; the ``svc:``
    prefix keeps it out of any other key space sharing the allocator.
    """
    text = (name or "").strip()
    if not text:
        raise InvalidPackageName("empty service name")
    return f"svc:{text.lower()}"


@dataclass(frozen=True)
class ParsedPurl:
    ecosystem: str
    name: str
    version: str | None


def parse_purl(purl: str) -> ParsedPurl:
    """Inverse of :func:`version_key` / :func:`package_key`."""
    if not purl.startswith("pkg:"):
        raise InvalidPackageName(f"not a purl: {purl!r}")
    body = purl[4:]
    ecosystem, _, rest = body.partition("/")
    if not rest:
        raise InvalidPackageName(f"purl has no name: {purl!r}")
    name_part, at, version = rest.rpartition("@")
    # rpartition on a scoped purl with no version would split the %40, so only
    # treat the tail as a version when something preceded the '@'.
    if not at or not name_part:
        name_part, version = rest, None
    return ParsedPurl(ecosystem, unquote(name_part), version or None)


# --------------------------------------------------------------------------
# Repositories
# --------------------------------------------------------------------------

#: Only the `git+` transport marker is stripped. `git://` and `ssh://git@` are
#: left alone because _HOST_PATH_RE already parses a scheme and a userinfo
#: part; removing them here would leave a bare `//host/path` that no longer
#: matches, which silently dropped every `git://` repository.
_GIT_PREFIX_RE = re.compile(r"^git\+")
_HOST_PATH_RE = re.compile(
    r"^(?:[a-z+]+://)?(?:[^@/]+@)?(?P<host>[^/:]+)[/:](?P<path>.+?)(?:\.git)?/?$"
)
#: Registry `repository` fields use these shorthands for GitHub.
_SHORTHAND_RE = re.compile(r"^(?:github:)?([\w.-]+)/([\w.-]+)$")


@dataclass(frozen=True)
class RepoRef:
    host: str
    owner: str
    name: str

    @property
    def key(self) -> str:
        return f"repo:{self.host}/{self.owner}/{self.name}"

    @property
    def url(self) -> str:
        return f"https://{self.host}/{self.owner}/{self.name}"


def normalize_repo_url(raw: str | None) -> RepoRef | None:
    """Reduce any of npm's repository spellings to one canonical reference.

    The registry carries the same GitHub repository as ``git+https://...``,
    ``git://...``, ``ssh://git@...``, ``https://...``, and the bare
    ``owner/name`` shorthand, with and without a ``.git`` suffix. Treating
    those as different repositories would break the shared-infrastructure
    signal exactly where it matters -- a compromised CI pipeline publishes
    several packages whose manifests were written by different people, and so
    spell the repository differently.

    Returns None when the value is absent or not a repository we can pin down;
    the caller records that as unknown rather than guessing.
    """
    if not raw or not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None

    shorthand = _SHORTHAND_RE.match(text)
    if shorthand and "://" not in text:
        owner, name = shorthand.groups()
        return RepoRef("github.com", owner.lower(), name.lower())

    text = _GIT_PREFIX_RE.sub("", text)
    text = text.split("#", 1)[0]  # strip a tree-ish suffix
    match = _HOST_PATH_RE.match(text)
    if not match:
        return None
    host = match.group("host").lower()
    path = match.group("path").strip("/")
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        return None
    # Take the first two segments: hosts like GitLab allow deeper nesting, but
    # owner/name is the unit that shares credentials.
    owner, name = parts[0].lower(), parts[1].lower()
    if name.endswith(".git"):
        name = name[:-4]
    return RepoRef(host, owner, name)


def repository_key(raw: str | None) -> str | None:
    ref = normalize_repo_url(raw)
    return ref.key if ref else None


# --------------------------------------------------------------------------
# People and organisations
# --------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def maintainer_key(username: str | None, email: str | None = None) -> str | None:
    """Identity for an npm account.

    The npm username is the identity that holds publish rights, so it is the
    key. Email is recorded as a property but deliberately not used for
    identity: one person may publish under several addresses, and more
    importantly an attacker who changes the email on a hijacked account must
    not thereby become a different node.
    """
    if username and isinstance(username, str) and username.strip():
        return f"npm-user:{username.strip().lower()}"
    if email and isinstance(email, str) and _EMAIL_RE.match(email.strip()):
        return f"email:{email.strip().lower()}"
    return None


def publisher_key(username: str | None, email: str | None = None) -> str | None:
    """Identity for the account that published one specific version.

    Same namespace as the maintainer -- ``_npmUser`` and ``maintainers`` name
    the same accounts -- but a distinct node label, because "who may publish"
    and "who did publish this artifact" are different questions and a
    compromise usually separates them.
    """
    return maintainer_key(username, email)


def organization_key(name: str) -> str:
    """Identity for an npm scope or a source-host owner.

    A scope (``@angular``) and a GitHub org (``angular``) are recorded under
    the same key when they share a name, because in practice they share the
    tokens that would be stolen.
    """
    return f"org:{name.strip().lstrip('@').lower()}"
