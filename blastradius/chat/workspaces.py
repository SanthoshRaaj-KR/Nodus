"""One chatbot per repository, and the guarantee that they never mix.

The graph is a single fleet by construction: `service_key` is global, ids are
allocated per `(label, natural_key)`, and `PackageVersion` nodes are shared on
purpose -- `lodash@4.17.21` really is the same thing wherever it appears, and
splitting it per repository would undo the identity work in `pkg/identity.py`.

So isolation cannot come from the store. HydraDB's per-graph and per-namespace
scoping both exist, but the bearer token this project ships is authorised for
`default` alone -- asking for any other graph is a 403 -- so a graph per repo
would mean re-provisioning auth, a much larger change than the thing it buys.

Isolation therefore comes from **ownership of a service set**. A workspace
records exactly which `Service` nodes an ingest created, and every tool the
agent can call is filtered to those ids. Two repositories can then sit in one
graph -- verified, not assumed: ingesting a second repository without `--reset`
adds its services and merges the versions it shares, leaving both answerable
apart.

What that buys, and what it does not:

* **Shared package versions are correct.** Asking "who resolves lodash@4.17.20"
  is always answered inside one workspace's service set, so a version present
  in two repositories reports each one's exposure separately.
* **A name collision is the one real hazard.** `service_key` is
  `svc:<lowercased name>`, so two repositories that both contain a service
  called `api` collapse into one node, and no filter downstream can pull them
  apart again. That is detected at registration and reported, because silently
  merging two teams' exposure is precisely the failure this module exists to
  prevent.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import RLock

from blastradius import schema
from blastradius.ids import IdAllocator
from blastradius.pkg.identity import InvalidPackageName, service_key

from .config import ROOT

#: Local state: absolute paths to somebody's checkouts, plus whatever they
#: chose to call them. Kept beside the other per-build state in data/.
DEFAULT_REGISTRY = ROOT / "data" / "chat-workspaces.json"


def _slugify(text: str) -> str:
    """A url-safe token for `/chat/<slug>`, or "" when nothing survives."""
    cleaned = re.sub(r"[^a-z0-9]+", "-", (text or "").strip().lower()).strip("-")
    return cleaned[:48]


@dataclass
class Workspace:
    """One repository's chatbot, and the services it is allowed to see."""

    id: int
    slug: str
    label: str
    repo_path: str
    #: Service names this workspace owns, as written by the ingest.
    service_names: list[str] = field(default_factory=list)
    #: The same services as graph ids, resolved through the id allocator.
    #: Stored rather than re-derived so a workspace keeps naming the same
    #: nodes even if `service_key` is ever changed underneath it.
    service_ids: list[int] = field(default_factory=list)
    created_at: int = 0
    #: Service names that already belonged to another workspace when this one
    #: was registered. Recorded, never silently dropped -- see the module
    #: docstring on why a collision is the one thing this cannot paper over.
    collisions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "Workspace":
        return cls(
            id=int(raw.get("id", 0)),
            slug=str(raw.get("slug", "")),
            label=str(raw.get("label", "")),
            repo_path=str(raw.get("repo_path", "")),
            service_names=[str(s) for s in raw.get("service_names") or []],
            service_ids=[int(i) for i in raw.get("service_ids") or []],
            created_at=int(raw.get("created_at", 0)),
            collisions=[str(s) for s in raw.get("collisions") or []],
        )

    @property
    def url(self) -> str:
        return f"/chat/{self.id}"

    def summary(self) -> dict:
        """What the picker page and `/api/chat/workspaces` show."""
        return {
            "id": self.id,
            "slug": self.slug,
            "label": self.label,
            "repo_path": self.repo_path,
            "services": len(self.service_ids),
            "service_names": self.service_names,
            "created_at": self.created_at,
            "collisions": self.collisions,
            "url": self.url,
        }


class WorkspaceRegistry:
    """The set of chatbots, persisted as one small JSON file.

    JSON rather than a table because it is read on nearly every request and
    written about once per ingest, it is small enough to rewrite whole, and it
    stays legible to whoever has to work out why a chatbot is answering for the
    wrong repository. Guarded by a lock because FastAPI serves these handlers
    from a thread pool and a torn rewrite would lose a workspace.
    """

    def __init__(self, path: Path | str | None = None, ids: IdAllocator | None = None):
        self.path = Path(path or os.environ.get("CHAT_WORKSPACES") or DEFAULT_REGISTRY)
        self._lock = RLock()
        self._ids = ids

    # -- storage -----------------------------------------------------------

    def _load(self) -> list[Workspace]:
        if not self.path.exists():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # A corrupt registry must not take the server down: an empty list
            # degrades to "no chatbots yet", which is recoverable by
            # registering one. Raising here would 500 every chat route.
            return []
        return [Workspace.from_dict(r) for r in raw.get("workspaces") or []]

    def _save(self, workspaces: list[Workspace]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "workspaces": [w.to_dict() for w in workspaces]}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    # -- reads -------------------------------------------------------------

    def list(self) -> list[Workspace]:
        with self._lock:
            return sorted(self._load(), key=lambda w: w.id)

    def get(self, ref: str | int) -> Workspace | None:
        """Look one up by numeric id or by slug. `/chat/2` and `/chat/web` both work."""
        token = str(ref).strip().lower()
        for workspace in self.list():
            if str(workspace.id) == token or workspace.slug == token:
                return workspace
        return None

    def owned_names(self, exclude_id: int | None = None) -> dict[str, int]:
        """service name -> the workspace id that already claims it."""
        out: dict[str, int] = {}
        for workspace in self.list():
            if exclude_id is not None and workspace.id == exclude_id:
                continue
            for name in workspace.service_names:
                out[name.strip().lower()] = workspace.id
        return out

    # -- writes ------------------------------------------------------------

    def _resolve_ids(self, names: list[str]) -> list[int]:
        """Service names -> graph ids, skipping any the allocator never saw.

        A name with no id means the ingest did not actually write that service,
        so including it would give the workspace a phantom member every query
        silently ignores. Dropping it keeps `len(service_ids)` an honest count
        of what the chatbot can see.
        """
        allocator = self._ids or IdAllocator()
        out: list[int] = []
        for name in names:
            try:
                found = allocator.lookup(schema.SERVICE, service_key(name))
            except InvalidPackageName:
                continue
            if found is not None:
                out.append(found)
        return sorted(set(out))

    def register(
        self,
        label: str,
        repo_path: str,
        service_names: list[str],
        slug: str = "",
    ) -> Workspace:
        """Add a chatbot for one repository's services.

        Re-registering the same repository path replaces the previous entry
        rather than stacking a second chatbot on the same services -- a repo
        re-scanned after a fix is the same repo, and two chatbots answering
        for it would disagree the moment one of them was refreshed.
        """
        with self._lock:
            workspaces = self._load()
            names = sorted({n.strip() for n in service_names if n and n.strip()})
            resolved = str(Path(repo_path).expanduser())

            existing = next((w for w in workspaces if w.repo_path == resolved), None)
            workspace_id = existing.id if existing else (
                max((w.id for w in workspaces), default=0) + 1
            )

            claimed = self.owned_names(exclude_id=workspace_id)
            collisions = sorted({n for n in names if n.strip().lower() in claimed})

            chosen = _slugify(slug or label or Path(resolved).name) or f"repo-{workspace_id}"
            taken = {w.slug for w in workspaces if w.id != workspace_id}
            if chosen in taken:
                chosen = f"{chosen}-{workspace_id}"

            workspace = Workspace(
                id=workspace_id,
                slug=chosen,
                label=(label or Path(resolved).name or f"repo {workspace_id}").strip(),
                repo_path=resolved,
                service_names=names,
                service_ids=self._resolve_ids(names),
                created_at=int(time.time()),
                collisions=collisions,
            )
            workspaces = [w for w in workspaces if w.id != workspace_id]
            workspaces.append(workspace)
            self._save(workspaces)
            return workspace

    def remove(self, ref: str | int) -> bool:
        """Forget a chatbot. The graph keeps its services -- this is a view."""
        with self._lock:
            workspaces = self._load()
            target = self.get(ref)
            if target is None:
                return False
            self._save([w for w in workspaces if w.id != target.id])
            return True

    def refresh_ids(self, ref: str | int) -> Workspace | None:
        """Re-resolve a workspace's service ids after a graph rebuild.

        Ids are allocated per `(label, natural_key)` and survive a re-ingest,
        but a `reset` clears `data/ids.sqlite` and the next ingest hands every
        node a fresh number. A workspace pointing at the old ones would then
        answer for nothing at all, which reads exactly like "you are not
        affected". This is the repair.
        """
        with self._lock:
            workspace = self.get(ref)
            if workspace is None:
                return None
            workspace.service_ids = self._resolve_ids(workspace.service_names)
            others = [w for w in self._load() if w.id != workspace.id]
            self._save(others + [workspace])
            return workspace
