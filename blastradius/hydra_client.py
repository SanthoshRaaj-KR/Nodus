"""HydraDB client: HTTP JSON API, with a Bolt fallback for bulk loads.

HTTP is the default because it needs no driver patching. Everything a caller
sees is plain Python -- the wire format is typed cells,
``{"type": "string", "value": "lodash"}``, and :func:`_flatten` unwraps them.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Sequence

DEFAULT_HTTP = "http://127.0.0.1:8443"
DEFAULT_TOKEN = "local-development-token-32-bytes"
DEFAULT_NAMESPACE = "default"
DEFAULT_GRAPH = "default"
DEFAULT_CELL = "cell-0"

#: One statement per request and no transactions, so a batch is a single
#: UNWIND. Large enough to amortise the round trip, small enough that a failed
#: chunk is cheap to replay.
BATCH_SIZE = 500


class HydraError(RuntimeError):
    """A statement was rejected, or the node was unreachable."""


@dataclass
class QueryResult:
    columns: list[str]
    rows: list[dict[str, Any]]
    bookmark: str | None = None
    elapsed_ms: float = 0.0

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.rows)

    def __len__(self) -> int:
        return len(self.rows)

    def scalar(self, column: str | None = None) -> Any:
        """First value of the named column, or of the only column; None if empty."""
        if not self.rows:
            return None
        return self.rows[0].get(column or self.columns[0])

    def column(self, name: str) -> list[Any]:
        return [r.get(name) for r in self.rows]


def _flatten(cell: Any) -> Any:
    """Unwrap one typed cell into a plain Python value.

    Lists and paths nest, so this recurses. Anything already plain passes
    through untouched, which keeps it safe against a response shape that
    changes underneath us.
    """
    if isinstance(cell, dict) and "type" in cell and "value" in cell:
        kind, value = cell["type"], cell["value"]
        if kind == "null":
            return None
        if kind in ("list", "path"):
            return _flatten(value)
        return value
    if isinstance(cell, list):
        return [_flatten(v) for v in cell]
    if isinstance(cell, dict):
        # Path payloads arrive as nested maps of vertices and edges. Keep the
        # structure whole -- the UI draws it, and collapsing it to bare ids
        # would throw away the edge types that make a chain readable.
        return {k: _flatten(v) for k, v in cell.items()}
    return cell


class HydraClient:
    """Synchronous client over the HTTP query endpoint."""

    def __init__(
        self,
        base_url: str = DEFAULT_HTTP,
        token: str = DEFAULT_TOKEN,
        namespace: str = DEFAULT_NAMESPACE,
        graph: str = DEFAULT_GRAPH,
        cell: str = DEFAULT_CELL,
        timeout_ms: int = 60_000,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.namespace = namespace
        self.graph = graph
        self.cell = cell
        self.timeout_ms = timeout_ms
        self.last_bookmark: str | None = None

    def query(
        self,
        statement: str,
        parameters: dict[str, Any] | None = None,
        consistency: str | None = None,
        use_bookmark: bool = False,
        retries: int = 3,
    ) -> QueryResult:
        """Run one statement. One statement per request is a server limit."""
        body: dict[str, Any] = {
            "cell_id": self.cell,
            "query": statement,
            "timeout_ms": self.timeout_ms,
        }
        if parameters:
            body["parameters"] = parameters
        if consistency:
            body["consistency"] = consistency
        if use_bookmark and self.last_bookmark:
            body["bookmark"] = self.last_bookmark

        request = urllib.request.Request(
            f"{self.base_url}/v1/graphs/{self.graph}/query",
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "X-Graph-Namespace": self.namespace,
                "Content-Type": "application/json",
            },
        )

        started = time.perf_counter()
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(
                    request, timeout=self.timeout_ms / 1000 + 5
                ) as response:
                    raw = json.loads(response.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                # A rejected statement is deterministic -- the parser will say
                # no just as fast next time, so do not spend retries on it.
                detail = exc.read().decode("utf-8", "replace")
                raise HydraError(
                    f"HTTP {exc.code} from HydraDB\n"
                    f"  statement: {statement.strip()[:400]}\n"
                    f"  response:  {detail[:800]}"
                ) from None
            except urllib.error.URLError as exc:
                if attempt == retries - 1:
                    raise HydraError(
                        f"cannot reach HydraDB at {self.base_url} ({exc.reason}). "
                        f"Is the container up? Try: hydra.ps1 status"
                    ) from None
                time.sleep(0.5 * (2**attempt))

        elapsed = (time.perf_counter() - started) * 1000
        columns = raw.get("columns") or []
        rows = []
        for row in raw.get("rows") or []:
            if isinstance(row, list):
                rows.append({c: _flatten(v) for c, v in zip(columns, row)})
            else:
                rows.append({k: _flatten(v) for k, v in row.items()})
        if raw.get("bookmark"):
            self.last_bookmark = raw["bookmark"]
        return QueryResult(columns, rows, raw.get("bookmark"), elapsed)

    def batch(
        self,
        statement: str,
        rows: Sequence[dict[str, Any]],
        param: str = "rows",
        size: int = BATCH_SIZE,
        progress: bool = False,
        label: str = "",
    ) -> int:
        """Run an UNWIND statement over rows in chunks; returns rows sent.

        Each chunk is an independent auto-commit, so a crash leaves a prefix
        written. That is safe because every write form here is a MERGE by id,
        making a re-run idempotent rather than duplicating.
        """
        rows = list(rows)
        if not rows:
            return 0
        sent = 0
        for i in range(0, len(rows), size):
            chunk = rows[i : i + size]
            self.query(statement, {param: chunk})
            sent += len(chunk)
            if progress:
                print(f"  {label or 'rows'}: {sent}/{len(rows)}", end="\r", flush=True)
        if progress:
            print(f"  {label or 'rows'}: {sent}/{len(rows)}  done")
        return sent

    def ready(self) -> bool:
        try:
            self.query("MATCH (n {id: 0}) RETURN n.id AS id")
            return True
        except HydraError:
            return False

    def counts_by_label(self, labels: Iterable[str]) -> dict[str, int]:
        """Node count per label. No IN operator, so one statement per label."""
        return {
            label: self.query(f"MATCH (n:{label}) RETURN count(*) AS n").scalar("n") or 0
            for label in labels
        }


def bolt_session(uri: str = "bolt://127.0.0.1:7687", token: str = DEFAULT_TOKEN):
    """A Bolt session with the two adjustments this server requires.

    1. HydraDB answers the handshake as SlateDBGraph/0.1.0 and a stock driver
       rejects any agent not starting with Neo4j/; the check is patched out.
    2. There are no explicit transactions -- execute_read/execute_write fail
       with TransactionStartFailed. Use auto-commit session.run; each statement
       is durable when it returns.
    """
    from neo4j import GraphDatabase
    from neo4j._sync.io import _bolt

    if hasattr(_bolt.Bolt, "_check_server_agent"):
        _bolt.Bolt._check_server_agent = staticmethod(lambda agent: None)

    return GraphDatabase.driver(uri, auth=("neo4j", token)).session()
