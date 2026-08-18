"""Persisted key -> id allocator.

HydraDB reifies relationships: every edge carries its own `id` drawn from the
same global integer space as nodes. Ids therefore have to be handed out by
something that survives the process, or a second ingest run would mint fresh
ids for rows that already exist and duplicate the whole graph.

A counter with a persisted map is used rather than a hash of the key. A hash
gives no way to enumerate what has been allocated, and a collision is silent
corruption; a counter is dense, auditable, and makes `MERGE` by id idempotent.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from . import schema

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "ids.sqlite"


class IdAllocator:
    """Maps a stable natural key to a graph id, once, forever.

    The natural key is whatever uniquely identifies the thing in the source
    data -- ``"lodash@4.17.21"`` for a PackageVersion, ``"payment-api::src/auth.ts::verify::42"``
    for a Function. Same key in, same id out, across runs.

    Safe to share across threads. The UI server runs sync endpoints in a
    worker pool, so an allocator opened at import time is used from whichever
    thread serves the request; sqlite refuses that outright unless the
    connection is opened with ``check_same_thread=False``. That flag alone
    only removes the guard, so every statement is serialised behind a lock --
    ``get`` in particular reads a counter and writes it back, and two threads
    interleaving there would hand the same id to two different keys.
    """

    def __init__(self, db_path: Path | str = DEFAULT_DB):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.RLock()
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS ids (
                kind TEXT NOT NULL,
                key  TEXT NOT NULL,
                id   INTEGER NOT NULL,
                PRIMARY KEY (kind, key)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ids_by_id ON ids(id);
            CREATE TABLE IF NOT EXISTS counters (
                kind TEXT PRIMARY KEY,
                next INTEGER NOT NULL
            );
            """
        )
        self.conn.commit()
        self._cache: dict[tuple[str, str], int] = {}

    # -- allocation -------------------------------------------------------

    def get(self, kind: str, key: str) -> int:
        """Id for ``key``, allocating one from ``kind``'s block if new."""
        cached = self._cache.get((kind, key))
        if cached is not None:
            return cached

        with self._lock:
            row = self.conn.execute(
                "SELECT id FROM ids WHERE kind = ? AND key = ?", (kind, key)
            ).fetchone()
            if row is not None:
                self._cache[(kind, key)] = row[0]
                return row[0]

            new_id = self._next(kind)
            self.conn.execute(
                "INSERT INTO ids (kind, key, id) VALUES (?, ?, ?)", (kind, key, new_id)
            )
            self._cache[(kind, key)] = new_id
            return new_id

    def get_many(self, kind: str, keys: list[str]) -> dict[str, int]:
        """Bulk :meth:`get`, in the order given."""
        return {k: self.get(kind, k) for k in keys}

    def lookup(self, kind: str, key: str) -> int | None:
        """Id for ``key``, or None. Never allocates -- for read paths."""
        cached = self._cache.get((kind, key))
        if cached is not None:
            return cached
        with self._lock:
            row = self.conn.execute(
                "SELECT id FROM ids WHERE kind = ? AND key = ?", (kind, key)
            ).fetchone()
        return row[0] if row else None

    def keys_with_prefix(self, kind: str, prefix: str) -> list[tuple[str, int]]:
        """Every (key, id) under ``kind`` whose key starts with ``prefix``.

        This is how a package name becomes graph ids without touching the
        database. The equivalent Cypher is a label scan with a property filter
        -- 36ms on a small graph and linear in node count -- because there is
        no index to hit. The id map already holds exactly this mapping, and
        SQLite has an index on it.

        Uses a half-open range rather than LIKE. ``_`` and ``%`` are both legal
        in an npm package name, so a LIKE pattern would need escaping and would
        silently over-match if that were ever got wrong. A range comparison
        needs no escaping and walks the primary-key index directly.
        """
        if not prefix:
            return []
        # Successor of the prefix: everything starting with `prefix` sorts
        # below it, nothing else does.
        upper = prefix[:-1] + chr(ord(prefix[-1]) + 1)
        with self._lock:
            return list(
                self.conn.execute(
                    "SELECT key, id FROM ids "
                    "WHERE kind = ? AND key >= ? AND key < ? ORDER BY key",
                    (kind, prefix, upper),
                )
            )

    def key_for(self, node_id: int) -> tuple[str, str] | None:
        """Reverse lookup: id -> (kind, key). Used to label query results."""
        with self._lock:
            row = self.conn.execute(
                "SELECT kind, key FROM ids WHERE id = ?", (node_id,)
            ).fetchone()
        return (row[0], row[1]) if row else None

    def _next(self, kind: str) -> int:
        lo, hi = schema.block_for(kind)
        row = self.conn.execute(
            "SELECT next FROM counters WHERE kind = ?", (kind,)
        ).fetchone()
        nxt = row[0] if row else lo
        if nxt > hi:
            raise OverflowError(
                f"id block for {kind!r} is exhausted at {hi}; widen it in schema.py"
            )
        self.conn.execute(
            "INSERT INTO counters (kind, next) VALUES (?, ?) "
            "ON CONFLICT(kind) DO UPDATE SET next = excluded.next",
            (kind, nxt + 1),
        )
        return nxt

    # -- lifecycle --------------------------------------------------------

    def commit(self) -> None:
        with self._lock:
            self.conn.commit()

    def counts(self) -> dict[str, int]:
        """Allocated count per kind, for the ingest summary."""
        with self._lock:
            return {
                kind: n
                for kind, n in self.conn.execute(
                    "SELECT kind, count(*) FROM ids GROUP BY kind ORDER BY kind"
                )
            }

    def close(self) -> None:
        with self._lock:
            self.conn.commit()
            self.conn.close()

    def __enter__(self) -> "IdAllocator":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
