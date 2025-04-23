"""gateway/store.py

SQLite persistence: a counters table and an append-only events table.

The events table is append-only. This module exposes INSERT and SELECT for it and nothing
else: no UPDATE, no DELETE, no truncate helper. A usage log that can be quietly edited is
worth nothing as evidence, so the restriction is enforced twice, once by omitting the API
and once by SQLite triggers that raise on UPDATE or DELETE. Counters are updated in place
but a trigger rejects any write that lowers a count.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Iterator

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS counters (
    device_id  TEXT PRIMARY KEY,
    count      INTEGER NOT NULL CHECK (count >= 0),
    updated_at REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    device_id     TEXT NOT NULL,
    event         TEXT NOT NULL,
    sequence      INTEGER NOT NULL,
    service       TEXT,
    characteristic TEXT,
    payload_head  BLOB
);

CREATE INDEX IF NOT EXISTS events_device_ts ON events(device_id, ts);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Append-only, enforced at the database.
CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only');
END;

-- Monotonicity, enforced at the database as well as in counter.py.
CREATE TRIGGER IF NOT EXISTS counters_no_rollback
BEFORE UPDATE ON counters
WHEN NEW.count < OLD.count
BEGIN
    SELECT RAISE(ABORT, 'counter rollback rejected');
END;
"""


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- counters -------------------------------------------------------------

    def save_counter(self, device_id: str, count: int) -> None:
        """Upsert. The trigger aborts if this would lower a stored count."""
        self._conn.execute(
            "INSERT INTO counters(device_id, count, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(device_id) DO UPDATE SET count=excluded.count, "
            "updated_at=excluded.updated_at",
            (device_id, count, time.time()),
        )

    def load_counters(self) -> dict[str, int]:
        rows = self._conn.execute("SELECT device_id, count FROM counters").fetchall()
        return {r["device_id"]: r["count"] for r in rows}

    def save_sequence(self, sequence: int) -> None:
        cur = self.load_sequence()
        if sequence < cur:
            raise ValueError(f"sequence rollback {cur} -> {sequence}")
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES ('sequence', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(sequence),),
        )

    def load_sequence(self) -> int:
        row = self._conn.execute("SELECT value FROM meta WHERE key='sequence'").fetchone()
        return int(row["value"]) if row else 0

    # -- events (insert and read only) ----------------------------------------

    def append_event(
        self,
        device_id: str,
        event: str,
        sequence: int,
        service: str | None = None,
        characteristic: str | None = None,
        payload_head: bytes | None = None,
        ts: float | None = None,
    ) -> None:
        self._conn.execute(
            "INSERT INTO events(ts, device_id, event, sequence, service, characteristic,"
            " payload_head) VALUES (?,?,?,?,?,?,?)",
            (
                ts if ts is not None else time.time(),
                device_id,
                event,
                sequence,
                service,
                characteristic,
                payload_head[:16] if payload_head else None,
            ),
        )

    def recent_events(self, limit: int = 50) -> Iterator[sqlite3.Row]:
        yield from self._conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    def event_count(self, device_id: str | None = None) -> int:
        if device_id is None:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE device_id=?", (device_id,)
            ).fetchone()
        return int(row["n"])
