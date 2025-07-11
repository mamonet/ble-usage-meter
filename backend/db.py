# backend/db.py
# SQLite connection handling and the migrations runner.

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

SCHEMA_PATH = Path(__file__).with_name("schema.sql")

# Bump when schema.sql changes in a way that needs a new apply.
SCHEMA_VERSION = 1

DEFAULT_DB_PATH = os.environ.get("METER_DB", "meter.db")


def connect(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), detect_types=0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")  # a lost accepted report is a billing hole
    return conn


def migrate(conn: sqlite3.Connection, schema_path: Path | None = None) -> int:
    """Apply schema.sql if this version has not been recorded. Idempotent."""
    path = schema_path or SCHEMA_PATH
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    row = conn.execute(
        "SELECT version FROM schema_migrations WHERE version = ?", (SCHEMA_VERSION,)
    ).fetchone()
    if row is not None:
        return SCHEMA_VERSION

    conn.executescript(path.read_text(encoding="utf-8"))
    conn.execute(
        "INSERT OR REPLACE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
        (SCHEMA_VERSION, utcnow_iso()),
    )
    return SCHEMA_VERSION


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = connect(db_path)
    migrate(conn)
    return conn


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_conn(db_path: str | Path = DEFAULT_DB_PATH) -> Iterator[sqlite3.Connection]:
    """FastAPI dependency. One connection per request; SQLite objects are not thread safe."""
    conn = init_db(db_path)
    try:
        yield conn
    finally:
        conn.close()
