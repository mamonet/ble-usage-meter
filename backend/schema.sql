-- backend/schema.sql
-- Schema for the usage meter backend.
--
-- usage_reports is APPEND-ONLY. There is no UPDATE or DELETE path for it anywhere in the
-- backend, and the triggers below enforce that at the database level. An accepted report is
-- evidence; rewriting one would let a device holder revise their own history, which is the
-- exact thing this system exists to prevent. Corrections are made by appending, never editing.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    device_id                TEXT PRIMARY KEY,
    -- base64 raw Ed25519 public key (32 bytes decoded). Registered out of band.
    public_key               TEXT NOT NULL,
    label                    TEXT,
    registered_at            TEXT NOT NULL,
    -- High-water marks. Both are the anti-rollback state; see backend/verify.py.
    -- -1 means no report accepted yet, so an honest first report at sequence 0 is valid.
    last_accepted_sequence   INTEGER NOT NULL DEFAULT -1,
    last_accepted_count      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS usage_reports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     TEXT NOT NULL REFERENCES devices(device_id),
    count         INTEGER NOT NULL,
    sequence      INTEGER NOT NULL,
    window_start  TEXT NOT NULL,
    window_end    TEXT NOT NULL,
    signature     TEXT NOT NULL,
    received_at   TEXT NOT NULL,
    -- One row per (device, sequence). A duplicate submission collides here even if the
    -- sequence check were somehow skipped; defence in depth, not the primary control.
    UNIQUE (device_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_usage_reports_device_window
    ON usage_reports (device_id, window_end);

-- Append-only enforcement. SQLite has no per-table permission model, so use triggers.
CREATE TRIGGER IF NOT EXISTS usage_reports_no_update
BEFORE UPDATE ON usage_reports
BEGIN
    SELECT RAISE(ABORT, 'usage_reports is append-only');
END;

CREATE TRIGGER IF NOT EXISTS usage_reports_no_delete
BEFORE DELETE ON usage_reports
BEGIN
    SELECT RAISE(ABORT, 'usage_reports is append-only');
END;

CREATE TABLE IF NOT EXISTS policies (
    device_id    TEXT PRIMARY KEY REFERENCES devices(device_id),
    active       INTEGER NOT NULL DEFAULT 0,
    quota_units  INTEGER,        -- NULL means no unit cap
    period_days  INTEGER,        -- NULL with a non-NULL quota_units is unevaluable -> deny
    expires_on   TEXT,           -- ISO date, NULL means no expiry
    notes        TEXT
);
