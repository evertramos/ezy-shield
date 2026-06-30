-- 003_allowlist.sql: temporal allowlist managed via `ezyshield allow`.
-- APPEND-ONLY: never edit this file; add a new migration instead.

-- allowlist: prefixes (single IPs are stored as /32 or /128) that bypass the
-- decision pipeline. expires_at NULL means permanent. The prefix column stores
-- the canonical (masked) form so duplicates collapse on insert.
CREATE TABLE IF NOT EXISTS allowlist (
    prefix     TEXT    PRIMARY KEY,
    expires_at TEXT,
    reason     TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL
);
