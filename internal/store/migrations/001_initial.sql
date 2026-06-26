-- 001_initial.sql: baseline schema for EzyShield persistence.
-- APPEND-ONLY: never edit this file; add a new migration instead.

-- offenders: one row per IP, never pruned, includes 1-strike IPs.
CREATE TABLE IF NOT EXISTS offenders (
    ip            TEXT    PRIMARY KEY,
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL,
    total_strikes INTEGER NOT NULL DEFAULT 0
);

-- strikes: individual strike events.
CREATE TABLE IF NOT EXISTS strikes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT    NOT NULL,
    recorded_at TEXT    NOT NULL,
    strike_num  INTEGER NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    reason      TEXT    NOT NULL,
    verdicts    TEXT    NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_strikes_ip ON strikes(ip);

-- bans_active: currently active ban for each IP.
-- expires_at NULL means permanent.
CREATE TABLE IF NOT EXISTS bans_active (
    ip         TEXT    PRIMARY KEY,
    banned_at  TEXT    NOT NULL,
    expires_at TEXT,
    strike_num INTEGER NOT NULL,
    reason     TEXT    NOT NULL
);

-- verdicts: full verdict audit trail.
CREATE TABLE IF NOT EXISTS verdicts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ip                  TEXT    NOT NULL,
    scored_at           TEXT    NOT NULL,
    score               INTEGER NOT NULL,
    category            TEXT    NOT NULL,
    confidence          REAL    NOT NULL,
    reason              TEXT    NOT NULL,
    source              TEXT    NOT NULL,
    suggest_ttl_seconds INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdicts_ip ON verdicts(ip);

-- ai_usage: token budget accounting per AI call.
CREATE TABLE IF NOT EXISTS ai_usage (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    called_at     TEXT    NOT NULL,
    provider      TEXT    NOT NULL,
    input_tokens  INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    cost_usd      REAL    NOT NULL
);

-- audit_log: append-only security journal.
-- There MUST be no UPDATE or DELETE paths that touch this table anywhere in the codebase.
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at TEXT    NOT NULL,
    op          TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    strike_num  INTEGER NOT NULL,
    reason      TEXT    NOT NULL
);
