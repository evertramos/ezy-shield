-- 002_scan_baseline.sql: port/service discovery baseline for drift detection.
-- APPEND-ONLY: never edit this file; add a new migration instead.

-- scan_baseline: one row per (proto, addr:port), upserted on every scan.
-- first_seen is set at INSERT and never updated; last_seen tracks the most
-- recent scan that observed this listener.  Drift is detected by comparing
-- the current scan result to this table and flagging rows absent from it.
CREATE TABLE IF NOT EXISTS scan_baseline (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    proto          TEXT    NOT NULL,  -- "tcp" | "tcp6"
    local_addr     TEXT    NOT NULL,  -- "ip:port" string (netip.AddrPort.String())
    first_seen     TEXT    NOT NULL,
    last_seen      TEXT    NOT NULL,
    pid            INTEGER NOT NULL DEFAULT 0,
    exe_path       TEXT    NOT NULL DEFAULT '',
    uid            INTEGER NOT NULL DEFAULT 0,
    user_name      TEXT    NOT NULL DEFAULT '',
    is_public      INTEGER NOT NULL DEFAULT 0,  -- 0|1 boolean
    owner_type     TEXT    NOT NULL DEFAULT 'unknown',  -- "systemd"|"docker"|"unknown"
    unit_name      TEXT    NOT NULL DEFAULT '',
    container_id   TEXT    NOT NULL DEFAULT '',
    container_name TEXT    NOT NULL DEFAULT '',
    container_image TEXT   NOT NULL DEFAULT '',
    log_source     TEXT    NOT NULL DEFAULT '',
    UNIQUE(proto, local_addr)
);
