-- Issue #228: daemon-side runtime state that must survive restarts.
-- First consumer: the arm auto-revert window ("arm --for 1h") — the revert
-- deadline lives here so the daemon reverts to dry-run even if the operator
-- lost their session or the daemon restarted mid-window (that loss is the
-- exact scenario the window protects against).
CREATE TABLE daemon_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
