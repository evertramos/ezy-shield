-- 011: since-strike watermark for the long-window counters (issue #636).
--
-- A strike consumes the evidence that earned it: the in-memory aggregator
-- is reset on a ban (issue #621), but the persistent hourly counters kept
-- counting the same failures, so ONE more event after the ban expired
-- re-fired the daily/weekly rules and climbed the ladder. This table holds,
-- per (ip, window, kind), the count that had accumulated in that window
-- when the last strike was recorded; the long-window evaluation subtracts
-- it. Rows older than their own window are ignored (their events have
-- aged out) and pruned with the counters. Integers only — no hostile data.
-- APPEND-ONLY: never edit this file; add a new migration instead.
CREATE TABLE IF NOT EXISTS events_consumed (
    ip          TEXT    NOT NULL,
    window_s    INTEGER NOT NULL, -- rule window in seconds
    kind        TEXT    NOT NULL,
    consumed    INTEGER NOT NULL DEFAULT 0,
    recorded_at INTEGER NOT NULL, -- epoch seconds of the strike
    PRIMARY KEY (ip, window_s, kind)
);
