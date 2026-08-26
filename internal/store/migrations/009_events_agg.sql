-- 009: persistent per-IP hourly event counters (issue #134).
--
-- Long-window (>1h) detection cannot live in the in-memory aggregator: a 24h
-- horizon would retain every event per IP in RAM and is defeated by the LRU
-- cap and daemon restarts — exactly the failure modes a low-and-slow attacker
-- exploits. Counts live here instead: one row per (ip, kind, hour), storing
-- ONLY aggregate integers — never usernames, paths, or raw log lines (the
-- "no hostile data persisted" rule). Rows are pruned once older than the
-- longest long-window rule.
CREATE TABLE IF NOT EXISTS events_agg (
    ip           TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    bucket_start INTEGER NOT NULL, -- UTC hour floor, epoch seconds
    count        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, kind, bucket_start)
);
CREATE INDEX IF NOT EXISTS idx_events_agg_ip_bucket ON events_agg(ip, bucket_start);
