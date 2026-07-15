-- 004_ban_suppression.sql: persistent suppression counters for the
-- ban_ineffective diagnostic (ADR-0009). Counters live on bans_active so
-- their lifecycle matches the ban itself: reset by the RecordStrike upsert,
-- removed by ban expiry. offenders.had_ineffective is the permanent memory
-- consumed by the pre-permanent alert; it survives daemon restarts and ban
-- expiry.
-- APPEND-ONLY: never edit this file; add a new migration instead.

ALTER TABLE bans_active ADD COLUMN suppressed_total INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bans_active ADD COLUMN suppressed_after_grace INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bans_active ADD COLUMN ineffective_fired INTEGER NOT NULL DEFAULT 0;

ALTER TABLE offenders ADD COLUMN had_ineffective INTEGER NOT NULL DEFAULT 0;
