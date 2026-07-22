-- ADR-0009 §5: dry-run mirrors armed semantics.
-- Simulated bans (recorded while armed=false) live in bans_active with
-- dry_run=1 so the active-ban suppression guard works identically in
-- dry-run, but they are NEVER pushed to an enforcer: the daemon filters
-- them out of every enforcement sync, and an armed engine ignores them
-- for suppression (a real strike overwrites the row with dry_run=0).
ALTER TABLE bans_active ADD COLUMN dry_run INTEGER NOT NULL DEFAULT 0;
