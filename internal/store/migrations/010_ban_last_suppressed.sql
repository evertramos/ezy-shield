-- 010: last_suppressed_at on bans_active (issue #587).
--
-- ineffective_fired was a one-way flag: set once per ban by MarkBanIneffective
-- and only ever reset when a NEW ban row replaced the old one. A permanent ban
-- is never replaced, so a single past leak kept `doctor` at FAIL forever and
-- a later, new leak on the same ban could never fire again. Recording WHEN
-- the last suppressed event arrived lets both sides recover: the doctor
-- distinguishes "still leaking" from "leaked once, quiet for weeks", and the
-- store re-arms the diagnostic after a quiet period. NULL = never suppressed
-- (or pre-migration row with no history): callers treat it as unknown and
-- fail closed.
-- APPEND-ONLY: never edit this file; add a new migration instead.

ALTER TABLE bans_active ADD COLUMN last_suppressed_at TEXT;
