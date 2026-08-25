-- 007: drop the dead `verdicts` table (issue #359).
--
-- Presented since 001 as the "full verdict audit trail", but no code path
-- ever inserted into or selected from it — verdicts are persisted as a JSON
-- column on strikes rows (strikes.verdicts), which IS the live audit trail.
-- Keeping the empty table (and its index) misdocuments where verdict history
-- lives and invites writes that nothing would ever read.
DROP INDEX IF EXISTS idx_verdicts_ip;
DROP TABLE IF EXISTS verdicts;
