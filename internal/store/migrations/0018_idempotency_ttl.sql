-- 0018_idempotency_ttl.sql — bound the idempotency_keys table (SPINE-002).
--
-- idempotency_keys (AN-5) records one permanent row per served mutation, with
-- the cached result bytea. It previously had no retention: a busy fleet wrote
-- rows forever, so the table, its index, and every backup grew without bound,
-- and completed keys/results were retained indefinitely (a privacy/compliance
-- concern). A background sweep now deletes keys whose completed_at is older than
-- a retention window that comfortably exceeds any client's retry horizon, so the
-- table is bounded while AN-5 still holds inside the window (a retry within the
-- window still finds its cached result).
--
-- This index makes the sweep's predicate (DELETE … WHERE completed_at < cutoff)
-- and the bound check cheap: it scans only the eligible tail rather than the
-- whole table. Pending rows (completed_at IS NULL) never expire and stay out of
-- the index. RLS and grants are inherited from 0002 (idempotency_keys).

CREATE INDEX IF NOT EXISTS idempotency_keys_completed_at_idx
    ON idempotency_keys (completed_at)
    WHERE completed_at IS NOT NULL;
