-- Outbox leasing/fairness (SPINE-002).
-- migrate: no-transaction
--
-- The dispatcher claims due work by marking a row processing, commits that short
-- claim transaction, performs the external call outside PostgreSQL, then finalizes
-- the row in a second short transaction. The lease columns let another worker
-- recover a row if the claiming process dies after claim but before finalize.
ALTER TABLE outbox
    ADD COLUMN IF NOT EXISTS worker_id text,
    ADD COLUMN IF NOT EXISTS lease_until timestamptz;

-- The previous due index was time-only. The fair dispatcher needs the due scan to
-- line up with tenant/destination ordering, then id for stable head-of-queue picks.
-- online-safe: CONCURRENTLY avoids blocking writes on the live outbox table; this
-- no-transaction migration is idempotent and safe to retry before the ledger row.
DROP INDEX CONCURRENTLY IF EXISTS outbox_due_fair_idx;
CREATE INDEX CONCURRENTLY outbox_due_fair_idx
    ON outbox (next_attempt_at, tenant_id, destination, id)
    WHERE status = 'pending';

-- online-safe: the old due index is dropped only after the replacement exists.
DROP INDEX CONCURRENTLY IF EXISTS outbox_due_idx;

-- online-safe: CONCURRENTLY avoids blocking writes on the live outbox table; this
-- no-transaction migration is idempotent and safe to retry before the ledger row.
DROP INDEX CONCURRENTLY IF EXISTS outbox_processing_destination_idx;
CREATE INDEX CONCURRENTLY outbox_processing_destination_idx
    ON outbox (destination, lease_until)
    WHERE status = 'processing';

-- online-safe: CONCURRENTLY avoids blocking writes on the live outbox table; this
-- no-transaction migration is idempotent and safe to retry before the ledger row.
DROP INDEX CONCURRENTLY IF EXISTS outbox_processing_tenant_idx;
CREATE INDEX CONCURRENTLY outbox_processing_tenant_idx
    ON outbox (tenant_id, lease_until)
    WHERE status = 'processing';

-- online-safe: CONCURRENTLY avoids blocking writes on the live outbox table; this
-- no-transaction migration is idempotent and safe to retry before the ledger row.
DROP INDEX CONCURRENTLY IF EXISTS outbox_processing_lease_idx;
CREATE INDEX CONCURRENTLY outbox_processing_lease_idx
    ON outbox (lease_until, id)
    WHERE status = 'processing';
