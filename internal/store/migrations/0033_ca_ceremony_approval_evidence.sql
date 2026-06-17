-- PKIGOV-003: a CA key-ceremony approval only counts toward quorum after its
-- immutable event-log evidence exists. The row may be reserved before append so
-- retries are idempotent, but quorum queries count only rows with evidence.
-- migrate: no-transaction
ALTER TABLE ca_ceremony_approvals
  ADD COLUMN IF NOT EXISTS approval_event_id text;

ALTER TABLE ca_ceremony_approvals
  ADD COLUMN IF NOT EXISTS approval_event_sequence bigint;

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS ca_ceremony_approvals_event_id_unique
  ON ca_ceremony_approvals (tenant_id, approval_event_id)
  WHERE approval_event_id IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS ca_ceremony_approvals_evidence_count_idx
  ON ca_ceremony_approvals (tenant_id, ceremony_id)
  WHERE approval_event_id IS NOT NULL;
