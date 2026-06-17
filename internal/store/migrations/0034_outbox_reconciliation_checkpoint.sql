-- Outbox reconciliation checkpoint (SPINE-003): a single-row, system
-- (non-tenant) table that records the highest event-stream sequence whose
-- side-effect intent has been checked against the outbox.
--
-- The boot reconciler exists for the append-then-project crash gap: an identity
-- lifecycle event may be durable in JetStream while the matching outbox row was
-- not committed yet. Replaying from this watermark+1 keeps boot work bounded to
-- the unreconciled tail instead of the whole lifetime event log, while preserving
-- AN-2 (events are still the source of truth) and AN-6 (effects are still
-- enqueued idempotently).
--
-- It carries no tenant_id by design: JetStream sequence numbers are global and
-- monotonic, so the reconciliation cursor is one deployment-wide system
-- watermark, like projection_checkpoint and schema_migrations.

CREATE TABLE IF NOT EXISTS outbox_reconciliation_checkpoint (
    id             smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    reconciled_seq bigint   NOT NULL DEFAULT 0,
    updated_at     timestamptz NOT NULL DEFAULT now()
);

INSERT INTO outbox_reconciliation_checkpoint (id, reconciled_seq)
VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;
