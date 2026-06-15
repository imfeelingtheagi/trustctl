-- Projection checkpoint (SPINE-007): a single-row, system (non-tenant) table that
-- records the highest event-stream sequence the relational read model has applied.
-- On boot the control plane catches up by replaying ONLY from this watermark+1
-- (the read model survives a restart in PostgreSQL), instead of re-applying the
-- whole log from sequence 0 — so cold start no longer grows linearly with the
-- lifetime event count. The read model is still a pure projection of the log
-- (AN-2): the watermark only bounds WHERE catch-up resumes; an explicit Rebuild
-- (disaster recovery / migration) still re-derives from sequence 0 and resets it.
--
-- It carries no tenant_id by design: the event-stream sequence is global and
-- monotonic (JetStream stream sequence), so the watermark is one number for the
-- whole deployment, not per tenant. Like schema_migrations it is owned by the
-- system role and never read under a tenant RLS context. The single row is keyed
-- by a fixed id so an UPSERT always targets it.
--
-- This is an additive, idempotent forward migration (CREATE ... IF NOT EXISTS):
-- it changes no existing row's behavior, and a fresh deployment starts at
-- applied_seq = 0 (full catch-up on first boot, identical to today).

CREATE TABLE IF NOT EXISTS projection_checkpoint (
    id          smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    applied_seq bigint   NOT NULL DEFAULT 0,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Seed the single row so the watermark read/advance can assume it exists.
INSERT INTO projection_checkpoint (id, applied_seq)
VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;
