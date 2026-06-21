-- 0038_connector_lifecycle_observability.sql -- served deploy/rotation evidence.
--
-- These are read models projected from connector.delivery.recorded and
-- lifecycle.rotation.recorded events. They carry no credential/key material: only
-- ids, status, public fingerprints, rollback references, and worker errors.

CREATE TABLE IF NOT EXISTS connector_delivery_receipts (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL,
    outbox_id        bigint,
    identity_id      uuid,
    destination      text NOT NULL DEFAULT 'connector.deploy',
    connector        text NOT NULL,
    target           text NOT NULL,
    fingerprint      text NOT NULL DEFAULT '',
    status           text NOT NULL,
    attempts         integer NOT NULL DEFAULT 0,
    reason           text NOT NULL DEFAULT '',
    detail           text NOT NULL DEFAULT '',
    rollback_ref     text NOT NULL DEFAULT '',
    idempotency_key  text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL,
    UNIQUE (tenant_id, outbox_id)
);

ALTER TABLE connector_delivery_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_delivery_receipts FORCE ROW LEVEL SECURITY;

CREATE POLICY connector_delivery_receipts_isolation ON connector_delivery_receipts
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

CREATE INDEX IF NOT EXISTS connector_delivery_receipts_tenant_updated_idx
    ON connector_delivery_receipts (tenant_id, updated_at DESC, id);

CREATE INDEX IF NOT EXISTS connector_delivery_receipts_identity_idx
    ON connector_delivery_receipts (tenant_id, identity_id, updated_at DESC, id)
    WHERE identity_id IS NOT NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON connector_delivery_receipts TO trstctl_app;

CREATE TABLE IF NOT EXISTS lifecycle_rotation_runs (
    id                      uuid PRIMARY KEY,
    tenant_id               uuid NOT NULL,
    identity_id             uuid NOT NULL,
    outbox_id               bigint,
    status                  text NOT NULL,
    trigger                 text NOT NULL,
    reason                  text NOT NULL DEFAULT '',
    predecessor_fingerprint text NOT NULL DEFAULT '',
    successor_fingerprint   text NOT NULL DEFAULT '',
    rollback_ref            text NOT NULL DEFAULT '',
    error                   text NOT NULL DEFAULT '',
    idempotency_key         text NOT NULL DEFAULT '',
    created_at              timestamptz NOT NULL,
    updated_at              timestamptz NOT NULL,
    completed_at            timestamptz,
    UNIQUE (tenant_id, outbox_id)
);

ALTER TABLE lifecycle_rotation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle_rotation_runs FORCE ROW LEVEL SECURITY;

CREATE POLICY lifecycle_rotation_runs_isolation ON lifecycle_rotation_runs
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

CREATE INDEX IF NOT EXISTS lifecycle_rotation_runs_tenant_updated_idx
    ON lifecycle_rotation_runs (tenant_id, updated_at DESC, id);

CREATE INDEX IF NOT EXISTS lifecycle_rotation_runs_identity_idx
    ON lifecycle_rotation_runs (tenant_id, identity_id, updated_at DESC, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON lifecycle_rotation_runs TO trstctl_app;
