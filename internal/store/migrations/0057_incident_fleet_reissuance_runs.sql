-- 0057_incident_fleet_reissuance_runs.sql -- served compromised-issuer fleet reissuance evidence.
--
-- incident_fleet_reissuance_runs is a read model projected from
-- incident.fleet_reissuance.recorded events. It stores operational evidence only:
-- issuer and identity ids, graph impact JSON, batch metadata, delivery receipt
-- ids, rollback references, failed target labels, and the sealed audit evidence
-- bundle. It must never carry certificate/key/secret bytes.

CREATE TABLE IF NOT EXISTS incident_fleet_reissuance_runs (
    id                        uuid PRIMARY KEY,
    tenant_id                 uuid NOT NULL,
    issuer_id                 uuid NOT NULL,
    status                    text NOT NULL,
    phase                     text NOT NULL,
    reason                    text NOT NULL DEFAULT '',
    batch_size                integer NOT NULL DEFAULT 25,
    connector                 text NOT NULL DEFAULT '',
    target                    text NOT NULL DEFAULT '',
    graph_impact              jsonb NOT NULL DEFAULT '{}'::jsonb,
    affected_identity_ids     text[] NOT NULL DEFAULT '{}',
    replacement_identity_ids  text[] NOT NULL DEFAULT '{}',
    revoked_identity_ids      text[] NOT NULL DEFAULT '{}',
    connector_delivery_ids    text[] NOT NULL DEFAULT '{}',
    batches                   jsonb NOT NULL DEFAULT '[]'::jsonb,
    health_gates              jsonb NOT NULL DEFAULT '[]'::jsonb,
    failed_targets            text[] NOT NULL DEFAULT '{}',
    rollback_refs             text[] NOT NULL DEFAULT '{}',
    evidence_bundle_format    text NOT NULL DEFAULT '',
    evidence_bundle           text NOT NULL DEFAULT '',
    idempotency_key           text NOT NULL DEFAULT '',
    created_by                text NOT NULL DEFAULT '',
    created_at                timestamptz NOT NULL,
    updated_at                timestamptz NOT NULL
);

ALTER TABLE incident_fleet_reissuance_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_fleet_reissuance_runs FORCE ROW LEVEL SECURITY;

CREATE POLICY incident_fleet_reissuance_runs_isolation ON incident_fleet_reissuance_runs
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

CREATE INDEX IF NOT EXISTS incident_fleet_reissuance_runs_tenant_updated_idx
    ON incident_fleet_reissuance_runs (tenant_id, updated_at DESC, id);

CREATE INDEX IF NOT EXISTS incident_fleet_reissuance_runs_issuer_idx
    ON incident_fleet_reissuance_runs (tenant_id, issuer_id, updated_at DESC, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON incident_fleet_reissuance_runs TO trstctl_app;
