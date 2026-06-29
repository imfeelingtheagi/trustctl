-- 0059_remediation_playbook_runs.sql -- served automated remediation playbook evidence.
--
-- remediation_playbook_runs is a read model projected from
-- remediation.playbook_run.recorded events. It stores operational evidence only:
-- target identifiers, action phase, scope delta JSON, outbox/connector evidence,
-- rollback references, and idempotency metadata. It must never carry provider
-- tokens, certificate/key/secret bytes, or other secret material.

CREATE TABLE IF NOT EXISTS remediation_playbook_runs (
    id                     uuid PRIMARY KEY,
    tenant_id              uuid NOT NULL,
    playbook_id            text NOT NULL,
    target_identity_id     text NOT NULL DEFAULT '',
    inventory_id           text NOT NULL DEFAULT '',
    status                 text NOT NULL,
    phase                  text NOT NULL,
    action                 text NOT NULL,
    reason                 text NOT NULL DEFAULT '',
    connector              text NOT NULL DEFAULT '',
    target                 text NOT NULL DEFAULT '',
    outbox_id              bigint,
    connector_delivery_id  uuid,
    scope_delta            jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence_refs          text[] NOT NULL DEFAULT '{}',
    rollback_refs          text[] NOT NULL DEFAULT '{}',
    idempotency_key        text NOT NULL DEFAULT '',
    created_by             text NOT NULL DEFAULT '',
    created_at             timestamptz NOT NULL,
    updated_at             timestamptz NOT NULL
);

ALTER TABLE remediation_playbook_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_playbook_runs FORCE ROW LEVEL SECURITY;

CREATE POLICY remediation_playbook_runs_isolation ON remediation_playbook_runs
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

CREATE INDEX IF NOT EXISTS remediation_playbook_runs_tenant_updated_idx
    ON remediation_playbook_runs (tenant_id, updated_at DESC, id);

CREATE INDEX IF NOT EXISTS remediation_playbook_runs_playbook_idx
    ON remediation_playbook_runs (tenant_id, playbook_id, updated_at DESC, id);

CREATE INDEX IF NOT EXISTS remediation_playbook_runs_identity_idx
    ON remediation_playbook_runs (tenant_id, target_identity_id, updated_at DESC, id)
    WHERE target_identity_id <> '';

GRANT SELECT, INSERT, UPDATE, DELETE ON remediation_playbook_runs TO trstctl_app;
