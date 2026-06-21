-- Non-audit PII retention evidence (PRIVACY-003). The event log remains the
-- source of truth: privacy.retention.enforced events project into this table so
-- operators can list which tenant retention runs anonymized operational PII.

CREATE TABLE privacy_retention_runs (
    tenant_id        uuid NOT NULL,
    run_id           uuid NOT NULL,
    requested_by_ref text NOT NULL DEFAULT '',
    cutoffs          jsonb NOT NULL DEFAULT '{}'::jsonb,
    counts           jsonb NOT NULL DEFAULT '{}'::jsonb,
    enforced_at      timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id)
);

ALTER TABLE privacy_retention_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE privacy_retention_runs FORCE ROW LEVEL SECURITY;

CREATE POLICY privacy_retention_runs_isolation ON privacy_retention_runs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX privacy_retention_runs_enforced_at_idx
    ON privacy_retention_runs (tenant_id, enforced_at DESC, run_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON privacy_retention_runs TO trstctl_app;

