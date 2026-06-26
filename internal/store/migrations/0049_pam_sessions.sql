-- 0049_pam_sessions.sql -- event-sourced privileged-access session read model.
--
-- pam_sessions stores session metadata and revocation handles for brokered
-- just-in-time access. It deliberately does not store the one-time PostgreSQL DSN
-- or OpenSSH certificate bytes returned to the caller; the event log and read model
-- carry only non-secret target, attestation, and expiry evidence.

CREATE TABLE IF NOT EXISTS pam_sessions (
    tenant_id       uuid NOT NULL,
    id              uuid NOT NULL,
    target_type     text NOT NULL,
    target_id       text NOT NULL,
    role            text NOT NULL,
    status          text NOT NULL,
    subject         text NOT NULL,
    requested_by    text NOT NULL,
    reason          text NOT NULL DEFAULT '',
    attestation_id  text NOT NULL DEFAULT '',
    backend_ref     text NOT NULL DEFAULT '',
    ssh_key_id      text NOT NULL DEFAULT '',
    ssh_serial      bigint NOT NULL DEFAULT 0,
    idempotency_key text NOT NULL DEFAULT '',
    audit           jsonb NOT NULL DEFAULT '{}'::jsonb,
    started_at      timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    ended_at        timestamptz,
    PRIMARY KEY (tenant_id, id)
);

ALTER TABLE pam_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY pam_sessions_isolation ON pam_sessions
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS pam_sessions_status_expiry_idx
    ON pam_sessions (tenant_id, status, expires_at, id);

CREATE INDEX IF NOT EXISTS pam_sessions_target_idx
    ON pam_sessions (tenant_id, target_type, target_id, started_at DESC, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON pam_sessions TO trstctl_app;
