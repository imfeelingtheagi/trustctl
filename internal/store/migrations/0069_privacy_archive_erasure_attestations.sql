-- Privacy archive/backup erasure evidence (PRIVACY-003).
--
-- The source of truth is privacy.archive_erasure.attested. This projected table
-- gives privacy operators a tenant-scoped evidence ledger for pre-erasure signed
-- audit archives and backups that cannot be rewritten by hot-log pseudonymization.

CREATE TABLE privacy_archive_erasure_attestations (
    tenant_id        uuid NOT NULL,
    attestation_id   uuid NOT NULL,
    subject_ref      text NOT NULL,
    requested_by_ref text NOT NULL DEFAULT '',
    artifact_type    text NOT NULL,
    artifact_uri     text NOT NULL DEFAULT '',
    action           text NOT NULL,
    reason           text NOT NULL DEFAULT '',
    evidence_refs    text[] NOT NULL DEFAULT '{}',
    held_until       timestamptz,
    attested_at      timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, attestation_id),
    CHECK (artifact_type IN ('backup', 'signed_audit_archive')),
    CHECK (action IN ('deleted', 'legal_hold', 'cryptographic_shred'))
);

ALTER TABLE privacy_archive_erasure_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE privacy_archive_erasure_attestations FORCE ROW LEVEL SECURITY;

CREATE POLICY privacy_archive_erasure_attestations_isolation ON privacy_archive_erasure_attestations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX privacy_archive_erasure_attestations_subject_idx
    ON privacy_archive_erasure_attestations (tenant_id, subject_ref, attested_at DESC);

CREATE INDEX privacy_archive_erasure_attestations_attested_at_idx
    ON privacy_archive_erasure_attestations (tenant_id, attested_at DESC, attestation_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON privacy_archive_erasure_attestations TO trstctl_app;
