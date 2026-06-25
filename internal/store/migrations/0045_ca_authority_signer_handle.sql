-- migrate: no-transaction
-- Signer-backed CA hierarchy handles (CLM-02 / F48).
--
-- The CA private key stays inside the isolated signer process (AN-4). The control
-- plane stores only the non-secret signer handle next to the public CA certificate,
-- so a restarted server can re-bind to the signer-held key without ever importing
-- private material.

ALTER TABLE ca_authorities
    ADD COLUMN signer_handle text;

-- online-safe: CONCURRENTLY avoids blocking writes on the populated CA authority
-- table; IF NOT EXISTS makes this no-transaction migration retry-safe before the
-- schema_migrations row is written.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS ca_authorities_tenant_signer_handle_idx
    ON ca_authorities (tenant_id, signer_handle)
    WHERE signer_handle IS NOT NULL AND signer_handle <> '';
