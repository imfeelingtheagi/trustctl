-- 0046_secret_store_versions.sql — sealed version history for the served secret
-- store (SEC-01 / F63). The current-value table keeps the latest sealed value for
-- fast reads; this table keeps every sealed version so operators can read a prior
-- version and perform point-in-time recovery without ever storing plaintext.

CREATE TABLE IF NOT EXISTS secret_store_versions (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              uuid NOT NULL,
    name                   text NOT NULL,
    version                integer NOT NULL,
    sealed                 bytea NOT NULL,
    written_at             timestamptz NOT NULL DEFAULT now(),
    recovered_from_version integer,
    FOREIGN KEY (tenant_id, name) REFERENCES secret_store (tenant_id, name) ON DELETE CASCADE,
    UNIQUE (tenant_id, name, version)
);

ALTER TABLE secret_store_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_store_versions FORCE  ROW LEVEL SECURITY;

CREATE POLICY secret_store_versions_isolation ON secret_store_versions
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS secret_store_versions_lookup_idx
    ON secret_store_versions (tenant_id, name, version);

CREATE INDEX IF NOT EXISTS secret_store_versions_pitr_idx
    ON secret_store_versions (tenant_id, name, written_at DESC, version DESC);

-- Existing deployments only retained the current sealed value. Seed that current
-- value as the first recoverable historical row available after this migration.
INSERT INTO secret_store_versions (tenant_id, name, version, sealed, written_at)
SELECT tenant_id, name, version, sealed, updated_at
  FROM secret_store
ON CONFLICT (tenant_id, name, version) DO NOTHING;

GRANT SELECT, INSERT, UPDATE, DELETE ON secret_store_versions TO trstctl_app;
