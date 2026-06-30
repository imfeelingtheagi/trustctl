-- MDM SCEP enrollment policy read model (TRACE-004 / F56).
-- Policy changes are projected from mdm.scep_policy.* events. Provider tokens,
-- shared secrets, and raw challenge values are not stored here; operators provide
-- reference names and runtime SCEP challenge validation remains fail-closed.

CREATE TABLE mdm_scep_policies (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    provider text NOT NULL,
    scep_profile text NOT NULL DEFAULT '',
    scep_endpoint text NOT NULL DEFAULT '',
    expected_audience text NOT NULL DEFAULT '',
    challenge_mode text NOT NULL DEFAULT 'intune-jws',
    trust_anchor_refs jsonb NOT NULL DEFAULT '{}'::jsonb,
    profile_guidance jsonb NOT NULL DEFAULT '{}'::jsonb,
    enabled boolean NOT NULL DEFAULT true,
    rotation_version integer NOT NULL DEFAULT 1,
    last_rotated_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id)
);

CREATE UNIQUE INDEX mdm_scep_policies_tenant_name_idx
    ON mdm_scep_policies (tenant_id, lower(name));

CREATE INDEX mdm_scep_policies_provider_idx
    ON mdm_scep_policies (tenant_id, provider, id);

ALTER TABLE mdm_scep_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_scep_policies FORCE  ROW LEVEL SECURITY;

CREATE POLICY mdm_scep_policies_isolation ON mdm_scep_policies
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON mdm_scep_policies TO trstctl_app;
