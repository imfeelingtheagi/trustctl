-- agents tenant-composite uniqueness (NEW-TENANT-1): the agents table was created
-- in 0004_core_data_model.sql with PRIMARY KEY (id) alone, and UpsertAgent used
-- ON CONFLICT (id). A same-id upsert from tenant B therefore conflicts on tenant
-- A's row and the UPDATE runs under tenant B's RLS context, hitting the FORCE'd
-- WITH CHECK (SQLSTATE 42501) — i.e. it already fails closed (no cross-tenant
-- write), but it surfaces as an error rather than a clean per-tenant upsert, and
-- the schema does not structurally scope agent ids per tenant. This mirrors the
-- ca_authorities composite-key fix in 0026 (TENANT-006).
--
-- Additive, idempotent forward migration: add UNIQUE (tenant_id, id) so the
-- upsert can target ON CONFLICT (tenant_id, id). The existing PRIMARY KEY (id)
-- is retained (ids remain globally unique today), so this only widens the
-- conflict target; on a clean database it is a no-op beyond enforcing the
-- composite uniqueness going forward.

ALTER TABLE agents
    ADD CONSTRAINT agents_tenant_id_id_key UNIQUE (tenant_id, id);
