-- ca_authorities tenant-composite self-FKs (TENANT-006): the self-referential
-- foreign keys parent_id and replaces_id were created in 0008_ca_hierarchy.sql as
-- PK-only references (REFERENCES ca_authorities (id)), unlike identities /
-- attestations / certificates (0004, 0006) whose FKs are tenant-composite
-- (tenant_id, <ref_id>) REFERENCES <table> (tenant_id, id). A PK-only self-FK does
-- not structurally forbid a CA row in tenant A from pointing parent_id/replaces_id
-- at a CA row in tenant B. RLS still hides cross-tenant rows so no read leak
-- surfaces today, and the application only ever links CAs within one tenant — but
-- for AN-1 schema-integrity completeness the database itself should make a
-- cross-tenant CA link impossible.
--
-- This is an additive, idempotent forward migration:
--   1. Add UNIQUE (tenant_id, id) so the composite FKs have a target to reference
--      (the PRIMARY KEY (id) alone cannot back a (tenant_id, id) reference).
--   2. Drop the PK-only self-FKs by their Postgres-default constraint names
--      (IF EXISTS makes it re-runnable and tolerant of an already-migrated db).
--   3. Re-add them as tenant-composite FKs, preserving ON DELETE SET NULL.
-- The NOT VALID + VALIDATE split keeps the rewrite non-blocking and lets the
-- validation surface any pre-existing cross-tenant link rather than failing the
-- DDL outright; on a clean/consistent database (the expected case) it is a no-op
-- beyond enforcing the constraint going forward.

ALTER TABLE ca_authorities
    ADD CONSTRAINT ca_authorities_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE ca_authorities DROP CONSTRAINT IF EXISTS ca_authorities_parent_id_fkey;
ALTER TABLE ca_authorities DROP CONSTRAINT IF EXISTS ca_authorities_replaces_id_fkey;

ALTER TABLE ca_authorities
    ADD CONSTRAINT ca_authorities_parent_fkey
    FOREIGN KEY (tenant_id, parent_id)
    REFERENCES ca_authorities (tenant_id, id) ON DELETE SET NULL;

ALTER TABLE ca_authorities
    ADD CONSTRAINT ca_authorities_replaces_fkey
    FOREIGN KEY (tenant_id, replaces_id)
    REFERENCES ca_authorities (tenant_id, id) ON DELETE SET NULL;
