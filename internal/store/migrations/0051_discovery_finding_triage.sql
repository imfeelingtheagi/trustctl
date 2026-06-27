-- migrate: no-transaction
-- Discovery finding triage lifecycle (C7-1). Findings are immutable evidence;
-- these columns are the tenant-scoped read-model projection of
-- discovery.finding.triage_changed events.

ALTER TABLE discovery_findings
    ADD COLUMN IF NOT EXISTS triage_status text NOT NULL DEFAULT 'unmanaged';

ALTER TABLE discovery_findings
    ADD COLUMN IF NOT EXISTS managed_identity_id uuid;

ALTER TABLE discovery_findings
    ADD COLUMN IF NOT EXISTS triage_actor text NOT NULL DEFAULT '';

ALTER TABLE discovery_findings
    ADD COLUMN IF NOT EXISTS triage_reason text NOT NULL DEFAULT '';

ALTER TABLE discovery_findings
    ADD COLUMN IF NOT EXISTS triaged_at timestamptz;

-- online-safe: CONCURRENTLY avoids blocking writes on the live discovery_findings
-- table; IF NOT EXISTS makes this no-transaction migration retry-safe before the
-- ledger row is recorded.
CREATE INDEX CONCURRENTLY IF NOT EXISTS discovery_findings_triage_status_idx
    ON discovery_findings (tenant_id, triage_status, id);
