-- Served discovery control plane (JOURNEY-001). These tables are tenant-scoped
-- projections of discovery.* events: sources/schedules describe what the tenant
-- asked the server to scan, runs track execution, and findings hold references to
-- discovered credentials. They store references and metadata only; secret values
-- and key material never belong here (AN-8).

CREATE TABLE discovery_sources (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    kind       text NOT NULL,
    name       text NOT NULL,
    config     jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE discovery_schedules (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL,
    source_id        uuid NOT NULL,
    name             text NOT NULL,
    interval_seconds integer NOT NULL CHECK (interval_seconds > 0),
    enabled          boolean NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name),
    FOREIGN KEY (tenant_id, source_id) REFERENCES discovery_sources (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE discovery_runs (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL,
    source_id    uuid NOT NULL,
    schedule_id  uuid,
    status       text NOT NULL,
    dry_run      boolean NOT NULL DEFAULT false,
    requested_by text NOT NULL DEFAULT '',
    targets      integer NOT NULL DEFAULT 0,
    discovered   integer NOT NULL DEFAULT 0,
    failed       integer NOT NULL DEFAULT 0,
    rejected     integer NOT NULL DEFAULT 0,
    error        text NOT NULL DEFAULT '',
    started_at   timestamptz,
    completed_at timestamptz,
    created_at   timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, source_id) REFERENCES discovery_sources (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, schedule_id) REFERENCES discovery_schedules (tenant_id, id)
);

CREATE TABLE discovery_findings (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL,
    run_id        uuid NOT NULL,
    source_id     uuid NOT NULL,
    kind          text NOT NULL,
    ref           text NOT NULL,
    provenance    text NOT NULL,
    fingerprint   text NOT NULL DEFAULT '',
    risk_score    integer NOT NULL DEFAULT 0,
    metadata      jsonb NOT NULL DEFAULT '{}',
    discovered_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, run_id, kind, ref, fingerprint),
    FOREIGN KEY (tenant_id, run_id) REFERENCES discovery_runs (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, source_id) REFERENCES discovery_sources (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX discovery_sources_kind_idx ON discovery_sources (tenant_id, kind, id);
CREATE INDEX discovery_schedules_source_idx ON discovery_schedules (tenant_id, source_id, id);
CREATE INDEX discovery_runs_source_created_idx ON discovery_runs (tenant_id, source_id, created_at DESC, id);
CREATE INDEX discovery_runs_status_idx ON discovery_runs (tenant_id, status, id);
CREATE INDEX discovery_findings_run_idx ON discovery_findings (tenant_id, run_id, id);
CREATE INDEX discovery_findings_kind_idx ON discovery_findings (tenant_id, kind, id);

ALTER TABLE discovery_sources   ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_sources   FORCE  ROW LEVEL SECURITY;
ALTER TABLE discovery_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_schedules FORCE  ROW LEVEL SECURITY;
ALTER TABLE discovery_runs      ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_runs      FORCE  ROW LEVEL SECURITY;
ALTER TABLE discovery_findings  ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_findings  FORCE  ROW LEVEL SECURITY;

CREATE POLICY discovery_sources_isolation ON discovery_sources
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
CREATE POLICY discovery_schedules_isolation ON discovery_schedules
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
CREATE POLICY discovery_runs_isolation ON discovery_runs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
CREATE POLICY discovery_findings_isolation ON discovery_findings
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON discovery_sources   TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON discovery_schedules TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON discovery_runs      TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON discovery_findings  TO trstctl_app;
