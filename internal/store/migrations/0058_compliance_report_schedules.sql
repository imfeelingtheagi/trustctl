-- 0058_compliance_report_schedules.sql -- CAP-OBS-02 scheduled compliance/inventory reports.
--
-- compliance_report_schedules is a tenant-scoped read model projected from
-- compliance.report_schedule.upserted events. It stores reporting metadata only:
-- framework, report type, cadence, non-secret delivery/reference labels, and the
-- next due time. It never stores generated report bytes, channel credentials, or
-- secret webhook/email material.

CREATE TABLE IF NOT EXISTS compliance_report_schedules (
    id               uuid        NOT NULL,
    tenant_id        uuid        NOT NULL,
    framework        text        NOT NULL,
    name             text        NOT NULL,
    report_type      text        NOT NULL,
    interval_seconds integer     NOT NULL,
    enabled          boolean     NOT NULL DEFAULT true,
    delivery         text        NOT NULL DEFAULT 'audit_export',
    recipient_ref    text        NOT NULL DEFAULT '',
    next_run_at      timestamptz NOT NULL,
    created_at       timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL,
    CONSTRAINT compliance_report_schedules_required_chk
        CHECK (framework <> '' AND name <> '' AND report_type <> '' AND delivery <> ''),
    CONSTRAINT compliance_report_schedules_interval_chk
        CHECK (interval_seconds > 0),
    PRIMARY KEY (tenant_id, id)
);

ALTER TABLE compliance_report_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_report_schedules FORCE ROW LEVEL SECURITY;

CREATE POLICY compliance_report_schedules_isolation ON compliance_report_schedules
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

CREATE UNIQUE INDEX IF NOT EXISTS compliance_report_schedules_tenant_name_idx
    ON compliance_report_schedules (tenant_id, name);

CREATE INDEX IF NOT EXISTS compliance_report_schedules_tenant_next_run_idx
    ON compliance_report_schedules (tenant_id, enabled, next_run_at, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_report_schedules TO trstctl_app;
