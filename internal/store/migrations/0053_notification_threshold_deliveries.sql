-- Notification threshold delivery ledger (C8-2). This table is the tenant-scoped
-- projection of notification.threshold.delivered events. It lets dispatch skip a
-- duplicate expiry threshold alert per (subject, threshold, channel) without
-- treating one channel's success as another channel's success.

CREATE TABLE notification_threshold_deliveries (
    tenant_id      uuid NOT NULL,
    subject        text NOT NULL,
    threshold_days integer NOT NULL,
    channel        text NOT NULL,
    first_sent_at  timestamptz NOT NULL,
    last_sent_at   timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, subject, threshold_days, channel)
);

CREATE INDEX notification_threshold_deliveries_subject_idx
    ON notification_threshold_deliveries (tenant_id, subject, threshold_days);

ALTER TABLE notification_threshold_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_threshold_deliveries FORCE ROW LEVEL SECURITY;

CREATE POLICY notification_threshold_deliveries_isolation ON notification_threshold_deliveries
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_threshold_deliveries TO trstctl_app;
