-- Notification read receipts (C8-3). Delivery state lives in outbox (AN-6);
-- operator read state is a tiny event-sourced projection of notification.read
-- events so a rebuild can reconstruct which notification rows were acknowledged.
CREATE TABLE notification_reads (
    tenant_id uuid NOT NULL,
    outbox_id bigint NOT NULL,
    read_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, outbox_id)
);

ALTER TABLE notification_reads ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_reads FORCE ROW LEVEL SECURITY;

CREATE POLICY notification_reads_isolation ON notification_reads
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_reads TO trstctl_app;
