-- Notification routing policies (C8-1). This is tenant-scoped control-plane
-- configuration for the outbox dispatcher: severity tier -> channel names. It
-- stores channel names and metadata only; channel secrets remain in the existing
-- deploy-time notifier configuration.

CREATE TABLE notification_routing_policies (
    id                   uuid PRIMARY KEY,
    tenant_id            uuid NOT NULL,
    name                 text NOT NULL,
    channels_by_severity jsonb NOT NULL DEFAULT '{}',
    default_channels     jsonb NOT NULL DEFAULT '[]',
    created_at           timestamptz NOT NULL,
    updated_at           timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE INDEX notification_routing_policies_tenant_name_idx
    ON notification_routing_policies (tenant_id, name);

ALTER TABLE notification_routing_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_routing_policies FORCE ROW LEVEL SECURITY;

CREATE POLICY notification_routing_policies_isolation ON notification_routing_policies
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_routing_policies TO trstctl_app;
