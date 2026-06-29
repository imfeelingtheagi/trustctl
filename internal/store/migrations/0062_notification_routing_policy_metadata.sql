-- Operator-authored notification routing metadata (DESIGN-003). The original
-- routing table already stores the severity-to-channel matrix used by the
-- outbox dispatcher. These additive columns let the served console persist the
-- policy owner and digest cadence preview without storing channel secrets.

ALTER TABLE notification_routing_policies
    ADD COLUMN IF NOT EXISTS owner_ref text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS owner_email text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS digest_interval_seconds integer NOT NULL DEFAULT 86400,
    ADD COLUMN IF NOT EXISTS digest_timezone text NOT NULL DEFAULT 'UTC';
