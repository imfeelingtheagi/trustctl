-- Agent offboarding tombstone evidence (JOURNEY-003).
--
-- The source of truth is the agent.offboarded event. These fields are projected
-- onto the existing tenant-scoped agents row so the console can keep the agent
-- visible as a tombstone instead of deleting it or requiring an audit-log lookup.
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS offboarded_at timestamptz,
    ADD COLUMN IF NOT EXISTS offboarded_by text,
    ADD COLUMN IF NOT EXISTS offboard_reason text;
