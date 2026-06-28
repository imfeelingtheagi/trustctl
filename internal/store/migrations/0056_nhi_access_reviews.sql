-- NHI access-review / certification campaigns (CAP-GOV-02).
--
-- These tables are read-model projections of nhi.access_review.* events. The
-- campaign header keeps bounded counts for list screens; each reviewed item is a
-- non-secret NHI/resource/entitlement fact plus reviewer decision evidence refs.
CREATE TABLE nhi_access_review_campaigns (
    tenant_id        uuid        NOT NULL,
    id               uuid        NOT NULL,
    name             text        NOT NULL,
    scope            text        NOT NULL DEFAULT 'all_nhi',
    reviewer_subject text        NOT NULL,
    requested_by     text        NOT NULL,
    status           text        NOT NULL,
    due_at           timestamptz,
    item_count       integer     NOT NULL DEFAULT 0,
    pending_count    integer     NOT NULL DEFAULT 0,
    certified_count  integer     NOT NULL DEFAULT 0,
    revoked_count    integer     NOT NULL DEFAULT 0,
    exception_count  integer     NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    completed_at     timestamptz,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT nhi_access_review_campaigns_status_chk
        CHECK (status IN ('open', 'completed')),
    CONSTRAINT nhi_access_review_campaigns_counts_chk
        CHECK (item_count >= 0 AND pending_count >= 0 AND certified_count >= 0 AND revoked_count >= 0 AND exception_count >= 0),
    CONSTRAINT nhi_access_review_campaigns_name_chk
        CHECK (name <> '' AND reviewer_subject <> '' AND requested_by <> '')
);

CREATE TABLE nhi_access_review_items (
    tenant_id              uuid        NOT NULL,
    campaign_id            uuid        NOT NULL,
    item_id                uuid        NOT NULL,
    nhi_id                 text        NOT NULL,
    nhi_kind               text        NOT NULL,
    display_name           text        NOT NULL,
    owner_ref              text        NOT NULL DEFAULT '',
    resource               text        NOT NULL,
    entitlement            text        NOT NULL,
    risk                   text        NOT NULL DEFAULT 'medium',
    evidence_refs          text[]      NOT NULL DEFAULT '{}',
    status                 text        NOT NULL DEFAULT 'pending',
    decision_by            text        NOT NULL DEFAULT '',
    decision_reason        text        NOT NULL DEFAULT '',
    decision_evidence_refs text[]      NOT NULL DEFAULT '{}',
    decided_at             timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, campaign_id, item_id),
    CONSTRAINT nhi_access_review_items_campaign_fk
        FOREIGN KEY (tenant_id, campaign_id)
        REFERENCES nhi_access_review_campaigns (tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT nhi_access_review_items_status_chk
        CHECK (status IN ('pending', 'certified', 'revoked', 'exception')),
    CONSTRAINT nhi_access_review_items_required_chk
        CHECK (nhi_id <> '' AND nhi_kind <> '' AND display_name <> '' AND resource <> '' AND entitlement <> '')
);

CREATE INDEX nhi_access_review_campaigns_tenant_id_idx
    ON nhi_access_review_campaigns (tenant_id, id);

CREATE INDEX nhi_access_review_items_campaign_status_idx
    ON nhi_access_review_items (tenant_id, campaign_id, status);

ALTER TABLE nhi_access_review_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE nhi_access_review_campaigns FORCE ROW LEVEL SECURITY;
ALTER TABLE nhi_access_review_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE nhi_access_review_items FORCE ROW LEVEL SECURITY;

CREATE POLICY nhi_access_review_campaigns_isolation ON nhi_access_review_campaigns
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE POLICY nhi_access_review_items_isolation ON nhi_access_review_items
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_access_review_campaigns TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_access_review_items TO trstctl_app;
