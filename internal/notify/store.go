package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// StorePolicyResolver adapts the tenant-scoped PostgreSQL read model to the
// dispatcher PolicyResolver interface.
type StorePolicyResolver struct {
	store *store.Store
}

// NewStorePolicyResolver builds a PostgreSQL-backed notification routing
// resolver. A nil store behaves like no policy, preserving fan-out.
func NewStorePolicyResolver(s *store.Store) *StorePolicyResolver {
	return &StorePolicyResolver{store: s}
}

// ResolveNotificationPolicy loads one tenant's policy. Missing policy ids fall
// back to fan-out; datastore errors fail dispatch so the outbox retries later.
func (r *StorePolicyResolver) ResolveNotificationPolicy(ctx context.Context, tenantID, policyID string) (RoutingPolicy, bool, error) {
	if r == nil || r.store == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(policyID) == "" {
		return RoutingPolicy{}, false, nil
	}
	p, err := r.store.GetNotificationRoutingPolicy(ctx, tenantID, policyID)
	if err != nil {
		if store.IsNotFound(err) {
			return RoutingPolicy{}, false, nil
		}
		return RoutingPolicy{}, false, err
	}
	return RoutingPolicy{
		TenantID:           p.TenantID,
		ID:                 p.ID,
		ChannelsBySeverity: p.ChannelsBySeverity,
		DefaultChannels:    p.DefaultChannels,
	}, true, nil
}

// StoreThresholdDedupLedger adapts the event-sourced notification threshold
// delivery projection to the dispatcher dedup interface.
type StoreThresholdDedupLedger struct {
	store     *store.Store
	log       *events.Log
	projector *projections.Projector
}

// NewStoreThresholdDedupLedger builds a PostgreSQL/event-log-backed threshold
// delivery ledger. The event log remains the source of truth; the PostgreSQL
// table is projected for fast dispatch checks.
func NewStoreThresholdDedupLedger(s *store.Store, log *events.Log) *StoreThresholdDedupLedger {
	var projector *projections.Projector
	if s != nil {
		projector = projections.New(s)
	}
	return &StoreThresholdDedupLedger{store: s, log: log, projector: projector}
}

// HasThresholdNotificationOnChannel consults the tenant-scoped projected ledger.
func (l *StoreThresholdDedupLedger) HasThresholdNotificationOnChannel(ctx context.Context, tenantID, subject string, threshold int, channel string) (bool, error) {
	if l == nil || l.store == nil {
		return false, nil
	}
	return l.store.HasThresholdNotificationOnChannel(ctx, tenantID, subject, threshold, channel)
}

// RecordThresholdNotificationOnChannel appends and immediately projects a
// notification.threshold.delivered event.
func (l *StoreThresholdDedupLedger) RecordThresholdNotificationOnChannel(ctx context.Context, rec ThresholdNotificationDelivery) error {
	if l == nil || l.store == nil {
		return nil
	}
	if l.log == nil || l.projector == nil {
		return fmt.Errorf("notify: threshold dedup ledger requires event log and projector")
	}
	payload, err := json.Marshal(projections.NotificationThresholdDelivered{
		Subject: rec.Subject, ThresholdDays: rec.ThresholdDays, Channel: rec.Channel, SentAt: rec.SentAt,
	})
	if err != nil {
		return err
	}
	ev, err := l.log.Append(ctx, events.Event{
		Type: projections.EventNotificationThresholdDelivered, TenantID: rec.TenantID, Data: payload,
	})
	if err != nil {
		return err
	}
	return l.projector.Apply(ctx, ev)
}
