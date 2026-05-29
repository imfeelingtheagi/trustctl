package projections

import (
	"context"
	"encoding/json"
	"fmt"

	"certctl.io/certctl/internal/events"
	"certctl.io/certctl/internal/store"
)

// Projector derives PostgreSQL read models from the event stream (AN-2). The
// read model is always a projection of the log; nothing writes derived state
// except through here.
type Projector struct {
	store *store.Store
}

// New returns a Projector that writes into s.
func New(s *store.Store) *Projector { return &Projector{store: s} }

type tenantRegistered struct {
	Name string `json:"name"`
}

// apply applies a single event to the read model. Unknown event types are
// ignored, so projections are forward-compatible with new event types.
func (p *Projector) apply(ctx context.Context, e events.Event) error {
	switch e.Type {
	case "tenant.registered":
		var payload tenantRegistered
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		return p.store.UpsertTenant(ctx, store.Tenant{
			TenantID: e.TenantID,
			Name:     payload.Name,
			EventSeq: e.Sequence,
		})
	default:
		return nil
	}
}

// Project replays the log from the beginning and applies every event to the
// read model.
func (p *Projector) Project(ctx context.Context, log *events.Log) error {
	return log.Replay(ctx, 0, func(e events.Event) error {
		return p.apply(ctx, e)
	})
}

// Rebuild discards the read model and re-derives it from the whole log,
// reproducing the same state (AN-2).
func (p *Projector) Rebuild(ctx context.Context, log *events.Log) error {
	if err := p.store.TruncateTenants(ctx); err != nil {
		return fmt.Errorf("projections: truncate: %w", err)
	}
	return p.Project(ctx, log)
}
