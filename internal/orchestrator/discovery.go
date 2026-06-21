package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const discoveryRunDestination = "discovery.run"

// UpsertDiscoverySource records a tenant discovery source as an event and returns
// the projected source row. Config is metadata/reference JSON only; API validation
// rejects inline credential values before calling this command.
func (o *Orchestrator) UpsertDiscoverySource(ctx context.Context, tenantID string, in store.DiscoverySource) (store.DiscoverySource, error) {
	id := in.ID
	if id == "" {
		id = uuid.NewString()
	}
	cfg := in.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage(`{}`)
	}
	payload, err := json.Marshal(projections.DiscoverySourceUpserted{
		ID: id, Kind: in.Kind, Name: in.Name, Config: cfg,
	})
	if err != nil {
		return store.DiscoverySource{}, err
	}
	ev, err := o.emit(ctx, projections.EventDiscoverySourceUpserted, tenantID, payload)
	if err != nil {
		return store.DiscoverySource{}, err
	}
	return store.DiscoverySource{
		ID: id, TenantID: tenantID, Kind: in.Kind, Name: in.Name, Config: cfg,
		CreatedAt: ev.Time, UpdatedAt: ev.Time,
	}, nil
}

// UpsertDiscoverySchedule records a source schedule. It refuses an absent source
// before emitting anything, so the event log never contains a dangling schedule.
func (o *Orchestrator) UpsertDiscoverySchedule(ctx context.Context, tenantID string, in store.DiscoverySchedule) (store.DiscoverySchedule, error) {
	if _, err := o.store.GetDiscoverySource(ctx, tenantID, in.SourceID); err != nil {
		return store.DiscoverySchedule{}, err
	}
	id := in.ID
	if id == "" {
		id = uuid.NewString()
	}
	payload, err := json.Marshal(projections.DiscoveryScheduleUpserted{
		ID: id, SourceID: in.SourceID, Name: in.Name, IntervalSeconds: in.IntervalSeconds, Enabled: in.Enabled,
	})
	if err != nil {
		return store.DiscoverySchedule{}, err
	}
	ev, err := o.emit(ctx, projections.EventDiscoveryScheduleUpserted, tenantID, payload)
	if err != nil {
		return store.DiscoverySchedule{}, err
	}
	return store.DiscoverySchedule{
		ID: id, TenantID: tenantID, SourceID: in.SourceID, Name: in.Name,
		IntervalSeconds: in.IntervalSeconds, Enabled: in.Enabled,
		CreatedAt: ev.Time, UpdatedAt: ev.Time,
	}, nil
}

// QueueDiscoveryRun records a queued run and its external scan intent together.
// The event is the source of truth (AN-2); the outbox row is enqueued in the same
// tenant-scoped transaction as the queued-run projection (AN-6), keyed by the event
// ID so boot reconciliation can recreate a lost outbox intent exactly once.
func (o *Orchestrator) QueueDiscoveryRun(ctx context.Context, tenantID string, in store.DiscoveryRun) (store.DiscoveryRun, error) {
	if _, err := o.store.GetDiscoverySource(ctx, tenantID, in.SourceID); err != nil {
		return store.DiscoveryRun{}, err
	}
	if in.ScheduleID != nil {
		sched, err := o.store.GetDiscoverySchedule(ctx, tenantID, *in.ScheduleID)
		if err != nil {
			return store.DiscoveryRun{}, err
		}
		if sched.SourceID != in.SourceID {
			return store.DiscoveryRun{}, fmt.Errorf("orchestrator: discovery schedule %s belongs to source %s, not %s", sched.ID, sched.SourceID, in.SourceID)
		}
	}
	requestedBy := in.RequestedBy
	if requestedBy == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			requestedBy = actor.Subject
		}
	}
	id := in.ID
	if id == "" {
		id = uuid.NewString()
	}
	payload, err := json.Marshal(projections.DiscoveryRunQueued{
		ID: id, SourceID: in.SourceID, ScheduleID: in.ScheduleID, DryRun: in.DryRun, RequestedBy: requestedBy,
	})
	if err != nil {
		return store.DiscoveryRun{}, err
	}
	ev, err := o.log.Append(ctx, events.Event{Type: projections.EventDiscoveryRunQueued, TenantID: tenantID, Data: payload})
	if err != nil {
		return store.DiscoveryRun{}, err
	}
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		_, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID:       tenantID,
			Destination:    discoveryRunDestination,
			IdempotencyKey: ev.ID,
			Payload:        payload,
		})
		return err
	}); err != nil {
		return store.DiscoveryRun{}, err
	}
	return store.DiscoveryRun{
		ID: id, TenantID: tenantID, SourceID: in.SourceID, ScheduleID: in.ScheduleID,
		Status: "queued", DryRun: in.DryRun, RequestedBy: requestedBy, CreatedAt: ev.Time,
	}, nil
}

// StartDiscoveryRun records that an outbox worker began executing a run.
func (o *Orchestrator) StartDiscoveryRun(ctx context.Context, tenantID, runID string) error {
	payload, err := json.Marshal(projections.DiscoveryRunStarted{ID: runID})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventDiscoveryRunStarted, tenantID, payload)
	return err
}

// RecordDiscoveryFinding records one metadata-only finding for a run.
func (o *Orchestrator) RecordDiscoveryFinding(ctx context.Context, tenantID string, in store.DiscoveryFinding) (store.DiscoveryFinding, error) {
	id := in.ID
	if id == "" {
		id = uuid.NewString()
	}
	meta := in.Metadata
	if len(meta) == 0 {
		meta = json.RawMessage(`{}`)
	}
	payload, err := json.Marshal(projections.DiscoveryFindingRecorded{
		ID: id, RunID: in.RunID, SourceID: in.SourceID, Kind: in.Kind, Ref: in.Ref,
		Provenance: in.Provenance, Fingerprint: in.Fingerprint, RiskScore: in.RiskScore,
		Metadata: meta,
	})
	if err != nil {
		return store.DiscoveryFinding{}, err
	}
	ev, err := o.emit(ctx, projections.EventDiscoveryFindingRecorded, tenantID, payload)
	if err != nil {
		return store.DiscoveryFinding{}, err
	}
	out := in
	out.ID, out.TenantID, out.Metadata, out.DiscoveredAt = id, tenantID, meta, ev.Time
	return out, nil
}

// CompleteDiscoveryRun records terminal run counts. Status is usually
// "succeeded" or "failed"; partial scans use "partial".
func (o *Orchestrator) CompleteDiscoveryRun(ctx context.Context, tenantID string, in store.DiscoveryRun) error {
	payload, err := json.Marshal(projections.DiscoveryRunCompleted{
		ID: in.ID, Status: in.Status, Targets: in.Targets, Discovered: in.Discovered,
		Failed: in.Failed, Rejected: in.Rejected, Error: in.Error,
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventDiscoveryRunCompleted, tenantID, payload)
	return err
}
