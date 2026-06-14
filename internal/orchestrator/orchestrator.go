package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trustctl.io/trustctl/internal/events"
	"trustctl.io/trustctl/internal/projections"
	"trustctl.io/trustctl/internal/store"
)

// Orchestrator is the command (write) side of the event-sourced spine. It drives
// an identity through its lifecycle state machine and records every served
// domain mutation (owners, issuers, identities, certificates) as an event (AN-2,
// the source of truth). For a lifecycle transition it atomically projects the
// read-model status change and enqueues any outbox side effect (AN-6) in one
// transaction. The read model is written only by the projector, so the state and
// history are reconstructable purely from the event log.
type Orchestrator struct {
	log    *events.Log
	store  *store.Store
	outbox *Outbox
	proj   *projections.Projector
}

// NewOrchestrator returns an Orchestrator over the event log, read store, and
// outbox. It builds its own projector so a mutation it records is projected with
// the same logic a rebuild uses.
func NewOrchestrator(log *events.Log, st *store.Store, ob *Outbox) *Orchestrator {
	return &Orchestrator{log: log, store: st, outbox: ob, proj: projections.New(st)}
}

// Transition moves an identity from its current state to "to". It rejects an
// invalid transition with a *TransitionError before any effect. For a valid
// transition it appends the lifecycle event, then in a single tenant-scoped
// transaction updates the identity's status and enqueues any outbox side effect,
// so the external call is recorded with the state change (AN-6).
func (o *Orchestrator) Transition(ctx context.Context, tenantID, identityID string, to State, reason string) error {
	ident, err := o.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return fmt.Errorf("orchestrator: load identity %s: %w", identityID, err)
	}
	from := State(ident.Status)

	evType, ok := EventTypeFor(from, to)
	if !ok {
		return &TransitionError{IdentityID: identityID, From: from, To: to}
	}

	payload, err := json.Marshal(transitionPayload{IdentityID: identityID, From: from, To: to, Reason: reason})
	if err != nil {
		return err
	}
	ev, err := o.log.Append(ctx, events.Event{Type: evType, TenantID: tenantID, Data: payload})
	if err != nil {
		return err
	}

	return o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Project the status change through the projector (the sole read-model
		// writer, AN-2) in the same transaction as the outbox enqueue (AN-6).
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		if dest, ok := sideEffectFor(from, to); ok {
			if _, err := o.outbox.Enqueue(ctx, tx, Entry{
				TenantID:       tenantID,
				Destination:    dest,
				IdempotencyKey: ev.ID,
				Payload:        payload,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// State returns an identity's current lifecycle state. It reads the last
// projected transition for the identity in its tenant context — a single
// indexed, tenant-scoped query (SPINE-001), not a scan of the cross-tenant event
// log. The transitions are a projection of the log (AN-2), which stays the source
// of truth (a Rebuild re-derives them). An identity with no transitions is
// StateRequested.
func (o *Orchestrator) State(ctx context.Context, tenantID, identityID string) (State, error) {
	hist, err := o.History(ctx, tenantID, identityID)
	if err != nil {
		return "", err
	}
	state := StateRequested
	if n := len(hist); n > 0 {
		state = hist[n-1].To
	}
	return state, nil
}

// History returns an identity's transitions in order, read from the
// identity_transitions projection in the identity's tenant context (SPINE-001).
// The work is bounded by this identity's transition count and confined to its
// tenant by row-level security (AN-1) — it never scans another tenant's events,
// and its cost does not grow with the total log size. The transitions are a
// projection of the event log, which remains the source of truth (AN-2): a
// projection Rebuild re-derives them from the log.
func (o *Orchestrator) History(ctx context.Context, tenantID, identityID string) ([]Transition, error) {
	var rows []store.IdentityTransition
	err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		got, err := o.store.ListIdentityTransitions(ctx, tx, tenantID, identityID)
		if err != nil {
			return err
		}
		rows = got
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("orchestrator: load identity %s history: %w", identityID, err)
	}
	hist := make([]Transition, 0, len(rows))
	for _, r := range rows {
		hist = append(hist, Transition{
			From: State(r.FromState), To: State(r.ToState), Event: r.EventType,
			Reason: r.Reason, Sequence: r.Seq, At: r.OccurredAt,
		})
	}
	return hist, nil
}
