package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"certctl.io/certctl/internal/events"
	"certctl.io/certctl/internal/store"
)

// eventPrefix marks the lifecycle events the orchestrator emits and replays.
const eventPrefix = "identity."

// Orchestrator drives an identity through its lifecycle state machine. Each valid
// transition emits an event (AN-2, the source of truth), then atomically updates
// the read-model status and enqueues any outbox side effect (AN-6) in one
// transaction. An identity's state and history are reconstructable purely from
// the event log.
type Orchestrator struct {
	log    *events.Log
	store  *store.Store
	outbox *Outbox
}

// NewOrchestrator returns an Orchestrator over the event log, read store, and
// outbox.
func NewOrchestrator(log *events.Log, st *store.Store, ob *Outbox) *Orchestrator {
	return &Orchestrator{log: log, store: st, outbox: ob}
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
		if err := o.store.SetIdentityStatusTx(ctx, tx, tenantID, identityID, string(to)); err != nil {
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

// State returns an identity's current lifecycle state, reconstructed from the
// event log. An identity with no lifecycle events is StateRequested.
func (o *Orchestrator) State(ctx context.Context, tenantID, identityID string) (State, error) {
	hist, err := o.History(ctx, tenantID, identityID)
	if err != nil {
		return "", err
	}
	state := StateRequested
	for _, t := range hist {
		state = t.To
	}
	return state, nil
}

// History returns an identity's transitions in order, reconstructed from the
// event log (AN-2: the log is the source of truth).
func (o *Orchestrator) History(ctx context.Context, tenantID, identityID string) ([]Transition, error) {
	var hist []Transition
	err := o.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID != tenantID || !strings.HasPrefix(e.Type, eventPrefix) {
			return nil
		}
		var p transitionPayload
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return fmt.Errorf("orchestrator: decode event %s: %w", e.ID, err)
		}
		if p.IdentityID != identityID {
			return nil
		}
		hist = append(hist, Transition{
			From: p.From, To: p.To, Event: e.Type, Reason: p.Reason, Sequence: e.Sequence, At: e.Time,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return hist, nil
}
