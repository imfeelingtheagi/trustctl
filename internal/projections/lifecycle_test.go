package projections_test

import (
	"context"
	"errors"
	"testing"

	"trustctl.io/trustctl/internal/events"
	"trustctl.io/trustctl/internal/orchestrator"
	"trustctl.io/trustctl/internal/store"
)

// seedIdentity creates an owner and a freshly-requested identity so the
// orchestrator has something to drive through its lifecycle.
func seedIdentity(t *testing.T, s *store.Store, tenantID string) {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertOwner(ctx, store.Owner{ID: idOwner, TenantID: tenantID, Kind: store.OwnerService, Name: "svc"}); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if err := s.UpsertIdentity(ctx, store.Identity{
		ID: idIdentity, TenantID: tenantID, Kind: store.KindX509Certificate,
		Name: "svc.acme.test", OwnerID: idOwner, Status: string(orchestrator.StateRequested),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
}

// identityEvents replays the log and returns the lifecycle event types for the
// identity, in order.
func identityEvents(t *testing.T, log *events.Log, tenantID, identityID string) []string {
	t.Helper()
	var types []string
	if err := log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.TenantID == tenantID && len(e.Type) > len("identity.") && e.Type[:len("identity.")] == "identity." {
			types = append(types, e.Type)
		}
		return nil
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	return types
}

// TestLifecycleValidTransitionsEmitEvents is the acceptance: each valid
// transition emits the right event, and the read model tracks the state.
func TestLifecycleValidTransitionsEmitEvents(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	seedIdentity(t, s, tenantA)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))

	for _, to := range []orchestrator.State{
		orchestrator.StateIssued, orchestrator.StateDeployed, orchestrator.StateRenewing, orchestrator.StateDeployed,
	} {
		if err := orch.Transition(ctx, tenantA, idIdentity, to, ""); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}

	got := identityEvents(t, log, tenantA, idIdentity)
	want := []string{"identity.issued", "identity.deployed", "identity.renewing", "identity.renewed"}
	if len(got) != len(want) {
		t.Fatalf("emitted events = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d = %q, want %q", i, got[i], want[i])
		}
	}

	// The read model and the log-reconstructed state agree on the final state.
	st, err := orch.State(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if st != orchestrator.StateDeployed {
		t.Errorf("reconstructed state = %s, want deployed", st)
	}
	ident, err := s.GetIdentity(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if ident.Status != string(orchestrator.StateDeployed) {
		t.Errorf("read-model status = %s, want deployed", ident.Status)
	}
}

// TestLifecycleInvalidTransitionRejected is the acceptance: an illegal transition
// is rejected with a structured error and has no effect.
func TestLifecycleInvalidTransitionRejected(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	seedIdentity(t, s, tenantA)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))

	// requested -> deployed skips issuance and must be rejected.
	err := orch.Transition(ctx, tenantA, idIdentity, orchestrator.StateDeployed, "")
	if !errors.Is(err, orchestrator.ErrInvalidTransition) {
		t.Fatalf("error = %v, want ErrInvalidTransition", err)
	}
	var te *orchestrator.TransitionError
	if !errors.As(err, &te) {
		t.Fatalf("error = %v, want *TransitionError", err)
	}
	if te.From != orchestrator.StateRequested || te.To != orchestrator.StateDeployed || te.IdentityID != idIdentity {
		t.Errorf("transition error = %+v, want requested->deployed for %s", te, idIdentity)
	}

	// No event was emitted and the status is unchanged.
	if got := identityEvents(t, log, tenantA, idIdentity); len(got) != 0 {
		t.Errorf("a rejected transition emitted events: %v", got)
	}
	ident, err := s.GetIdentity(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if ident.Status != string(orchestrator.StateRequested) {
		t.Errorf("status = %s after a rejected transition, want requested", ident.Status)
	}

	// A terminal state rejects all further transitions.
	for _, to := range []orchestrator.State{orchestrator.StateIssued, orchestrator.StateRevoked, orchestrator.StateRetired} {
		if err := orch.Transition(ctx, tenantA, idIdentity, to, ""); err != nil {
			t.Fatalf("driving to retired (%s): %v", to, err)
		}
	}
	if err := orch.Transition(ctx, tenantA, idIdentity, orchestrator.StateIssued, ""); !errors.Is(err, orchestrator.ErrInvalidTransition) {
		t.Errorf("transition out of retired = %v, want ErrInvalidTransition", err)
	}
}

// TestLifecycleReconstructableFromLog is the acceptance: an identity's transition
// history and current state can be rebuilt purely from the event log.
func TestLifecycleReconstructableFromLog(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	seedIdentity(t, s, tenantA)
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))

	steps := []orchestrator.State{
		orchestrator.StateIssued, orchestrator.StateDeployed, orchestrator.StateRevoked, orchestrator.StateRetired,
	}
	for _, to := range steps {
		if err := orch.Transition(ctx, tenantA, idIdentity, to, "test"); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}

	// A fresh orchestrator over the same log reconstructs the same history/state,
	// proving the lifecycle is derived from the log and not in-memory.
	fresh := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	hist, err := fresh.History(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	wantFrom := []orchestrator.State{orchestrator.StateRequested, orchestrator.StateIssued, orchestrator.StateDeployed, orchestrator.StateRevoked}
	wantTo := steps
	if len(hist) != len(wantTo) {
		t.Fatalf("history has %d transitions, want %d (%v)", len(hist), len(wantTo), hist)
	}
	for i := range hist {
		if hist[i].From != wantFrom[i] || hist[i].To != wantTo[i] {
			t.Errorf("transition %d = %s->%s, want %s->%s", i, hist[i].From, hist[i].To, wantFrom[i], wantTo[i])
		}
		if i > 0 && hist[i].Sequence <= hist[i-1].Sequence {
			t.Errorf("transition %d sequence %d not increasing", i, hist[i].Sequence)
		}
	}
	st, err := fresh.State(ctx, tenantA, idIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if st != orchestrator.StateRetired {
		t.Errorf("reconstructed state = %s, want retired", st)
	}
}

// TestLifecycleOutboxSideEffects is the acceptance for outbox-driven side
// effects: transitions that require an external call enqueue an outbox entry in
// the same transaction as the state change, keyed by the emitting event.
func TestLifecycleOutboxSideEffects(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	seedIdentity(t, s, tenantA)
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	for _, to := range []orchestrator.State{orchestrator.StateIssued, orchestrator.StateDeployed, orchestrator.StateRevoked} {
		if err := orch.Transition(ctx, tenantA, idIdentity, to, ""); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}

	pending, err := ob.Pending(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	gotDest := map[string]bool{}
	for _, r := range pending {
		gotDest[r.Destination] = true
		if r.IdempotencyKey == "" {
			t.Errorf("outbox entry %d has no idempotency key (should be the emitting event id)", r.ID)
		}
	}
	for _, want := range []string{"ca.issue", "connector.deploy", "revocation.publish"} {
		if !gotDest[want] {
			t.Errorf("missing outbox side effect %q; got destinations %v", want, gotDest)
		}
	}
}
