package server

// Served wiring for the BYOK/HSM managed-key lifecycle (CRYPTO-005 / EXC-CRYPTO-01).
// When Deps.ManagedKeyCustody is set (a configured KMS/HSM RemoteKeyLifecycle
// backend), the running control plane serves the /api/v1/managed-keys/* surface: the
// service emits its lifecycle events to the event log (AN-2), records mutations
// through the orchestrator's durable idempotency recorder (AN-5), and gates the
// destructive transitions (rotate/revoke/zeroize) on the SAME store-backed
// distinct-approver dual control the issuance gate uses. The private key stays in the
// provider; nothing here touches private material.

import (
	"context"
	"encoding/json"

	"trstctl.com/trstctl/internal/crypto/byok"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/managedkeys"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// eventLogSink adapts the event log to byok.EventSink so the served managed-key
// lifecycle records its key-material-free transitions on the AN-2 spine, exactly
// like the in-process byok path. A dropped append fails the operation (the sink
// contract): a lost event would make the key history unrebuildable.
type eventLogSink struct{ log *events.Log }

func (s eventLogSink) Emit(ctx context.Context, e byok.LifecycleEvent) error {
	payload, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = s.log.Append(ctx, events.Event{Type: e.Type, TenantID: e.TenantID, Data: payload})
	return err
}

// orchestratorIdempotency adapts the orchestrator's durable idempotency recorder
// (AN-5) to the managedkeys.Idempotency interface, JSON-encoding the Result so a
// replay of the same Idempotency-Key returns the original outcome without re-running
// the provider operation.
type orchestratorIdempotency struct{ idem *orchestrator.Idempotency }

func (o orchestratorIdempotency) Do(ctx context.Context, tenantID, key string, fn func(context.Context) (managedkeys.Result, error)) (managedkeys.Result, error) {
	raw, err := o.idem.Do(ctx, tenantID, key, func(ctx context.Context) ([]byte, error) {
		res, ferr := fn(ctx)
		if ferr != nil {
			return nil, ferr
		}
		return json.Marshal(res)
	})
	if err != nil {
		return managedkeys.Result{}, err
	}
	var res managedkeys.Result
	if err := json.Unmarshal(raw, &res); err != nil {
		return managedkeys.Result{}, err
	}
	return res, nil
}

// managedKeyApprovalGate adapts the store-backed distinct-approver checker (the same
// machinery the issuance gate uses) to managedkeys.ApprovalGate, so a managed-key
// rotate/revoke/zeroize requires a recorded approval by a principal distinct from the
// requester before the provider is ever called (dual control, AN-1 tenant-scoped).
type managedKeyApprovalGate struct {
	store    *store.Store
	required int
}

func (g managedKeyApprovalGate) IsApproved(ctx context.Context, tenantID, keyID, action, requester string) (bool, string) {
	return storeApprovalChecker(g).IsApproved(ctx, tenantID, keyID, action, requester)
}

// buildManagedKeyService assembles the served managed-key lifecycle from Deps. It
// returns nil when no custody backend is configured (the surface stays off and the
// routes fail closed). When dual control is enabled platform-wide (Deps.RequireApproval),
// destructive managed-key transitions inherit it.
func buildManagedKeyService(d Deps, idem *orchestrator.Idempotency) (*managedkeys.Service, error) {
	if d.ManagedKeyCustody == nil {
		return nil, nil
	}
	cfg := managedkeys.Config{
		Backend: d.ManagedKeyCustody,
		Sink:    eventLogSink{log: d.Log},
		Idem:    orchestratorIdempotency{idem: idem},
	}
	if d.RequireApproval {
		required := d.RequiredApprovals
		if required <= 0 {
			required = defaultRequiredApprovals
		}
		cfg.Gate = managedKeyApprovalGate{store: d.Store, required: required}
	}
	return managedkeys.New(cfg)
}
