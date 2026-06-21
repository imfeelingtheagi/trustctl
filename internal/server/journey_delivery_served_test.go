package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// TestServedDeployAndRotationPublishReceipts is the JOURNEY-002 proof: the served
// issue->deploy->rotate path exposes connector delivery receipts and rotation-run
// status from real outbox work. On the pre-fix tree the connector delivery and
// lifecycle endpoints are 404s, deploy acks were invisible, and renewals did not
// queue a post-rotation connector.deploy receipt.
func TestServedDeployAndRotationPublishReceipts(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write",
		"identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "lifecycle:read",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload",
		"name": "journey-002-owner",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode owner: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind":     "x509_certificate",
		"name":     "journey-002.served.test",
		"owner_id": owner.ID,
		"attributes": map[string]any{
			"connector": "nginx",
			"target":    "edge-1",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	transition := func(to, reason string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
			"to":     to,
			"reason": reason,
		})
		if status != http.StatusOK {
			t.Fatalf("transition %s: status %d body %s", to, status, body)
		}
	}
	transition("issued", "journey-002 initial issue")
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue: %v", err)
	}
	transition("deployed", "journey-002 deploy")
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain deploy: %v", err)
	}

	first := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	if len(first.Items) != 1 {
		pending, perr := h.srv.outbox.Pending(t.Context(), h.tenant)
		if perr != nil {
			t.Fatalf("connector receipts after deploy = %d, want 1 (%s); pending outbox error: %v", len(first.Items), first.Raw, perr)
		}
		t.Fatalf("connector receipts after deploy = %d, want 1 (%s); pending outbox: %+v", len(first.Items), first.Raw, pending)
	}
	if got := first.Items[0]; got.Status != "unrouted" || got.Connector != "nginx" || got.Target != "edge-1" || got.Fingerprint == "" {
		t.Fatalf("bad deploy receipt: %+v", got)
	}

	queued, err := h.srv.RunLifecycleOnce(t.Context())
	if err != nil {
		t.Fatalf("run lifecycle scheduler: %v", err)
	}
	if queued != 1 {
		t.Fatalf("scheduled renewals = %d, want 1", queued)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain renewal: %v", err)
	}

	runs := rotationRunsForIdentity(t, h, tok, ident.ID)
	if len(runs.Items) != 1 {
		t.Fatalf("rotation runs = %d, want 1 (%s)", len(runs.Items), runs.Raw)
	}
	run := runs.Items[0]
	if run.Status != "succeeded" || run.Trigger != "scheduler" || run.PredecessorFingerprint == "" || run.SuccessorFingerprint == "" || run.RollbackRef == "" {
		t.Fatalf("bad rotation run: %+v", run)
	}

	afterRenew := connectorDeliveriesForIdentity(t, h, tok, ident.ID)
	if len(afterRenew.Items) != 2 {
		t.Fatalf("connector receipts after renewal = %d, want 2 (%s)", len(afterRenew.Items), afterRenew.Raw)
	}
	foundSuccessorReceipt := false
	for _, got := range afterRenew.Items {
		if got.Status != "unrouted" || got.Fingerprint == "" {
			t.Fatalf("bad deploy receipt after renewal: %+v", got)
		}
		if got.Fingerprint == run.SuccessorFingerprint {
			foundSuccessorReceipt = true
		}
	}
	if !foundSuccessorReceipt {
		t.Fatalf("no connector delivery receipt references renewal successor %s: %+v", run.SuccessorFingerprint, afterRenew.Items)
	}

	for _, eventType := range []string{"connector.delivery.recorded", "lifecycle.rotation.recorded"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event", eventType)
		}
	}
}

type connectorDeliveryList struct {
	Raw   []byte
	Items []struct {
		ID          string `json:"id"`
		IdentityID  string `json:"identity_id"`
		Connector   string `json:"connector"`
		Target      string `json:"target"`
		Fingerprint string `json:"fingerprint"`
		Status      string `json:"status"`
		Reason      string `json:"reason"`
		Detail      string `json:"detail"`
	} `json:"items"`
}

type rotationRunList struct {
	Raw   []byte
	Items []struct {
		ID                     string `json:"id"`
		IdentityID             string `json:"identity_id"`
		Status                 string `json:"status"`
		Trigger                string `json:"trigger"`
		PredecessorFingerprint string `json:"predecessor_fingerprint"`
		SuccessorFingerprint   string `json:"successor_fingerprint"`
		RollbackRef            string `json:"rollback_ref"`
	} `json:"items"`
}

func connectorDeliveriesForIdentity(t *testing.T, h *servedHarness, tok, identityID string) connectorDeliveryList {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/connectors/deliveries?identity_id="+identityID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list connector deliveries: status %d body %s", status, body)
	}
	var out connectorDeliveryList
	out.Raw = body
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode connector deliveries: %v (%s)", err, body)
	}
	return out
}

func rotationRunsForIdentity(t *testing.T, h *servedHarness, tok, identityID string) rotationRunList {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/lifecycle/rotation-runs?identity_id="+identityID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list rotation runs: status %d body %s", status, body)
	}
	var out rotationRunList
	out.Raw = body
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode rotation runs: %v (%s)", err, body)
	}
	return out
}
