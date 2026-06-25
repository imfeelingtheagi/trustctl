package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// IAM-06 acceptance: the running control plane serves the recovery-side
// break-glass procedure. A signed offline emergency bundle is POSTed to the served
// API, verified against deployment-pinned break-glass trust anchors, and reconciled
// into the tenant's hash-chained audit log.
func TestServedBreakglassReconcileRecordsAuditChain(t *testing.T) {
	bundle, caDER, pubDER := servedBreakglassBundle(t)
	auditKey, err := jose.GenerateRSASigningKey("iam-06-audit")
	if err != nil {
		t.Fatalf("generate audit key: %v", err)
	}

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditSigningKey = auditKey
		d.BreakglassCACertDER = caDER
		d.BreakglassPublicKeyDER = pubDER
	})
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "incident-commander", []string{
		string(authz.CertsIssue), string(authz.AuditRead),
	})

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/breakglass/reconcile", token, "iam-06-breakglass-reconcile", map[string]any{
		"bundles": []breakglass.Bundle{bundle},
	})
	if code != http.StatusOK {
		t.Fatalf("break-glass reconcile = %d body=%s; want 200", code, body)
	}
	var reconcileResp struct {
		Reconciled int `json:"reconciled"`
	}
	if err := json.Unmarshal(body, &reconcileResp); err != nil || reconcileResp.Reconciled != 1 {
		t.Fatalf("decode reconcile response: reconciled=%d err=%v body=%s", reconcileResp.Reconciled, err, body)
	}
	if !h.hasEvent(t, "breakglass.issued") {
		t.Fatal("breakglass.issued was not appended to the event log")
	}

	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/audit/events?type=breakglass.issued", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("audit search = %d body=%s; want 200", code, body)
	}
	var auditResp struct {
		Events []audit.Record `json:"events"`
		Count  int            `json:"count"`
	}
	if err := json.Unmarshal(body, &auditResp); err != nil || auditResp.Count != 1 || len(auditResp.Events) != 1 {
		t.Fatalf("decode audit response: count=%d len=%d err=%v body=%s", auditResp.Count, len(auditResp.Events), err, body)
	}
	rec := auditResp.Events[0]
	if rec.Type != "breakglass.issued" || rec.TenantID != h.tenant || rec.Hash == "" {
		t.Fatalf("audit record = type %q tenant %q hash %q; want breakglass.issued for tenant with hash", rec.Type, rec.TenantID, rec.Hash)
	}
	if !bytes.Contains(rec.Data, []byte(`"request_id":"iam-06-emergency-1"`)) || !bytes.Contains(rec.Data, []byte(`"approvals":2`)) {
		t.Fatalf("audit data does not describe the reconciled bundle: %s", rec.Data)
	}
	if _, err := audit.VerifyChain(auditResp.Events); err != nil {
		t.Fatalf("break-glass audit record is not chain-verifiable: %v", err)
	}
}

func servedBreakglassBundle(t *testing.T) (breakglass.Bundle, []byte, []byte) {
	t.Helper()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate break-glass CA key: %v", err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := crypto.SelfSignedCACert(ca, "Break-glass Emergency CA", time.Hour)
	if err != nil {
		t.Fatalf("self-sign break-glass CA: %v", err)
	}
	svc, err := breakglass.New(breakglass.Config{
		TenantID:  servedTestTenant,
		CACertDER: caDER,
		CASigner:  ca,
		Quorum:    breakglass.Quorum{Threshold: 2, Operators: []string{"op1", "op2", "op3"}},
		Clock:     func() time.Time { return time.Unix(1_736_000_000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("new break-glass service: %v", err)
	}
	workload, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate workload key: %v", err)
	}
	t.Cleanup(workload.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "recovery.svc.example.test",
		DNSNames:   []string{"recovery.svc.example.test"},
	}, workload)
	if err != nil {
		t.Fatalf("create emergency CSR: %v", err)
	}
	bundle, err := svc.IssueOffline(breakglass.EmergencyRequest{
		ID:        "iam-06-emergency-1",
		Subject:   "recovery.svc.example.test",
		CSRDer:    csrDER,
		Reason:    "control plane signer unavailable during regional outage",
		Approvals: []string{"op1", "op2"},
	}, 30*time.Minute)
	if err != nil {
		t.Fatalf("issue offline bundle: %v", err)
	}
	return bundle, caDER, svc.PublicKeyDER()
}
