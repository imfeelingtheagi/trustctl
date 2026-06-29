package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// CAP-REM-01 acceptance: automated remediation is not only a library workflow.
// The served API exposes a playbook catalog and runs a usage-backed NHI
// right-size playbook end-to-end: posture evidence is read, a connector intent is
// queued through the outbox, and remediation.playbook_run.recorded persists the
// run evidence for list/get.
func TestServedRemediationPlaybooksCAPREM01RightSizeEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	owner, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantID, Kind: store.OwnerWorkload, Name: "payments"})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	attrs, err := json.Marshal(map[string]any{
		"granted_scopes": []string{"secrets:read", "secrets:write", "admin:*"},
		"used_scopes":    []string{"secrets:read"},
		"last_used_at":   "2026-06-25T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("marshal attributes: %v", err)
	}
	identity, err := st.CreateIdentity(ctx, store.Identity{
		TenantID: tenantID, Kind: store.IdentityKind("service_account"), Name: "payments-bot",
		OwnerID: owner.ID, Attributes: attrs,
	})
	if err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "incident-commander", []string{
		string(authz.IncidentsRead), string(authz.IncidentsWrite), string(authz.NHIRead),
		string(authz.ConnectorsRead),
	})

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	srv, err := Build(ctx, Deps{
		Store: st, Log: log, EnableRemediation: true,
		APIOptions: []api.Option{api.WithAuth(api.AuthConfig{OIDCEnabled: true})},
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	code, catalogBody := doBearer(t, ts, http.MethodGet, "/api/v1/remediation/playbooks", adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(catalogBody, []byte(`"id":"nhi-right-size"`)) || !bytes.Contains(catalogBody, []byte(`"id":"credential-rotate"`)) {
		t.Fatalf("playbook catalog = %d body=%s; want revoke/rotate/right-size catalog", code, catalogBody)
	}

	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/remediation/playbooks/nhi-right-size/runs", adminToken, "cap-rem-01-right-size", map[string]any{
		"target_identity_id": identity.ID,
		"reason":             "remove unused production grants",
		"connector":          "aws-iam",
		"target":             "arn:aws:iam::123456789012:role/payments-bot",
		"remove_scopes":      []string{"secrets:write", "admin:*"},
		"rollback_ref":       "restore iam policy version v17",
	})
	if code != http.StatusCreated {
		t.Fatalf("run right-size playbook = %d, want 201; body=%s", code, body)
	}
	var run struct {
		ID                  string          `json:"id"`
		PlaybookID          string          `json:"playbook_id"`
		TargetIdentityID    string          `json:"target_identity_id"`
		InventoryID         string          `json:"inventory_id"`
		Status              string          `json:"status"`
		Phase               string          `json:"phase"`
		Action              string          `json:"action"`
		Connector           string          `json:"connector"`
		Target              string          `json:"target"`
		ConnectorDeliveryID string          `json:"connector_delivery_id"`
		ScopeDelta          json.RawMessage `json:"scope_delta"`
		EvidenceRefs        []string        `json:"evidence_refs"`
		RollbackRefs        []string        `json:"rollback_refs"`
		ConnectorDelivery   struct {
			Destination string `json:"destination"`
			Status      string `json:"status"`
			Connector   string `json:"connector"`
			Target      string `json:"target"`
		} `json:"connector_delivery"`
	}
	if err := json.Unmarshal(body, &run); err != nil {
		t.Fatalf("decode playbook run: %v body=%s", err, body)
	}
	if run.ID == "" || run.PlaybookID != "nhi-right-size" || run.TargetIdentityID != identity.ID || run.InventoryID != "identity/"+identity.ID {
		t.Fatalf("run ids = %+v", run)
	}
	if run.Status != "queued" || run.Phase != "right_size_connector_intent_queued" || run.Action != "right_size" {
		t.Fatalf("run status/phase/action = %s/%s/%s", run.Status, run.Phase, run.Action)
	}
	if run.Connector != "aws-iam" || run.Target != "arn:aws:iam::123456789012:role/payments-bot" {
		t.Fatalf("connector target = %s/%s", run.Connector, run.Target)
	}
	if run.ConnectorDeliveryID == "" || run.ConnectorDelivery.Destination != orchestrator.DestinationConnectorRightSize || run.ConnectorDelivery.Status != "queued" {
		t.Fatalf("connector delivery evidence = id %q %+v", run.ConnectorDeliveryID, run.ConnectorDelivery)
	}
	if !bytes.Contains(run.ScopeDelta, []byte(`"remove_scopes":["secrets:write","admin:*"]`)) || !bytes.Contains(run.ScopeDelta, []byte(`"used_scopes":["secrets:read"]`)) {
		t.Fatalf("scope delta does not preserve usage-backed least-privilege evidence: %s", run.ScopeDelta)
	}
	if len(run.EvidenceRefs) < 2 || !bytes.Contains([]byte(run.EvidenceRefs[0]), []byte("CAP-POST-01")) {
		t.Fatalf("evidence refs = %#v", run.EvidenceRefs)
	}
	if len(run.RollbackRefs) != 1 || run.RollbackRefs[0] != "restore iam policy version v17" {
		t.Fatalf("rollback refs = %#v", run.RollbackRefs)
	}

	code, listBody := doBearer(t, ts, http.MethodGet, "/api/v1/remediation/playbook-runs?playbook_id=nhi-right-size", adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(listBody, []byte(run.ID)) {
		t.Fatalf("list playbook runs = %d body=%s; want run id", code, listBody)
	}
	code, getBody := doBearer(t, ts, http.MethodGet, "/api/v1/remediation/playbook-runs/"+run.ID, adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(getBody, []byte(run.ConnectorDeliveryID)) {
		t.Fatalf("get playbook run = %d body=%s; want connector delivery id", code, getBody)
	}

	var outboxRows int
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
			tenantID, orchestrator.DestinationConnectorRightSize).Scan(&outboxRows)
	}); err != nil {
		t.Fatalf("count right-size outbox rows: %v", err)
	}
	if outboxRows != 1 {
		t.Fatalf("right-size outbox rows = %d, want 1", outboxRows)
	}

	var sawPlaybookEvent bool
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.Type == projections.EventRemediationPlaybookRunRecorded && ev.TenantID == tenantID && bytes.Contains(ev.Data, []byte(run.ID)) {
			sawPlaybookEvent = true
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log: %v", err)
	}
	if !sawPlaybookEvent {
		t.Fatal("remediation.playbook_run.recorded event was not recorded")
	}
}
