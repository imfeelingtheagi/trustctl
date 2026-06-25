package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/drift"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/webhook"
)

func TestServedCTMonitoringAndDriftWorkers(t *testing.T) {
	secret := []byte("served-ct-drift-webhook-test-secret")
	sink := newServedWebhookSink(t, secret)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.NotificationChannels = []notify.Notifier{
			webhook.New(sink.URL(), secret, webhook.WithHTTPClient(sink.Client())),
		}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	shadowDER, shadowTBS, err := ctlogtest.IssueCert("shadow", "shadow.example.com")
	if err != nil {
		t.Fatal(err)
	}
	logSrv := ctlogtest.NewServer(ctlogtest.PrecertEntry(shadowDER, shadowTBS))
	t.Cleanup(logSrv.Close)

	ctRunID := createAndRunDiscoverySource(t, h, tok, "ct-log-fixture", "ct_log", map[string]any{
		"logs":                   []string{logSrv.URL()},
		"watched_domains":        []string{"example.com"},
		"allow_private_endpoint": true,
	})
	ctFindings := discoveryFindingsForRun(t, h, tok, ctRunID)
	if len(ctFindings.Items) != 1 {
		t.Fatalf("CT findings count = %d (%s), want 1", len(ctFindings.Items), ctFindings.Raw)
	}
	if f := ctFindings.Items[0]; f.Kind != "ct_unexpected_issuance" || f.Fingerprint == "" || !strings.Contains(f.Provenance, "ct:") {
		t.Fatalf("bad CT finding: %+v", f)
	}
	alert := sink.LastAlert()
	if sink.Accepted() != 1 || alert.Kind != notify.KindUnexpectedIssuance || alert.Subject != "CN=shadow" {
		t.Fatalf("CT alert not dispatched through notification webhook: accepted=%d alert=%+v", sink.Accepted(), alert)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "leaf.pem")
	declared := []byte("declared certificate bytes")
	if err := os.WriteFile(path, []byte("drifted certificate bytes"), 0o600); err != nil {
		t.Fatalf("write drift fixture: %v", err)
	}
	driftRunID := createAndRunDiscoverySource(t, h, tok, "drift-fixture", "drift", map[string]any{
		"watched": []map[string]any{{
			"path":        path,
			"class":       "certificate",
			"fingerprint": drift.Fingerprint(declared),
			"mode":        "0600",
		}},
	})
	driftFindings := discoveryFindingsForRun(t, h, tok, driftRunID)
	if len(driftFindings.Items) != 1 {
		t.Fatalf("drift findings count = %d (%s), want 1", len(driftFindings.Items), driftFindings.Raw)
	}
	if f := driftFindings.Items[0]; f.Kind != "credential_drift" || f.Ref != path || !strings.Contains(f.Provenance, "drift:") {
		t.Fatalf("bad drift finding: %+v", f)
	}
	var meta struct {
		Type  string `json:"type"`
		Class string `json:"class"`
	}
	if err := json.Unmarshal(driftFindings.Items[0].Metadata, &meta); err != nil {
		t.Fatalf("decode drift metadata: %v (%s)", err, driftFindings.Items[0].Metadata)
	}
	if meta.Type != string(drift.Replaced) || meta.Class != "certificate" {
		t.Fatalf("drift metadata = %+v, want replaced certificate", meta)
	}

	for _, eventType := range []string{"discovery.finding.recorded", "discovery.run.completed"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event", eventType)
		}
	}
}

func createAndRunDiscoverySource(t *testing.T, h *servedHarness, tok, name, kind string, cfg map[string]any) string {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name":   name,
		"kind":   kind,
		"config": cfg,
	})
	if status != http.StatusCreated {
		t.Fatalf("create %s discovery source: status %d body %s", kind, status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start %s discovery run: status %d body %s", kind, status, body)
	}
	var queued struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.Status != "queued" {
		t.Fatalf("bad queued run: %+v", queued)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain %s discovery outbox: %v", kind, err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get %s discovery run: status %d body %s", kind, status, body)
	}
	var completed struct {
		Status     string `json:"status"`
		Targets    int    `json:"targets"`
		Discovered int    `json:"discovered"`
		Failed     int    `json:"failed"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed run: %v (%s)", err, body)
	}
	if completed.Status != "succeeded" || completed.Targets != 1 || completed.Discovered != 1 || completed.Failed != 0 {
		t.Fatalf("%s discovery run = %+v, want one successful finding", kind, completed)
	}
	return queued.ID
}

type servedDiscoveryFindingList struct {
	Raw   []byte
	Items []struct {
		Kind        string          `json:"kind"`
		Ref         string          `json:"ref"`
		Provenance  string          `json:"provenance"`
		Fingerprint string          `json:"fingerprint"`
		Metadata    json.RawMessage `json:"metadata"`
	} `json:"items"`
}

func discoveryFindingsForRun(t *testing.T, h *servedHarness, tok, runID string) servedDiscoveryFindingList {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+runID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list discovery findings: status %d body %s", status, body)
	}
	var out servedDiscoveryFindingList
	out.Raw = body
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode discovery findings: %v (%s)", err, body)
	}
	return out
}
