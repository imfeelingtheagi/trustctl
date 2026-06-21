package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// TestServedDiscoveryNetworkScanEndToEnd is the JOURNEY-001 proof: the assembled
// control plane serves discovery source/run/finding APIs, queues scan execution
// through the outbox, records findings through projected events, and feeds the
// certificate inventory. On the pre-wiring tree the first POST is a 404 because
// discovery existed only as library code.
func TestServedDiscoveryNetworkScanEndToEnd(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(tlsSrv.Close)
	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse test TLS URL: %v", err)
	}

	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "loopback-tls",
		"kind": "network",
		"config": map[string]any{
			"targets": []string{u.Host},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create discovery source: status %d body %s", status, body)
	}
	var source struct {
		ID       string          `json:"id"`
		TenantID string          `json:"tenant_id"`
		Kind     string          `json:"kind"`
		Config   json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}
	if source.ID == "" || source.TenantID != h.tenant || source.Kind != "network" {
		t.Fatalf("bad source response: %+v", source)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start discovery run: status %d body %s", status, body)
	}
	var queued struct {
		ID       string `json:"id"`
		Status   string `json:"status"`
		SourceID string `json:"source_id"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.SourceID != source.ID || queued.Status != "queued" {
		t.Fatalf("bad queued run: %+v", queued)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain discovery outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get discovery run: status %d body %s", status, body)
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
		t.Fatalf("completed run = %+v, want one successful discovery", completed)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list discovery findings: status %d body %s", status, body)
	}
	var findings struct {
		Items []struct {
			Kind        string `json:"kind"`
			Ref         string `json:"ref"`
			Provenance  string `json:"provenance"`
			Fingerprint string `json:"fingerprint"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("findings count = %d body %s, want 1", len(findings.Items), body)
	}
	if f := findings.Items[0]; f.Kind != "x509_certificate" || f.Ref != u.Host || f.Fingerprint == "" || !strings.Contains(f.Provenance, "network") {
		t.Fatalf("bad finding: %+v", f)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list certificates: status %d body %s", status, body)
	}
	var certs struct {
		Items []struct {
			DeploymentLocation string `json:"deployment_location"`
			Source             string `json:"source"`
			Fingerprint        string `json:"fingerprint"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &certs); err != nil {
		t.Fatalf("decode certificates: %v (%s)", err, body)
	}
	if len(certs.Items) != 1 || certs.Items[0].DeploymentLocation != u.Host || certs.Items[0].Source != "discovery:network" || certs.Items[0].Fingerprint == "" {
		t.Fatalf("inventory was not populated from discovery: %+v", certs.Items)
	}

	for _, eventType := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "certificate.recorded"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event; discovery is not fully event-sourced", eventType)
		}
	}
}
