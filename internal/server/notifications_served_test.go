package server

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/webhook"
)

func TestServedLifecycleSchedulerDispatchesExpiryWebhookNotification(t *testing.T) {
	secret := []byte("served-expiry-webhook-test-secret")
	sink := newServedWebhookSink(t, secret)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleAlertBefore = 7 * 24 * time.Hour
		d.NotificationChannels = []notify.Notifier{
			webhook.New(sink.URL(), secret, webhook.WithHTTPClient(sink.Client())),
		}
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write",
		"identities:read", "identities:write",
		"certs:read", "certs:issue",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload",
		"name": "notif-01-owner",
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

	const name = "notif-01-expiring.served.test"
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind":     "x509_certificate",
		"name":     name,
		"owner_id": owner.ID,
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

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to":     "issued",
		"reason": "NOTIF-01 initial issue",
	})
	if status != http.StatusOK {
		t.Fatalf("issue transition: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue: %v", err)
	}

	certs, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner.ID, name)
	if err != nil {
		t.Fatalf("load issued cert: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("issued certs = %d, want 1", len(certs))
	}
	cert := certs[0]
	now := time.Now().UTC()
	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.Add(72 * time.Hour)
	cert.NotBefore = &notBefore
	cert.NotAfter = &notAfter
	if _, err := h.srv.orch.RecordCertificate(t.Context(), h.tenant, cert); err != nil {
		t.Fatalf("record near-expiry certificate: %v", err)
	}

	queued, err := h.srv.RunLifecycleOnce(t.Context())
	if err != nil {
		t.Fatalf("run lifecycle scheduler: %v", err)
	}
	if queued != 0 {
		t.Fatalf("renewals queued = %d, want 0; this test only enables expiry alerting", queued)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain notification outbox: %v", err)
	}

	alert := sink.LastAlert()
	if sink.Accepted() != 1 {
		t.Fatalf("webhook accepted %d expiry notifications, want 1", sink.Accepted())
	}
	if alert.Kind != notify.KindCertificateExpiry || alert.TenantID != h.tenant || alert.CertificateID != cert.ID || alert.Subject != cert.Subject || alert.Serial != cert.Serial {
		t.Fatalf("bad webhook alert: %+v, cert=%+v", alert, cert)
	}
	if !alert.NotAfter.Equal(notAfter) {
		t.Fatalf("alert not_after = %s, want %s", alert.NotAfter.Format(time.RFC3339), notAfter.Format(time.RFC3339))
	}
	got, err := h.store.GetCertificate(t.Context(), h.tenant, cert.ID)
	if err != nil {
		t.Fatalf("reload cert: %v", err)
	}
	if got.AlertedAt == nil {
		t.Fatal("certificate was not stamped alerted_at after served expiry notification enqueue")
	}
	var outboxStatus string
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT status
		   FROM outbox
		  WHERE tenant_id = $1
		    AND destination = $2
		    AND idempotency_key = $3`,
		h.tenant, notify.DestinationExpiry, "expiry:"+cert.ID).Scan(&outboxStatus); err != nil {
		t.Fatalf("load notification outbox row: %v", err)
	}
	if outboxStatus != "delivered" {
		t.Fatalf("notification outbox status = %q, want delivered", outboxStatus)
	}
	if !h.hasEvent(t, "certificate.expiring") {
		t.Fatal("missing certificate.expiring event")
	}
}

type servedWebhookSink struct {
	srv    *httptest.Server
	secret []byte

	mu       sync.Mutex
	accepted int
	last     notify.Alert
}

func newServedWebhookSink(t *testing.T, secret []byte) *servedWebhookSink {
	t.Helper()
	s := &servedWebhookSink{secret: append([]byte(nil), secret...)}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *servedWebhookSink) URL() string          { return s.srv.URL }
func (s *servedWebhookSink) Client() *http.Client { return s.srv.Client() }

func (s *servedWebhookSink) Accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

func (s *servedWebhookSink) LastAlert() notify.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

func (s *servedWebhookSink) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	want := "sha256=" + hex.EncodeToString(crypto.HMACSHA256(s.secret, body))
	if got := r.Header.Get("X-Trstctl-Signature"); got != want {
		http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
		return
	}
	var alert notify.Alert
	if err := json.Unmarshal(body, &alert); err != nil {
		http.Error(w, `{"error":"malformed alert"}`, http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.accepted++
	s.last = alert
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}
