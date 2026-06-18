package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// TestServedMutationIdempotencyReplayMatrix is the ARCH-006 protection guard for
// AN-5 over the live served API composition. It drives representative mutation
// families through server.Build -> Handler on the embedded stack, then retries the
// exact request with the same Idempotency-Key. A correct replay returns the cached
// response and does not append a second tenant event.
func TestServedMutationIdempotencyReplayMatrix(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant,
		"owners:write",
		"issuers:write",
		"identities:write",
		"certs:write",
		"certs:issue",
		"profiles:write",
		"agents:write",
		"secrets:write",
	)

	ownerBody := assertServedMutationReplay(t, h, servedReplayCase{
		name:       "owners create",
		method:     http.MethodPost,
		path:       "/api/v1/owners",
		token:      token,
		key:        "arch-006-owner-create",
		body:       map[string]any{"kind": "workload", "name": "arch-006-owner"},
		wantStatus: http.StatusCreated,
		eventType:  "owner.created",
	})
	var owner struct {
		ID string `json:"id"`
	}
	decodeServedReplayBody(t, ownerBody, &owner)
	if owner.ID == "" {
		t.Fatalf("owners create replay returned no id: %s", ownerBody)
	}

	issuerBody := assertServedMutationReplay(t, h, servedReplayCase{
		name:       "issuers create",
		method:     http.MethodPost,
		path:       "/api/v1/issuers",
		token:      token,
		key:        "arch-006-issuer-create",
		body:       map[string]any{"kind": "x509_ca", "name": "arch-006-issuer", "chain": []string{string(h.caPEM)}, "internal": true},
		wantStatus: http.StatusCreated,
		eventType:  "issuer.created",
	})
	var issuer struct {
		ID string `json:"id"`
	}
	decodeServedReplayBody(t, issuerBody, &issuer)
	if issuer.ID == "" {
		t.Fatalf("issuers create replay returned no id: %s", issuerBody)
	}

	identityBody := assertServedMutationReplay(t, h, servedReplayCase{
		name:       "identities create",
		method:     http.MethodPost,
		path:       "/api/v1/identities",
		token:      token,
		key:        "arch-006-identity-create",
		body:       map[string]any{"kind": "x509_certificate", "name": "arch-006-identity", "owner_id": owner.ID, "issuer_id": issuer.ID},
		wantStatus: http.StatusCreated,
		eventType:  "identity.created",
	})
	var identity struct {
		ID string `json:"id"`
	}
	decodeServedReplayBody(t, identityBody, &identity)
	if identity.ID == "" {
		t.Fatalf("identities create replay returned no id: %s", identityBody)
	}

	assertServedMutationReplay(t, h, servedReplayCase{
		name:       "identity transition",
		method:     http.MethodPost,
		path:       "/api/v1/identities/" + identity.ID + "/transitions",
		token:      token,
		key:        "arch-006-identity-transition",
		body:       map[string]any{"to": "issued", "reason": "ARCH-006 replay guard"},
		wantStatus: http.StatusOK,
		eventType:  "identity.issued",
	})

	assertServedMutationReplay(t, h, servedReplayCase{
		name:       "certificates ingest",
		method:     http.MethodPost,
		path:       "/api/v1/certificates",
		token:      token,
		key:        "arch-006-certificate-ingest",
		body:       map[string]any{"pem": string(h.caPEM), "owner_id": owner.ID, "source": "import", "deployment_location": "arch-006"},
		wantStatus: http.StatusCreated,
		eventType:  "certificate.recorded",
	})

	assertServedMutationReplay(t, h, servedReplayCase{
		name:   "profiles create",
		method: http.MethodPost,
		path:   "/api/v1/profiles",
		token:  token,
		key:    "arch-006-profile-create",
		body: map[string]any{
			"name": "arch-006-profile",
			"spec": map[string]any{
				"subject":         map[string]any{"common_name": "arch-006.example.test"},
				"max_ttl_seconds": 3600,
			},
		},
		wantStatus: http.StatusCreated,
		eventType:  "profile.created",
	})

	assertServedMutationReplay(t, h, servedReplayCase{
		name:       "agent enrollment tokens",
		method:     http.MethodPost,
		path:       "/api/v1/agents/enrollment-tokens",
		token:      token,
		key:        "arch-006-agent-token",
		wantStatus: http.StatusCreated,
	})

	assertServedMutationReplay(t, h, servedReplayCase{
		name:       "secrets create",
		method:     http.MethodPost,
		path:       "/api/v1/secrets/store",
		token:      token,
		key:        "arch-006-secret-create",
		body:       map[string]any{"name": "arch-006/db-password", "value": "secret-value"},
		wantStatus: http.StatusCreated,
		eventType:  "secret.created",
	})
}

type servedReplayCase struct {
	name       string
	method     string
	path       string
	token      string
	key        string
	body       any
	wantStatus int
	eventType  string
}

func assertServedMutationReplay(t *testing.T, h *servedHarness, tc servedReplayCase) []byte {
	t.Helper()
	before := servedEventCount(t, h, tc.eventType)
	firstStatus, firstBody := servedMutationRequest(t, h, tc)
	secondStatus, secondBody := servedMutationRequest(t, h, tc)

	if firstStatus != tc.wantStatus {
		t.Fatalf("%s first status = %d, want %d; body=%s", tc.name, firstStatus, tc.wantStatus, firstBody)
	}
	if secondStatus != tc.wantStatus {
		t.Fatalf("%s replay status = %d, want %d; body=%s", tc.name, secondStatus, tc.wantStatus, secondBody)
	}
	if !bytes.Equal(firstBody, secondBody) {
		t.Fatalf("%s replay body changed\nfirst:  %s\nsecond: %s", tc.name, firstBody, secondBody)
	}
	if tc.eventType != "" {
		after := servedEventCount(t, h, tc.eventType)
		if after != before+1 {
			t.Fatalf("%s appended %d %q events, want exactly 1", tc.name, after-before, tc.eventType)
		}
	}
	return firstBody
}

func servedMutationRequest(t *testing.T, h *servedHarness, tc servedReplayCase) (int, []byte) {
	t.Helper()
	var body io.Reader
	if tc.body != nil {
		data, err := json.Marshal(tc.body)
		if err != nil {
			t.Fatalf("%s: marshal body: %v", tc.name, err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(tc.method, h.ts.URL+tc.path, body)
	if err != nil {
		t.Fatalf("%s: new request: %v", tc.name, err)
	}
	req.Header.Set("Authorization", "Bearer "+tc.token)
	req.Header.Set("X-Tenant-ID", h.tenant)
	req.Header.Set("Idempotency-Key", tc.key)
	if tc.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s: do request: %v", tc.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s: read response: %v", tc.name, err)
	}
	return resp.StatusCode, data
}

func servedEventCount(t *testing.T, h *servedHarness, eventType string) int {
	t.Helper()
	if eventType == "" {
		return 0
	}
	count := 0
	if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.Type == eventType && e.TenantID == h.tenant {
			count++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
	return count
}

func decodeServedReplayBody(t *testing.T, body []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("decode replay body: %v; body=%s", err, body)
	}
}
