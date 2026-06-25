package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
)

// TestServedSecretSyncPushesGitHubAWSAndKubernetes is the SEC-06 proof: a stored
// secret changes once in trstctl, then the served sync API pushes the value through
// configured concrete pushers to GitHub Actions, AWS Secrets Manager, and Kubernetes.
// The response and event log contain delivery metadata only; each destination fixture
// is read back over its own API-facing recorder to prove the external write happened.
func TestServedSecretSyncPushesGitHubAWSAndKubernetes(t *testing.T) {
	gh := newGitHubActionsSyncFixture(t)
	aws := newAWSSecretsManagerSyncFixture(t)
	k8s := newKubernetesSecretSyncFixture(t)

	ghPusher, err := secretsync.NewGitHubActionsPusher(secretsync.GitHubActionsConfig{
		Endpoint: gh.URL(), HTTPClient: gh.Client(), Owner: "ctlplne", Repo: "payments", Token: []byte("github-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	awsPusher, err := secretsync.NewAWSSecretsManagerPusher(secretsync.AWSSecretsManagerConfig{
		Endpoint: aws.URL(), HTTPClient: aws.Client(), Region: "us-east-1", AccessKeyID: "AKID", SecretAccessKey: []byte("SECRET"),
	})
	if err != nil {
		t.Fatal(err)
	}
	k8sPusher, err := secretsync.NewKubernetesPusher(secretsync.KubernetesConfig{
		Endpoint: k8s.URL(), HTTPClient: k8s.Client(), Namespace: "apps", BearerToken: []byte("k8s-token"),
	})
	if err != nil {
		t.Fatal(err)
	}

	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretSyncTargets = map[string]*secretsync.Target{
				"github-actions":      secretsync.NewGitHubActionsTarget(ghPusher),
				"aws-secrets-manager": secretsync.NewAWSSecretsManagerTarget(awsPusher),
				"kubernetes":          secretsync.NewKubernetesTarget(k8sPusher),
			}
		},
	)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok,
		map[string]any{"name": "sync/source", "value": "sync-v1"})
	if status != http.StatusCreated {
		t.Fatalf("create sync source: status %d body %s", status, body)
	}

	syncCases := []struct {
		target string
		remote string
		read   func() string
	}{
		{target: "github-actions", remote: "DB_PASSWORD", read: func() string { return gh.value("ctlplne", "payments", "DB_PASSWORD") }},
		{target: "aws-secrets-manager", remote: "prod/db/password", read: func() string { return aws.value("prod/db/password") }},
		{target: "kubernetes", remote: "db-password", read: func() string { return k8s.value("apps", "db-password") }},
	}

	for _, tc := range syncCases {
		status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", tok, "sec06-"+tc.target,
			map[string]any{"name": "sync/source", "target": tc.target, "remote_key": tc.remote})
		if status != http.StatusOK {
			t.Fatalf("%s sync: status %d body %s", tc.target, status, body)
		}
		var resp struct {
			Name      string `json:"name"`
			Target    string `json:"target"`
			RemoteKey string `json:"remote_key"`
			Enqueued  bool   `json:"enqueued"`
			Delivered bool   `json:"delivered"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("decode %s response: %v (%s)", tc.target, err, body)
		}
		if resp.Name != "sync/source" || resp.Target != tc.target || resp.RemoteKey != tc.remote || !resp.Enqueued || !resp.Delivered {
			t.Fatalf("%s sync response = %+v", tc.target, resp)
		}
		if strings.Contains(string(body), "sync-v1") {
			t.Fatalf("%s sync response leaked the secret value: %s", tc.target, body)
		}
		if got := tc.read(); got != "sync-v1" {
			t.Fatalf("%s destination readback = %q, want sync-v1", tc.target, got)
		}
	}

	// Replaying a sync with the same Idempotency-Key returns the cached result and
	// does not push a second write to the destination.
	before := gh.count("ctlplne", "payments", "DB_PASSWORD")
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", tok, "sec06-github-actions",
		map[string]any{"name": "sync/source", "target": "github-actions", "remote_key": "DB_PASSWORD"})
	if status != http.StatusOK {
		t.Fatalf("github replay: status %d body %s", status, body)
	}
	if after := gh.count("ctlplne", "payments", "DB_PASSWORD"); after != before {
		t.Fatalf("idempotent replay wrote GitHub %d times, want unchanged %d", after, before)
	}
	if !h.hasEvent(t, "secret.sync.delivered") {
		t.Fatal("no secret.sync.delivered event recorded")
	}
	if h.logContains(t, "sync-v1") {
		t.Fatal("secret sync event log leaked the synced secret value")
	}
}

type gitHubActionsSyncFixture struct {
	t      *testing.T
	server *httptest.Server
	mu     sync.Mutex
	values map[string]string
	counts map[string]int
}

func newGitHubActionsSyncFixture(t *testing.T) *gitHubActionsSyncFixture {
	t.Helper()
	f := &gitHubActionsSyncFixture{t: t, values: map[string]string{}, counts: map[string]int{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *gitHubActionsSyncFixture) URL() string          { return f.server.URL }
func (f *gitHubActionsSyncFixture) Client() *http.Client { return f.server.Client() }

func (f *gitHubActionsSyncFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer github-token" {
		http.Error(w, "auth", http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 6 || parts[0] != "repos" || parts[3] != "actions" || parts[4] != "secrets" {
		http.Error(w, "path", http.StatusNotFound)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		EncodedValue string `json:"encoded_value"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.EncodedValue)
	if err != nil {
		http.Error(w, "encoded_value", http.StatusBadRequest)
		return
	}
	key := parts[1] + "/" + parts[2] + "/" + parts[5]
	f.mu.Lock()
	f.values[key] = string(decoded)
	f.counts[key]++
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *gitHubActionsSyncFixture) value(owner, repo, name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[owner+"/"+repo+"/"+name]
}

func (f *gitHubActionsSyncFixture) count(owner, repo, name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[owner+"/"+repo+"/"+name]
}

type awsSecretsManagerSyncFixture struct {
	server *httptest.Server
	mu     sync.Mutex
	values map[string]string
}

func newAWSSecretsManagerSyncFixture(t *testing.T) *awsSecretsManagerSyncFixture {
	t.Helper()
	f := &awsSecretsManagerSyncFixture{values: map[string]string{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *awsSecretsManagerSyncFixture) URL() string          { return f.server.URL }
func (f *awsSecretsManagerSyncFixture) Client() *http.Client { return f.server.Client() }

func (f *awsSecretsManagerSyncFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Authorization") == "" || r.Header.Get("X-Amz-Date") == "" {
		http.Error(w, "missing sigv4", http.StatusUnauthorized)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Name         string `json:"Name"`
		SecretBinary string `json:"SecretBinary"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.Name == "" {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.SecretBinary)
	if err != nil {
		http.Error(w, "SecretBinary", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.values[req.Name] = string(decoded)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:us-east-1:111111111111:secret:` + req.Name + `","Name":"` + req.Name + `"}`))
}

func (f *awsSecretsManagerSyncFixture) value(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[name]
}

type kubernetesSecretSyncFixture struct {
	server *httptest.Server
	mu     sync.Mutex
	values map[string]string
}

func newKubernetesSecretSyncFixture(t *testing.T) *kubernetesSecretSyncFixture {
	t.Helper()
	f := &kubernetesSecretSyncFixture{values: map[string]string{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *kubernetesSecretSyncFixture) URL() string          { return f.server.URL }
func (f *kubernetesSecretSyncFixture) Client() *http.Client { return f.server.Client() }

func (f *kubernetesSecretSyncFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer k8s-token" {
		http.Error(w, "auth", http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 6 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "namespaces" || parts[4] != "secrets" {
		http.Error(w, "path", http.StatusNotFound)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.Data == nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.Data["value"])
	if err != nil {
		http.Error(w, "data.value", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.values[parts[3]+"/"+parts[5]] = string(decoded)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"kind":"Secret","apiVersion":"v1"}`))
}

func (f *kubernetesSecretSyncFixture) value(namespace, name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[namespace+"/"+name]
}

var _ = context.Background
