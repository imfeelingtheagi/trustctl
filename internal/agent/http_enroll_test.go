package agent_test

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"certctl.io/certctl/internal/agent"
	"certctl.io/certctl/internal/agent/enroll"
)

// TestAgentBootstrapsOverHTTP exercises the binary's enrollment transport: the
// agent bootstraps through the HTTP enrollment endpoint (enroll.Handler) rather
// than an in-process enroller, and ends up with an issued certificate.
func TestAgentBootstrapsOverHTTP(t *testing.T) {
	authority, err := enroll.NewAuthority("cp")
	if err != nil {
		t.Fatal(err)
	}
	token, err := authority.IssueBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	hsrv := httptest.NewServer(enroll.Handler(authority))
	t.Cleanup(hsrv.Close)

	dir := t.TempDir()
	a := agent.New(agent.Config{
		CommonName: "agent-http", BootstrapToken: token,
		KeyPath: filepath.Join(dir, "a.key"), CertPath: filepath.Join(dir, "a.crt"),
		ServerName: "localhost", ServerCAPEM: authority.CABundlePEM(), RefreshBefore: time.Hour,
	}, agent.NewHTTPEnroller(hsrv.URL, nil))

	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap over HTTP: %v", err)
	}
	if a.CertificateSerial() == "" {
		t.Error("agent has no certificate after HTTP bootstrap")
	}

	// Rotation also works over HTTP (the renewal endpoint).
	if err := a.Rotate(context.Background()); err != nil {
		t.Fatalf("Rotate over HTTP: %v", err)
	}
}
