package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TestServedKMIPPyKMIPCreateGet is the KMS-02 acceptance proof: the same server
// composition the binary runs mounts a tenant-bound, mTLS KMIP listener, and a real
// PyKMIP client container creates an AES-256 symmetric key and retrieves its 32-byte
// key material over the served listener.
func TestServedKMIPPyKMIPCreateGet(t *testing.T) {
	requireDockerForKMIP(t)

	dir := t.TempDir()
	ca, err := mtls.NewCA("trstctl KMIP test CA")
	if err != nil {
		t.Fatalf("kmip CA: %v", err)
	}
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, ca.BundlePEM(), 0o644); err != nil {
		t.Fatalf("write KMIP CA: %v", err)
	}
	serverCert, err := ca.IssueServerCertificate([]string{"host.docker.internal", "localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("issue KMIP server cert: %v", err)
	}
	clientCert, err := ca.IssueClientCertificate("pykmip-client", time.Hour)
	if err != nil {
		t.Fatalf("issue PyKMIP client cert: %v", err)
	}
	serverCertPath, serverKeyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	clientCertPath, clientKeyPath := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	if err := mtls.WriteCertKeyFiles(serverCertPath, serverKeyPath, serverCert); err != nil {
		t.Fatalf("write KMIP server material: %v", err)
	}
	if err := mtls.WriteCertKeyFiles(clientCertPath, clientKeyPath, clientCert); err != nil {
		t.Fatalf("write PyKMIP client material: %v", err)
	}

	h := newServedHarness(t, config.Protocols{
		KMIP: config.KMIPProtocol{
			Enabled:      true,
			TenantID:     servedTestTenant,
			Addr:         "127.0.0.1:0",
			CertFile:     serverCertPath,
			KeyFile:      serverKeyPath,
			ClientCAFile: caPath,
		},
	})
	if !h.srv.KMIPServed() {
		t.Fatal("KMIP listener is not wired into the served server")
	}

	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen KMIP test socket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.srv.ServeKMIP(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("ServeKMIP: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("ServeKMIP did not stop")
		}
	})

	host := os.Getenv("TRSTCTL_KMIP_TEST_HOST")
	if host == "" {
		host = "host.docker.internal"
	}
	port := ln.Addr().(*net.TCPAddr).Port
	out := runServedPyKMIPClient(t, dir, host, port)
	if !strings.Contains(out, "PYKMIP_OK") {
		t.Fatalf("PyKMIP client did not report success:\n%s", out)
	}
	if !h.hasEvent(t, "kmip.object.created") {
		t.Fatal("KMIP create did not emit the tenant-scoped audit/event record")
	}
}

func requireDockerForKMIP(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required for the PyKMIP acceptance test: %v", err)
	}
	cmd := exec.Command("docker", "version", "--format", "{{.Server.Version}}")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("docker daemon is required for the PyKMIP acceptance test: %v\n%s", err, out)
	}
}

func runServedPyKMIPClient(t *testing.T, certDir, host string, port int) string {
	t.Helper()
	image := "trstctl-pykmip-client:kms-02-py311"
	if out, err := exec.Command("docker", "image", "inspect", image).CombinedOutput(); err != nil {
		build := exec.Command("docker", "build", "-t", image, filepath.Join("testdata", "pykmip-client"))
		if buildOut, buildErr := build.CombinedOutput(); buildErr != nil {
			t.Fatalf("build PyKMIP client image after inspect failed (%v, %s): %v\n%s", err, out, buildErr, buildOut)
		}
	}
	args := []string{
		"run", "--rm",
		"--add-host=host.docker.internal:host-gateway",
		"-v", fmt.Sprintf("%s:/certs:ro", certDir),
		image,
		"--host", host,
		"--port", fmt.Sprintf("%d", port),
		"--ca", "/certs/ca.crt",
		"--cert", "/certs/client.crt",
		"--key", "/certs/client.key",
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil && strings.Contains(string(out), "host-gateway") {
		args = append([]string{"run", "--rm", "-v", fmt.Sprintf("%s:/certs:ro", certDir), image}, args[6:]...)
		out, err = exec.Command("docker", args...).CombinedOutput()
	}
	if err != nil {
		t.Fatalf("PyKMIP client failed: %v\n%s", err, out)
	}
	return string(out)
}
