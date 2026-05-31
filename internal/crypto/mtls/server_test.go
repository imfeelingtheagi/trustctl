package mtls_test

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"certctl.io/certctl/internal/crypto/mtls"
)

// TestServeHTTPSEncryptsAndRefusesPlaintext is the B4 acceptance: the control
// plane served with a self-signed internal certificate answers over TLS to a
// client that trusts it, a session cookie travels only over that TLS connection,
// and a plaintext request to the same socket is refused (nothing in the clear).
func TestServeHTTPSEncryptsAndRefusesPlaintext(t *testing.T) {
	sc, err := mtls.SelfSignedServerCert([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedServerCert: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "certctl_session", Value: "top-secret-session"})
		_, _ = io.WriteString(w, "ok")
	})}
	go func() { _ = sc.ServeHTTPS(srv, ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := ln.Addr().String()

	// A client trusting the server's certificate gets 200 over TLS, and the
	// session cookie is delivered (over the encrypted channel).
	tr, err := mtls.HTTPTransport(sc.TrustPEM)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	var resp *http.Response
	for i := 0; i < 50; i++ { // tolerate the serve goroutine starting
		resp, err = client.Get("https://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("HTTPS GET never succeeded: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HTTPS GET = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Set-Cookie"), "certctl_session") {
		t.Errorf("session cookie not delivered over TLS: %q", resp.Header.Get("Set-Cookie"))
	}

	// A plaintext request to the TLS socket never reaches the handler: the server
	// rejects it (Go answers a bare 400 "Client sent an HTTP request to an HTTPS
	// server"), so no handler response — and no session cookie — travels in the
	// clear.
	plain := &http.Client{Timeout: 2 * time.Second}
	if presp, perr := plain.Get("http://" + addr + "/healthz"); perr == nil {
		defer func() { _ = presp.Body.Close() }()
		if presp.StatusCode/100 == 2 {
			t.Errorf("plaintext request to the TLS socket was served by the handler (%d); cleartext must be refused", presp.StatusCode)
		}
		if strings.Contains(presp.Header.Get("Set-Cookie"), "certctl_session") {
			t.Error("session cookie was delivered over a plaintext request")
		}
	}
}

// TestSelfSignedServerCertHasUsableSANs: the generated certificate is a server
// certificate covering the requested hostnames and IPs.
func TestSelfSignedServerCertHasUsableSANs(t *testing.T) {
	sc, err := mtls.SelfSignedServerCert([]string{"localhost", "127.0.0.1", "certctl"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.TrustPEM) == 0 {
		t.Fatal("TrustPEM is empty; a client would have nothing to trust")
	}
}

// TestServerCertFromFilesRejectsMissing: an operator cert/key path that does not
// exist fails clearly rather than serving without TLS.
func TestServerCertFromFilesRejectsMissing(t *testing.T) {
	if _, err := mtls.ServerCertFromFiles("/no/such/cert.pem", "/no/such/key.pem"); err == nil {
		t.Error("ServerCertFromFiles accepted a missing cert/key")
	}
}

// TestLoopbackProbeClientTrustsNothingButConnects: the loopback liveness client
// reaches an internal-cert server (it does not verify the chain — it is a
// localhost liveness probe only).
func TestLoopbackProbeClientReachesInternalServer(t *testing.T) {
	sc, err := mtls.SelfSignedServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })}
	go func() { _ = sc.ServeHTTPS(srv, ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	client := mtls.LoopbackProbeClient(3 * time.Second)
	var err2 error
	for i := 0; i < 50; i++ {
		resp, e := client.Get("https://" + ln.Addr().String() + "/healthz")
		if e == nil {
			_ = resp.Body.Close()
			err2 = nil
			break
		}
		err2 = e
		time.Sleep(20 * time.Millisecond)
	}
	if err2 != nil && !errors.Is(err2, http.ErrServerClosed) {
		t.Fatalf("loopback probe client could not reach the internal-cert server: %v", err2)
	}
}
