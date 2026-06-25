package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// HybridHandshakeMaterial is the opaque TLS material needed to prove that a
// served certificate can complete a TLS 1.3 handshake with ML-KEM hybrid key
// exchange. The private key is PKCS#8 DER bytes so callers outside the crypto
// boundary never import crypto/x509.
type HybridHandshakeMaterial struct {
	CertificatePEM  []byte
	PrivateKeyPKCS8 []byte
	TrustPEM        []byte
	ServerName      string
}

// HybridHandshakeState is the reduced, non-secret handshake result a caller can
// assert without importing crypto/tls.
type HybridHandshakeState struct {
	Version     string
	Curve       string
	CipherSuite string
}

// ProbeHybridHandshake starts a loopback TLS server with the supplied
// certificate chain, connects a TLS 1.3 client that offers only X25519MLKEM768,
// and returns the negotiated state. It is a served-path probe for hybrid TLS,
// not a library-only config check.
func ProbeHybridHandshake(mat HybridHandshakeMaterial) (HybridHandshakeState, error) {
	if len(mat.CertificatePEM) == 0 {
		return HybridHandshakeState{}, errors.New("mtls: hybrid probe requires certificate PEM")
	}
	if len(mat.PrivateKeyPKCS8) == 0 {
		return HybridHandshakeState{}, errors.New("mtls: hybrid probe requires PKCS#8 private key")
	}
	if len(mat.TrustPEM) == 0 {
		return HybridHandshakeState{}, errors.New("mtls: hybrid probe requires trust PEM")
	}
	if mat.ServerName == "" {
		return HybridHandshakeState{}, errors.New("mtls: hybrid probe requires server name")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mat.PrivateKeyPKCS8})
	defer secret.Wipe(keyPEM)
	cert, err := tls.X509KeyPair(mat.CertificatePEM, keyPEM)
	if err != nil {
		return HybridHandshakeState{}, fmt.Errorf("mtls: load hybrid probe certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(mat.TrustPEM) {
		return HybridHandshakeState{}, errors.New("mtls: hybrid probe trust PEM contained no certificates")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return HybridHandshakeState{}, fmt.Errorf("mtls: listen for hybrid probe: %w", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
		TLSConfig: &tls.Config{
			Certificates:     []tls.Certificate{cert},
			MinVersion:       tls.VersionTLS13,
			MaxVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		},
	}
	done := make(chan error, 1)
	go func() {
		err := srv.ServeTLS(ln, "", "")
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		done <- err
	}()
	defer func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}()

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:          roots,
				ServerName:       mat.ServerName,
				MinVersion:       tls.VersionTLS13,
				MaxVersion:       tls.VersionTLS13,
				CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
			},
		},
	}
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ln.Addr().String(), http.NoBody)
	if err != nil {
		return HybridHandshakeState{}, fmt.Errorf("mtls: build hybrid probe request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		select {
		case serveErr := <-done:
			if serveErr != nil {
				return HybridHandshakeState{}, fmt.Errorf("mtls: hybrid probe server failed: %w", serveErr)
			}
		default:
		}
		return HybridHandshakeState{}, fmt.Errorf("mtls: hybrid TLS handshake failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.TLS == nil {
		return HybridHandshakeState{}, errors.New("mtls: hybrid probe completed without TLS state")
	}
	return HybridHandshakeState{
		Version:     tlsVersionName(resp.TLS.Version),
		Curve:       resp.TLS.CurveID.String(),
		CipherSuite: tls.CipherSuiteName(resp.TLS.CipherSuite),
	}, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
