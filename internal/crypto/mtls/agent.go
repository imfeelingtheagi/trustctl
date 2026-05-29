package mtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
)

// This file adds the agent side of mutual TLS, inside the AN-3 crypto boundary:
// an agent generates its key here and never exports it — only a CSR crosses the
// wire — and the control plane signs that CSR. AgentIdentity holds the local key
// plus its issued certificate, presents it for handshakes (a ClientCertSource),
// and persists/reloads it so an agent survives restarts.

// AgentIdentity is an agent's local key plus its issued client certificate. The
// private key is generated and held here and never leaves the boundary.
type AgentIdentity struct {
	commonName string
	key        *ecdsa.PrivateKey
	chainPEM   []byte
	chainDER   [][]byte
	leaf       *x509.Certificate
}

// GenerateAgentKey generates a fresh local key for an agent identity (no
// certificate yet — call CSR, have it signed, then UseCertificate).
func GenerateAgentKey(commonName string) (*AgentIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &AgentIdentity{commonName: commonName, key: key}, nil
}

// CSR returns a PKCS#10 certificate request (DER) for this identity's key. Only
// the CSR — carrying the public key, never the private key — is sent to the CA.
func (a *AgentIdentity) CSR() ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: a.commonName},
	}, a.key)
}

// UseCertificate adopts the certificate chain (PEM) the CA issued for this
// identity's CSR, after verifying the leaf carries this identity's public key.
func (a *AgentIdentity) UseCertificate(chainPEM []byte) error {
	var ders [][]byte
	rest := chainPEM
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			ders = append(ders, block.Bytes)
		}
		rest = r
	}
	if len(ders) == 0 {
		return errors.New("mtls: certificate chain has no certificates")
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return fmt.Errorf("mtls: parse issued leaf: %w", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&a.key.PublicKey) {
		return errors.New("mtls: issued certificate does not match the agent's key")
	}
	a.chainPEM = append([]byte(nil), chainPEM...)
	a.chainDER = ders
	a.leaf = leaf
	return nil
}

// ClientCertificate implements ClientCertSource, presenting this identity's
// certificate for a TLS handshake.
func (a *AgentIdentity) ClientCertificate() (*tls.Certificate, error) {
	if a.leaf == nil {
		return nil, errors.New("mtls: agent identity has no certificate yet")
	}
	return &tls.Certificate{Certificate: a.chainDER, PrivateKey: a.key, Leaf: a.leaf}, nil
}

// CommonName is the identity's subject common name.
func (a *AgentIdentity) CommonName() string { return a.commonName }

// Serial is the issued certificate's serial number in hex (empty if unissued).
func (a *AgentIdentity) Serial() string {
	if a.leaf == nil {
		return ""
	}
	return a.leaf.SerialNumber.Text(16)
}

// NotAfter is the issued certificate's expiry.
func (a *AgentIdentity) NotAfter() time.Time {
	if a.leaf == nil {
		return time.Time{}
	}
	return a.leaf.NotAfter
}

// CertificatePEM returns the issued certificate chain (PEM).
func (a *AgentIdentity) CertificatePEM() []byte { return a.chainPEM }

// Save persists the private key (0600) and certificate chain to keyPath and
// certPath. The key stays on the host; it is never transmitted.
func (a *AgentIdentity) Save(keyPath, certPath string) error {
	der, err := x509.MarshalPKCS8PrivateKey(a.key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("mtls: write key: %w", err)
	}
	if err := os.WriteFile(certPath, a.chainPEM, 0o644); err != nil {
		return fmt.Errorf("mtls: write certificate: %w", err)
	}
	return nil
}

// LoadAgentIdentity reloads an identity persisted by Save. It is how an agent
// resumes after a restart without re-bootstrapping.
func LoadAgentIdentity(commonName, keyPath, certPath string) (*AgentIdentity, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("mtls: stored key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse stored key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("mtls: stored key is not an ECDSA key")
	}
	chainPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	a := &AgentIdentity{commonName: commonName, key: key}
	if err := a.UseCertificate(chainPEM); err != nil {
		return nil, err
	}
	return a, nil
}

// SignClientCSR signs a PKCS#10 CSR as a short-lived agent client certificate
// (ClientAuth), valid for ttl, and returns the chain (leaf + CA) in PEM. The
// CA never sees the agent's private key — only its CSR.
func (c *CA) SignClientCSR(csrDER []byte, ttl time.Duration) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("mtls: csr signature: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("mtls: sign client csr: %w", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	out = append(out, c.BundlePEM()...)
	return out, nil
}

// BundlePEM returns the CA certificate in PEM (the trust anchor an agent pins to
// verify the control plane, and the chain root of issued client certs).
func (c *CA) BundlePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// ServerCredentials issues a server certificate for dnsNames and returns gRPC
// transport credentials that present it and require client certs from this CA —
// so the control plane wires mutual TLS without naming crypto/* itself.
func (c *CA) ServerCredentials(dnsNames []string, ttl time.Duration) (credentials.TransportCredentials, error) {
	serverCert, err := c.IssueServerCertificate(dnsNames, ttl)
	if err != nil {
		return nil, err
	}
	return ServerCredentials(serverCert, c.Pool()), nil
}

// SwappableSource is a ClientCertSource whose backing identity can be replaced
// atomically — so an agent's rotated certificate is presented on the next
// handshake without rebuilding the transport credentials.
type SwappableSource struct {
	mu  sync.Mutex
	cur ClientCertSource
}

// NewSwappableSource wraps an initial source.
func NewSwappableSource(initial ClientCertSource) *SwappableSource {
	return &SwappableSource{cur: initial}
}

// Set replaces the backing source.
func (s *SwappableSource) Set(src ClientCertSource) {
	s.mu.Lock()
	s.cur = src
	s.mu.Unlock()
}

// ClientCertificate returns the current source's certificate.
func (s *SwappableSource) ClientCertificate() (*tls.Certificate, error) {
	s.mu.Lock()
	src := s.cur
	s.mu.Unlock()
	if src == nil {
		return nil, errors.New("mtls: no client certificate source set")
	}
	return src.ClientCertificate()
}

// AgentClientCredentials builds gRPC client credentials for an agent from the
// control-plane CA certificate (PEM) — so the agent trusts the CP without naming
// crypto/* itself.
func AgentClientCredentials(src ClientCertSource, serverCAPEM []byte, serverName string, pin *Pin) (credentials.TransportCredentials, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(serverCAPEM) {
		return nil, errors.New("mtls: no CA certificates in the provided PEM")
	}
	return ClientCredentials(src, pool, serverName, pin), nil
}

// IsCSR reports whether der is a parseable PKCS#10 certificate request — used to
// assert that what an agent transmits during enrollment is a CSR, not a key.
func IsCSR(der []byte) bool {
	_, err := x509.ParseCertificateRequest(der)
	return err == nil
}

// LooksLikePrivateKey reports whether der parses as a private key — used to assert
// that a private key is never transmitted.
func LooksLikePrivateKey(der []byte) bool {
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return true
	}
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		return true
	}
	// Also catch a PEM-wrapped key.
	if block, _ := pem.Decode(bytes.TrimSpace(der)); block != nil {
		return block.Type == "PRIVATE KEY" || block.Type == "EC PRIVATE KEY" || block.Type == "RSA PRIVATE KEY"
	}
	return false
}
