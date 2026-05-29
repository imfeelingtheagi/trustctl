// Package enroll is the control-plane side of agent enrollment (F3/F15, sprint
// S5.1): it issues one-time bootstrap tokens, signs agents' CSRs into short-lived
// mTLS client certificates, and serves the mutual-TLS transport credentials.
// Agents generate their keys locally and submit only CSRs, so private keys never
// reach the control plane. All signing routes through the internal/crypto/mtls
// boundary (AN-3); in production the CA key is custodied by the signer (AN-4).
package enroll

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"

	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/crypto/mtls"
)

// ErrBadToken is returned when a bootstrap token is unknown or already used.
var ErrBadToken = errors.New("enroll: invalid or already-used bootstrap token")

// Authority issues agent client certificates: it validates one-time bootstrap
// tokens and signs CSRs through the mTLS CA.
type Authority struct {
	ca *mtls.CA

	mu     sync.Mutex
	tokens map[string]bool // unused one-time bootstrap tokens
}

// NewAuthority creates an enrollment authority with a fresh mTLS CA.
func NewAuthority(commonName string) (*Authority, error) {
	ca, err := mtls.NewCA(commonName)
	if err != nil {
		return nil, err
	}
	return &Authority{ca: ca, tokens: map[string]bool{}}, nil
}

// IssueBootstrapToken mints a one-time bootstrap token for provisioning an agent.
func (a *Authority) IssueBootstrapToken() (string, error) {
	b, err := crypto.RandomBytes(24)
	if err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	a.mu.Lock()
	a.tokens[token] = true
	a.mu.Unlock()
	return token, nil
}

// EnrollBootstrap consumes a one-time token and signs the agent's CSR into a
// client certificate chain (PEM).
func (a *Authority) EnrollBootstrap(_ context.Context, token string, csrDER []byte) ([]byte, error) {
	a.mu.Lock()
	ok := a.tokens[token]
	delete(a.tokens, token)
	a.mu.Unlock()
	if !ok {
		return nil, ErrBadToken
	}
	return a.ca.SignClientCSR(csrDER, mtls.ClientCertTTL)
}

// EnrollRenewal signs a rotation CSR into a fresh client certificate chain. In
// production this endpoint is reached over the agent's existing mTLS connection,
// so the agent is already authenticated by its current certificate.
func (a *Authority) EnrollRenewal(_ context.Context, csrDER []byte) ([]byte, error) {
	return a.ca.SignClientCSR(csrDER, mtls.ClientCertTTL)
}

// CABundlePEM is the CA certificate (PEM) an agent trusts to verify the control
// plane and that anchors issued client certificates.
func (a *Authority) CABundlePEM() []byte { return a.ca.BundlePEM() }

// ServerCredentials returns mutual-TLS transport credentials for the
// control-plane gRPC server, presenting a server certificate for dnsNames.
func (a *Authority) ServerCredentials(dnsNames []string) (credentials.TransportCredentials, error) {
	return a.ca.ServerCredentials(dnsNames, 24*time.Hour)
}
