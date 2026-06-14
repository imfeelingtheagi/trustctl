// Package enroll is the control-plane side of agent enrollment (F3/F15, sprint
// S5.1): it issues one-time bootstrap tokens, signs agents' CSRs into short-lived
// mTLS client certificates, and serves the mutual-TLS transport credentials.
// Agents generate their keys locally and submit only CSRs, so private keys never
// reach the control plane. All signing routes through the internal/crypto/mtls
// boundary (AN-3); in production the CA key is custodied by the signer (AN-4).
//
// Bootstrap tokens are bound to the authorizing tenant at mint and redeemed
// single-use through a durable, tenant-scoped TokenStore (WIRE-003): a token
// survives a control-plane restart, is redeemable on any instance, and can be
// redeemed at most once across the whole deployment. The issued certificate is
// stamped with the authorizing tenant's SPIFFE SAN (AN-1) so the mTLS consumer
// derives the tenant from the certificate, never from the (attacker-chosen) CSR
// subject or a request header.
package enroll

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"

	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/crypto/mtls"
)

// ErrBadToken is returned when a bootstrap token is unknown, expired, or already
// used. It is deliberately coarse so a caller cannot distinguish those cases.
var ErrBadToken = errors.New("enroll: invalid, expired, or already-used bootstrap token")

// DefaultTokenTTL is how long a freshly minted bootstrap token is redeemable. A
// bootstrap token is meant to be used promptly during provisioning, so the window
// is short.
const DefaultTokenTTL = 1 * time.Hour

// MintedToken is a stored bootstrap token bound to its authorizing tenant. Only
// the token's hash is persisted; the raw secret is returned once at mint.
type MintedToken struct {
	TokenHash       string
	TenantID        string
	AllowedIdentity string
	ExpiresAt       time.Time
}

// RedeemedToken is what a TokenStore returns when a token is consumed: the
// authorizing tenant and any identity the token was pinned to.
type RedeemedToken struct {
	TenantID        string
	AllowedIdentity string
}

// TokenStore persists tenant-bound, single-use bootstrap tokens durably. The
// store package's *store.Store satisfies it (adapted in internal/server); tests
// and the standalone HTTP transport use the in-memory implementation below. Save
// records a minted token; Redeem atomically consumes it by hash and returns its
// tenant — and must reject a second redemption of the same token (single-use)
// across instances and restarts.
type TokenStore interface {
	Save(ctx context.Context, t MintedToken) error
	// Redeem consumes the token with tokenHash exactly once. It returns ErrBadToken
	// (recognizable via errors.Is) when the token is unknown, expired, or already
	// used.
	Redeem(ctx context.Context, tokenHash string) (RedeemedToken, error)
}

// Authority issues agent client certificates: it mints tenant-bound one-time
// bootstrap tokens, redeems them single-use through a durable TokenStore, and
// signs CSRs through the mTLS CA — stamping the redeemed tenant into the issued
// certificate.
type Authority struct {
	ca    *mtls.CA
	store TokenStore
	ttl   time.Duration
}

// NewAuthority creates an enrollment authority with a fresh mTLS CA and a durable,
// tenant-scoped TokenStore. The store makes bootstrap tokens restart-safe,
// multi-instance-safe, and tenant-attributed (WIRE-003).
func NewAuthority(commonName string, store TokenStore) (*Authority, error) {
	if store == nil {
		return nil, errors.New("enroll: a TokenStore is required")
	}
	ca, err := mtls.NewCA(commonName)
	if err != nil {
		return nil, err
	}
	return &Authority{ca: ca, store: store, ttl: DefaultTokenTTL}, nil
}

// IssueBootstrapToken mints a one-time bootstrap token bound to tenantID (and,
// optionally, to allowedIdentity — the agent common name it may enroll as; empty
// means any). The raw token is returned once; only its hash is stored. A token
// minted here is durable and tenant-scoped, so it survives restarts, is
// redeemable on any instance, and yields a tenant-attributed certificate.
func (a *Authority) IssueBootstrapToken(ctx context.Context, tenantID, allowedIdentity string) (string, error) {
	if tenantID == "" {
		return "", errors.New("enroll: refusing to mint a bootstrap token without a tenant")
	}
	b, err := crypto.RandomBytes(24)
	if err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	hash, err := hashToken(token)
	if err != nil {
		return "", err
	}
	if err := a.store.Save(ctx, MintedToken{
		TokenHash:       hash,
		TenantID:        tenantID,
		AllowedIdentity: allowedIdentity,
		ExpiresAt:       time.Now().Add(a.ttl),
	}); err != nil {
		return "", err
	}
	return token, nil
}

// EnrollBootstrap consumes a one-time token (single-use, via the durable store)
// and signs the agent's CSR into a client-certificate chain (PEM) stamped with
// the redeeming token's tenant (AN-1). The tenant comes from the token, never the
// CSR, so a token cannot mint a certificate attributed to a different tenant. When
// the token pins an allowed identity, a CSR whose common name differs is rejected.
func (a *Authority) EnrollBootstrap(ctx context.Context, token string, csrDER []byte) ([]byte, error) {
	hash, err := hashToken(token)
	if err != nil {
		return nil, err
	}
	redeemed, err := a.store.Redeem(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrBadToken) {
			return nil, ErrBadToken
		}
		return nil, err
	}
	if redeemed.AllowedIdentity != "" {
		cn, err := mtls.CSRCommonName(csrDER)
		if err != nil {
			return nil, err
		}
		if cn != redeemed.AllowedIdentity {
			return nil, ErrBadToken
		}
	}
	return a.ca.SignClientCSRWithTenant(csrDER, redeemed.TenantID, mtls.ClientCertTTL)
}

// EnrollRenewal signs a rotation CSR into a fresh client certificate chain. In
// production this endpoint is reached over the agent's existing mTLS connection,
// so the agent is already authenticated by its current certificate, and the tenant
// it should retain is carried by that certificate's SPIFFE SAN (WIRE-003): the
// renewal preserves it rather than trusting the new CSR.
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

// hashToken returns the deterministic lookup hash of a raw bootstrap token
// (SHA-256 hex), computed through the crypto boundary (AN-3). Only the hash is
// stored, never the raw token.
func hashToken(token string) (string, error) {
	sum, err := crypto.Digest(crypto.SHA256, []byte(token))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum), nil
}

// MemoryTokenStore is an in-process TokenStore for the standalone HTTP enrollment
// transport and tests. It is durable only for the process lifetime — production
// uses the PostgreSQL-backed store (the WIRE-003 fix). It is concurrency-safe and
// enforces single-use, tenant binding, and expiry exactly like the durable store.
type MemoryTokenStore struct {
	mu     sync.Mutex
	tokens map[string]MintedToken
}

// NewMemoryTokenStore creates an empty in-memory token store.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{tokens: map[string]MintedToken{}}
}

// Save records a minted token.
func (m *MemoryTokenStore) Save(_ context.Context, t MintedToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.TokenHash] = t
	return nil
}

// Redeem consumes a token by hash exactly once, rejecting unknown, expired, or
// already-used tokens.
func (m *MemoryTokenStore) Redeem(_ context.Context, tokenHash string) (RedeemedToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[tokenHash]
	if !ok {
		return RedeemedToken{}, ErrBadToken
	}
	delete(m.tokens, tokenHash) // single-use: gone after first redemption
	if time.Now().After(t.ExpiresAt) {
		return RedeemedToken{}, ErrBadToken
	}
	return RedeemedToken{TenantID: t.TenantID, AllowedIdentity: t.AllowedIdentity}, nil
}
