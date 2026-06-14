// Package pkisecret exposes PKI issuance through the secrets API (S18.3, F67): a
// developer requests a short-lived certificate like any other dynamic secret. It
// implements dynsecret.Provider, so the certificate is leased and revokes on
// expiry (S17.1); it issues from the internal CA through the crypto boundary
// (AN-3) with profile-scoped constraints (S8.1), is policy-gated (S10.1), and is
// audited via the lease engine (AN-2).
package pkisecret

import (
	"context"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/dynsecret"
)

// Profile constrains certificates issued through the secrets API (S8.1).
type Profile struct {
	Name               string
	MaxTTL             time.Duration
	AllowedCommonNames map[string]bool // empty = any
}

// PKIProvider issues short-lived certificates as a dynamic secret.
type PKIProvider struct {
	caCertDER []byte
	caSigner  crypto.DigestSigner
	profile   Profile
	gate      func(cn string) (bool, string) // optional policy gate (S10.1)
	mu        sync.Mutex
	live      map[string]bool
}

// NewPKIProvider constructs a PKIProvider over an internal CA.
func NewPKIProvider(caCertDER []byte, caSigner crypto.DigestSigner, profile Profile, gate func(string) (bool, string)) *PKIProvider {
	return &PKIProvider{caCertDER: caCertDER, caSigner: caSigner, profile: profile, gate: gate, live: map[string]bool{}}
}

// Name implements dynsecret.Provider.
func (p *PKIProvider) Name() string { return "pki" }

// Generate issues a short-lived certificate. The requested common name is carried
// in the lease Role (the "secret name"); the profile and policy gate it.
func (p *PKIProvider) Generate(_ context.Context, req dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	cn := req.Role
	if cn == "" {
		return dynsecret.Credential{}, fmt.Errorf("pkisecret: common name required")
	}
	if len(p.profile.AllowedCommonNames) > 0 && !p.profile.AllowedCommonNames[cn] {
		return dynsecret.Credential{}, fmt.Errorf("pkisecret: common name %q not permitted by profile %q", cn, p.profile.Name)
	}
	if p.gate != nil {
		if ok, reason := p.gate(cn); !ok {
			return dynsecret.Credential{}, fmt.Errorf("pkisecret: policy denied %q: %s", cn, reason)
		}
	}
	ttl := req.TTL
	if ttl <= 0 || (p.profile.MaxTTL > 0 && ttl > p.profile.MaxTTL) {
		ttl = p.profile.MaxTTL // profile-enforced cap
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return dynsecret.Credential{}, err
	}
	defer leafKey.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn}, leafKey)
	if err != nil {
		return dynsecret.Credential{}, err
	}
	certDER, err := crypto.SignLeafFromCSR(p.caCertDER, p.caSigner, csr, ttl)
	if err != nil {
		return dynsecret.Credential{}, fmt.Errorf("pkisecret: sign cert: %w", err)
	}
	serial := crypto.SHA256Hex(certDER)[:16]
	p.mu.Lock()
	p.live[serial] = true
	p.mu.Unlock()
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return dynsecret.Credential{BackendRef: serial, Secret: pemCert, Metadata: map[string]string{"cn": cn, "serial": serial}}, nil
}

// Revoke marks an issued certificate revoked (idempotent).
func (p *PKIProvider) Revoke(_ context.Context, serial string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.live, serial)
	return nil
}

// IsLive reports whether a certificate serial is still live (test/inspection).
func (p *PKIProvider) IsLive(serial string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.live[serial]
}
