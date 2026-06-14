package pkisecret

import (
	"context"
	"encoding/pem"
	"testing"
	"time"

	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/dynsecret"
)

func ca(t *testing.T) ([]byte, crypto.DigestSigner) {
	t.Helper()
	k, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Destroy)
	der, _ := crypto.SelfSignedCACert(k, "PKI Secrets CA", time.Hour)
	return der, k
}

func TestPKISecretIssuedAndLeasedLikeDynamicSecret(t *testing.T) {
	caDER, caKey := ca(t)
	prof := Profile{Name: "web", MaxTTL: 30 * time.Minute, AllowedCommonNames: map[string]bool{"web.example": true}}
	p := NewPKIProvider(caDER, caKey, prof, nil)
	eng, _ := dynsecret.New(dynsecret.Config{TenantID: "t1", Providers: []dynsecret.Provider{p}, Queue: dynsecret.NewMemoryQueue()})
	ctx := context.Background()

	// Request a cert via the secrets API, asking for 1h but the profile caps to 30m.
	lease, secret, err := eng.Issue(ctx, "pki", "web.example", time.Hour, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	block, _ := pem.Decode(secret)
	if block == nil {
		t.Fatal("secret is not a PEM certificate")
	}
	if err := crypto.VerifyLeafSignedByCA(block.Bytes, caDER); err != nil {
		t.Fatalf("issued cert does not chain to CA: %v", err)
	}
	_, notAfter, _ := crypto.CertValidity(block.Bytes)
	if time.Until(notAfter) > 35*time.Minute {
		t.Errorf("TTL not capped by profile: expires in %v", time.Until(notAfter))
	}
	// Leased like a dynamic secret: revokes on expiry.
	if !p.IsLive(lease.BackendRef) {
		t.Fatal("cert not live after issue")
	}
	_, _ = eng.ExpireDue(ctx, time.Now().Add(time.Hour))
	_, _ = eng.RunRevocations(ctx)
	if p.IsLive(lease.BackendRef) {
		t.Error("cert not revoked on lease expiry")
	}
}

func TestPKISecretProfileAndPolicyConstraints(t *testing.T) {
	caDER, caKey := ca(t)
	ctx := context.Background()

	// Profile restricts allowed CNs.
	p := NewPKIProvider(caDER, caKey, Profile{Name: "x", MaxTTL: time.Hour, AllowedCommonNames: map[string]bool{"ok.example": true}}, nil)
	if _, err := p.Generate(ctx, dynsecret.GenerateRequest{Role: "evil.example", TTL: time.Minute}); err == nil {
		t.Error("issued a CN not permitted by the profile")
	}

	// Policy gate denies.
	gated := NewPKIProvider(caDER, caKey, Profile{Name: "x", MaxTTL: time.Hour}, func(cn string) (bool, string) {
		return cn != "blocked", "policy"
	})
	if _, err := gated.Generate(ctx, dynsecret.GenerateRequest{Role: "blocked", TTL: time.Minute}); err == nil {
		t.Error("issued despite a policy denial")
	}
}

// TestPKISecretReturnsUsableKeypair is the GAP-004 acceptance: the issued
// dynamic-secret credential must carry the certificate AND its matching leaf
// private key, so the holder can actually present a TLS identity. Pre-fix the
// Secret held only a CERTIFICATE block (the key was Destroy()'d inside Generate),
// so this fails; post-fix the Secret is a cert+key PEM bundle whose private key
// matches the certificate's public key (proven by a sign/verify round-trip
// through the crypto boundary — no crypto/* import, AN-3).
func TestPKISecretReturnsUsableKeypair(t *testing.T) {
	caDER, caKey := ca(t)
	prof := Profile{Name: "web", MaxTTL: 30 * time.Minute, AllowedCommonNames: map[string]bool{"app.example": true}}
	p := NewPKIProvider(caDER, caKey, prof, nil)

	cred, err := p.Generate(context.Background(), dynsecret.GenerateRequest{Role: "app.example", TTL: time.Hour})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// The Secret must contain both a CERTIFICATE and a PRIVATE KEY PEM block.
	var certDER, keyDER []byte
	rest := cred.Secret
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			certDER = blk.Bytes
		case "PRIVATE KEY":
			keyDER = blk.Bytes
		}
	}
	if certDER == nil {
		t.Fatal("returned Secret has no CERTIFICATE block")
	}
	if keyDER == nil {
		t.Fatal("returned Secret has no PRIVATE KEY block — the issued cert is unusable (GAP-004)")
	}

	// The private key must actually match the cert's public key: reconstruct the
	// leaf key, sign a payload, and verify with the cert's public key.
	leaf, err := crypto.LockedKeyFromPKCS8(keyDER)
	if err != nil {
		t.Fatalf("returned private key is not valid PKCS#8: %v", err)
	}
	defer leaf.Destroy()

	payload := []byte("proof-of-possession")
	sig, err := crypto.SignMessage(leaf, payload)
	if err != nil {
		t.Fatalf("sign with returned leaf key: %v", err)
	}
	certPub, err := crypto.PublicKeyDERFromCert(certDER)
	if err != nil {
		t.Fatalf("extract cert public key: %v", err)
	}
	if err := crypto.VerifyMessage(certPub, payload, sig); err != nil {
		t.Fatalf("returned private key does NOT match the certificate's public key: %v", err)
	}

	// The cert must still chain to the CA (no regression of the existing promise).
	if err := crypto.VerifyLeafSignedByCA(certDER, caDER); err != nil {
		t.Fatalf("issued cert does not chain to CA: %v", err)
	}
}

func TestPKIProviderConforms(t *testing.T) {
	caDER, caKey := ca(t)
	p := NewPKIProvider(caDER, caKey, Profile{Name: "any", MaxTTL: time.Hour}, nil)
	if err := dynsecret.Conform(p); err != nil {
		t.Fatalf("Conform: %v", err)
	}
}
