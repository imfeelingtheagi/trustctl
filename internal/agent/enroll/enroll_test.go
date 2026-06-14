package enroll_test

import (
	"context"
	"errors"
	"testing"

	"trustctl.io/trustctl/internal/agent/enroll"
	"trustctl.io/trustctl/internal/crypto/mtls"
)

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
)

// newCSR generates a fresh agent key locally and returns its CSR (DER) — the same
// thing an agent transmits during enrollment (the private key never leaves).
func newCSR(t *testing.T, cn string) []byte {
	t.Helper()
	id, err := mtls.GenerateAgentKey(cn)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// leafDER pulls the leaf certificate (DER) out of the issued PEM chain so a test
// can inspect the SANs the CA stamped.
func leafDER(t *testing.T, chainPEM []byte) []byte {
	t.Helper()
	der, err := mtls.FirstCertDER(chainPEM)
	if err != nil {
		t.Fatalf("decode issued chain: %v", err)
	}
	return der
}

// TestBootstrapTokenIsTenantAttributed is the WIRE-003 core acceptance: a token
// minted under tenant A yields a client certificate whose SPIFFE SAN carries
// tenant A — the tenant comes from the token, not the (attacker-chosen) CSR.
func TestBootstrapTokenIsTenantAttributed(t *testing.T) {
	a, err := enroll.NewAuthority("cp", enroll.NewMemoryTokenStore())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	token, err := a.IssueBootstrapToken(ctx, tenantA, "")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := a.EnrollBootstrap(ctx, token, newCSR(t, "edge-agent-01"))
	if err != nil {
		t.Fatalf("EnrollBootstrap: %v", err)
	}
	got, err := mtls.TenantFromClientCert(leafDER(t, chain))
	if err != nil {
		t.Fatalf("TenantFromClientCert: %v", err)
	}
	if got != tenantA {
		t.Errorf("issued cert carries tenant %q, want %q", got, tenantA)
	}
}

// TestBootstrapTokenIsSingleUse: a token redeemed once is rejected on every later
// attempt (single-use) — proving a replayed token cannot mint a second
// certificate. This is the in-memory analogue of the cross-instance/cross-restart
// durable-store test (see the store-backed test in internal/projections).
func TestBootstrapTokenIsSingleUse(t *testing.T) {
	a, err := enroll.NewAuthority("cp", enroll.NewMemoryTokenStore())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	token, err := a.IssueBootstrapToken(ctx, tenantA, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.EnrollBootstrap(ctx, token, newCSR(t, "agent")); err != nil {
		t.Fatalf("first EnrollBootstrap should succeed: %v", err)
	}
	_, err = a.EnrollBootstrap(ctx, token, newCSR(t, "agent"))
	if !errors.Is(err, enroll.ErrBadToken) {
		t.Fatalf("second EnrollBootstrap = %v, want ErrBadToken (single-use)", err)
	}
}

// TestUnknownTokenRejected: a token that was never minted is rejected.
func TestUnknownTokenRejected(t *testing.T) {
	a, err := enroll.NewAuthority("cp", enroll.NewMemoryTokenStore())
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.EnrollBootstrap(context.Background(), "never-minted", newCSR(t, "agent"))
	if !errors.Is(err, enroll.ErrBadToken) {
		t.Fatalf("unknown token = %v, want ErrBadToken", err)
	}
}

// TestMintRequiresTenant: a mint with no tenant is refused — no bootstrap token is
// ever minted unattributed (AN-1).
func TestMintRequiresTenant(t *testing.T) {
	a, err := enroll.NewAuthority("cp", enroll.NewMemoryTokenStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.IssueBootstrapToken(context.Background(), "", ""); err == nil {
		t.Fatal("IssueBootstrapToken with empty tenant should fail")
	}
}

// TestAllowedIdentityPin: a token pinned to one identity refuses a CSR whose
// common name differs, and accepts the matching one — scoping a leaked token.
func TestAllowedIdentityPin(t *testing.T) {
	a, err := enroll.NewAuthority("cp", enroll.NewMemoryTokenStore())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Wrong identity is refused (and, being single-use, the token is now spent).
	tok1, _ := a.IssueBootstrapToken(ctx, tenantA, "payments-agent")
	if _, err := a.EnrollBootstrap(ctx, tok1, newCSR(t, "attacker-agent")); !errors.Is(err, enroll.ErrBadToken) {
		t.Fatalf("mismatched identity = %v, want ErrBadToken", err)
	}

	// Matching identity is accepted.
	tok2, _ := a.IssueBootstrapToken(ctx, tenantA, "payments-agent")
	if _, err := a.EnrollBootstrap(ctx, tok2, newCSR(t, "payments-agent")); err != nil {
		t.Fatalf("matching identity should enroll: %v", err)
	}
}

// TestTwoTenantsGetDistinctAttribution: tokens minted under different tenants
// yield certificates attributed to their respective tenants — no cross-tenant
// bleed in the issued credential (AN-1).
func TestTwoTenantsGetDistinctAttribution(t *testing.T) {
	a, err := enroll.NewAuthority("cp", enroll.NewMemoryTokenStore())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, tenant := range []string{tenantA, tenantB} {
		tok, err := a.IssueBootstrapToken(ctx, tenant, "")
		if err != nil {
			t.Fatal(err)
		}
		chain, err := a.EnrollBootstrap(ctx, tok, newCSR(t, "agent"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := mtls.TenantFromClientCert(leafDER(t, chain))
		if err != nil {
			t.Fatal(err)
		}
		if got != tenant {
			t.Errorf("cert attributed to %q, want %q", got, tenant)
		}
	}
}
