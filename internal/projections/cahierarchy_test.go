package projections_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"certctl.io/certctl/internal/ca/hierarchy"
	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/crypto/certinfo"
	"certctl.io/certctl/internal/store"
)

func caHierCSR(t *testing.T, cn string, sans []string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: sans}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// quorum starts a ceremony and approves it with n distinct custodians.
func quorum(t *testing.T, m *hierarchy.Manager, tenantID, purpose string, threshold, approvals int) string {
	t.Helper()
	ctx := context.Background()
	id, err := m.StartCeremony(ctx, tenantID, purpose, threshold)
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}
	custodians := []string{"alice", "bob", "carol", "dave", "erin"}
	for i := 0; i < approvals; i++ {
		if _, err := m.Approve(ctx, tenantID, id, custodians[i]); err != nil {
			t.Fatalf("Approve: %v", err)
		}
	}
	return id
}

// TestKeyCeremonyRequiresQuorum is the acceptance "the key ceremony requires
// quorum": creating a CA before the m-of-n threshold is met is rejected; once the
// threshold is met it succeeds.
func TestKeyCeremonyRequiresQuorum(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m := hierarchy.NewManager(s, openLog(t))

	ceremony := quorum(t, m, tenantA, "root:Acme Root CA", 3, 2) // only 2 of 3 approvals
	if _, err := m.CreateRoot(ctx, tenantA, ceremony, hierarchy.CASpec{CommonName: "Acme Root CA", TTL: 10 * 365 * 24 * time.Hour}); !errors.Is(err, hierarchy.ErrQuorumNotMet) {
		t.Fatalf("CreateRoot without quorum err = %v, want ErrQuorumNotMet", err)
	}

	if _, err := m.Approve(ctx, tenantA, ceremony, "carol"); err != nil { // the third approval
		t.Fatal(err)
	}
	root, err := m.CreateRoot(ctx, tenantA, ceremony, hierarchy.CASpec{CommonName: "Acme Root CA", TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateRoot with quorum: %v", err)
	}
	if root.ID == "" || root.Kind != "root" || root.Status != "active" {
		t.Fatalf("root = %+v", root)
	}
}

// TestRootIntermediateAndEndEntity is the acceptance "create a root and an
// intermediate; issue an end-entity cert from the internal CA".
func TestRootIntermediateAndEndEntity(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m := hierarchy.NewManager(s, openLog(t))

	root, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, "root", 2, 2),
		hierarchy.CASpec{CommonName: "Acme Root CA", MaxPathLen: 1, TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}
	inter, err := m.CreateIntermediate(ctx, tenantA, quorum(t, m, tenantA, "intermediate", 2, 2), root.ID,
		hierarchy.CASpec{CommonName: "Acme Issuing CA", TTL: 5 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateIntermediate: %v", err)
	}
	if inter.Kind != "intermediate" || inter.ParentID == nil || *inter.ParentID != root.ID {
		t.Fatalf("intermediate = %+v", inter)
	}

	chain, err := m.IssueEndEntity(ctx, tenantA, inter.ID, caHierCSR(t, "svc.corp.internal", []string{"svc.corp.internal"}), 90*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueEndEntity: %v", err)
	}
	info, err := certinfo.Inspect(chain)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.corp.internal" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.corp.internal", info.DNSNames)
	}
}

// TestInternalCAConstraintViolationRejected is the acceptance "constraints are
// enforced (a violating issuance is rejected)".
func TestInternalCAConstraintViolationRejected(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m := hierarchy.NewManager(s, openLog(t))

	root, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, "root", 1, 1),
		hierarchy.CASpec{CommonName: "Corp Root CA", PermittedDNSDomains: []string{"corp.internal"}, TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	if _, err := m.IssueEndEntity(ctx, tenantA, root.ID, caHierCSR(t, "ok", []string{"ok.corp.internal"}), time.Hour); err != nil {
		t.Errorf("a permitted issuance was rejected: %v", err)
	}
	if _, err := m.IssueEndEntity(ctx, tenantA, root.ID, caHierCSR(t, "evil", []string{"evil.example.com"}), time.Hour); err == nil {
		t.Error("an issuance violating the name constraints was accepted")
	}
}

// TestCARotationCompletes is the acceptance "a CA-cert rotation completes".
func TestCARotationCompletes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m := hierarchy.NewManager(s, openLog(t))

	root, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, "root", 1, 1),
		hierarchy.CASpec{CommonName: "Rotate Root CA", TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	fresh, err := m.Rotate(ctx, tenantA, root.ID, quorum(t, m, tenantA, "rotate", 1, 1))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if fresh.ID == root.ID || fresh.Status != "active" {
		t.Fatalf("rotated CA = %+v", fresh)
	}
	if fresh.ReplacesID == nil || *fresh.ReplacesID != root.ID {
		t.Errorf("rotated CA replaces_id = %v, want %s", fresh.ReplacesID, root.ID)
	}
	old, err := s.GetCAAuthority(ctx, tenantA, root.ID)
	if err != nil {
		t.Fatal(err)
	}
	if old.Status != "superseded" {
		t.Errorf("old CA status = %q, want superseded", old.Status)
	}
}

// TestCAHierarchyTenantIsolation is the AN-1 acceptance for the new tables: a CA
// created in one tenant is invisible to another.
func TestCAHierarchyTenantIsolation(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m := hierarchy.NewManager(s, openLog(t))

	root, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, "root", 1, 1),
		hierarchy.CASpec{CommonName: "Tenant A Root", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	if cas, err := s.ListCAAuthorities(ctx, tenantB); err != nil {
		t.Fatal(err)
	} else if len(cas) != 0 {
		t.Errorf("tenant B sees %d CA authorities, want 0 (RLS must isolate)", len(cas))
	}
	if _, err := s.GetCAAuthority(ctx, tenantB, root.ID); !store.IsNotFound(err) {
		t.Errorf("tenant B could read tenant A's CA (err=%v); RLS must deny it", err)
	}
}
