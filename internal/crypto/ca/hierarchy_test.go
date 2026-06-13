package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

// leafCSR builds a PKCS#10 CSR for the given common name and DNS SANs.
func leafCSR(t *testing.T, cn string, dnsNames []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func leafFromPEM(t *testing.T, chainPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(chainPEM)
	if block == nil {
		t.Fatal("no PEM block in chain")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestRootAndIntermediateChainVerifies builds a root → intermediate hierarchy and
// confirms an end-entity issued by the intermediate verifies up to the root.
func TestRootAndIntermediateChainVerifies(t *testing.T) {
	root, err := NewRoot(CASpec{CommonName: "trustctl Test Root", MaxPathLen: 1, TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewRoot: %v", err)
	}
	inter, err := root.CreateIntermediate(CASpec{CommonName: "trustctl Test Intermediate", TTL: 5 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateIntermediate: %v", err)
	}

	issued, err := inter.IssueLeaf(leafCSR(t, "svc.internal", []string{"svc.internal"}), 90*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}

	// The issued chain must verify: leaf -> intermediate -> root.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root.CertificatePEM()) {
		t.Fatal("could not add root to pool")
	}
	inters := x509.NewCertPool()
	if !inters.AppendCertsFromPEM(inter.CertificatePEM()) {
		t.Fatal("could not add intermediate to pool")
	}
	leaf := leafFromPEM(t, issued.CertificatePEM)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("issued leaf does not chain to the root: %v", err)
	}
}

// TestIssueLeafEnforcesNameConstraints rejects an end-entity whose SAN is outside
// the CA's permitted DNS name constraints.
func TestIssueLeafEnforcesNameConstraints(t *testing.T) {
	root, err := NewRoot(CASpec{CommonName: "Constrained Root", PermittedDNSDomains: []string{"acme.test"}, TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.IssueLeaf(leafCSR(t, "ok", []string{"ok.acme.test"}), time.Hour); err != nil {
		t.Errorf("a permitted SAN was rejected: %v", err)
	}
	if _, err := root.IssueLeaf(leafCSR(t, "evil", []string{"evil.example.com"}), time.Hour); err == nil {
		t.Error("a SAN outside the name constraints was issued")
	}
}

// TestPathLengthExhaustionRejected: a CA whose remaining path length is zero
// cannot create a further intermediate.
func TestPathLengthExhaustionRejected(t *testing.T) {
	root, err := NewRoot(CASpec{CommonName: "PathLen Root", MaxPathLen: 1, TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	inter, err := root.CreateIntermediate(CASpec{CommonName: "PathLen Intermediate", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("first intermediate: %v", err)
	}
	if inter.MaxPathLen() != 0 {
		t.Errorf("intermediate remaining path length = %d, want 0", inter.MaxPathLen())
	}
	if _, err := inter.CreateIntermediate(CASpec{CommonName: "Too Deep", TTL: time.Hour}); err == nil {
		t.Error("created an intermediate past the path-length constraint")
	}
}

// TestCrossSign signs another root's certificate with this CA, producing a
// cross-certificate that verifies under this CA's signature.
func TestCrossSign(t *testing.T) {
	a, err := NewRoot(CASpec{CommonName: "Root A", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewRoot(CASpec{CommonName: "Root B", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	crossPEM, err := a.CrossSign(b.CertificateDER())
	if err != nil {
		t.Fatalf("CrossSign: %v", err)
	}
	block, _ := pem.Decode(crossPEM)
	if block == nil {
		t.Fatal("cross cert has no PEM block")
	}
	cross, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// The cross-certificate carries B's subject but is signed by A.
	if cross.Subject.CommonName != "Root B" {
		t.Errorf("cross cert subject = %q, want Root B", cross.Subject.CommonName)
	}
	aCert := leafFromPEM(t, a.CertificatePEM())
	if err := cross.CheckSignatureFrom(aCert); err != nil {
		t.Errorf("cross cert is not signed by Root A: %v", err)
	}
}
