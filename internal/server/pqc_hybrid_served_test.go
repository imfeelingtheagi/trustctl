package server

import (
	"context"
	"encoding/pem"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/pqc"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestServedHybridLeafCompletesHybridTLSHandshake(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := context.Background()

	const domain = "hybrid.served.test"
	leafPKCS8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GeneratePKCS8: %v", err)
	}
	defer secret.Wipe(leafPKCS8)
	leafKey, err := crypto.NewLockedSignerFromPKCS8(crypto.ECDSAP256, leafPKCS8)
	if err != nil {
		t.Fatalf("NewLockedSignerFromPKCS8: %v", err)
	}
	defer leafKey.Destroy()
	mldsaKey, err := pqc.GenerateKey(crypto.MLDSA44)
	if err != nil {
		t.Fatalf("GenerateKey(ML-DSA-44): %v", err)
	}
	defer mldsaKey.Destroy()
	hybridExt, err := pqc.HybridLeafCSRExtraExtension(leafKey.Public(), mldsaKey)
	if err != nil {
		t.Fatalf("HybridLeafCSRExtraExtension: %v", err)
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName:      domain,
		DNSNames:        []string{domain},
		ExtraExtensions: []crypto.CertificateExtension{hybridExt},
	}, leafKey)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}

	leafPEM, err := h.srv.IssueHybridLeaf(ctx, csrDER, time.Hour)
	if err != nil {
		t.Fatalf("IssueHybridLeaf: %v", err)
	}
	block, _ := pem.Decode(leafPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("IssueHybridLeaf returned non-certificate PEM")
	}
	leafDER := block.Bytes
	if err := crypto.VerifyLeafSignedByCA(leafDER, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("hybrid leaf does not verify against served CA: %v", err)
	}
	hybrid, err := pqc.InspectHybridLeaf(leafDER)
	if err != nil {
		t.Fatalf("InspectHybridLeaf: %v", err)
	}
	if hybrid.CompositeAlgorithmOID != pqc.CompositeMLDSA44ECDSAP256SHA256OID {
		t.Fatalf("composite OID = %s, want %s", hybrid.CompositeAlgorithmOID, pqc.CompositeMLDSA44ECDSAP256SHA256OID)
	}
	if hybrid.MLDSAAlgorithm != crypto.MLDSA44 || len(hybrid.CompositePublicKey) == 0 {
		t.Fatalf("bad hybrid extension: %+v", hybrid)
	}
	if err := pqc.VerifyHybridLeaf(leafDER); err != nil {
		t.Fatalf("VerifyHybridLeaf: %v", err)
	}

	certChainPEM := append(append([]byte(nil), leafPEM...), h.caPEM...)
	state, err := mtls.ProbeHybridHandshake(mtls.HybridHandshakeMaterial{
		CertificatePEM:  certChainPEM,
		PrivateKeyPKCS8: leafPKCS8,
		TrustPEM:        h.caPEM,
		ServerName:      domain,
	})
	if err != nil {
		t.Fatalf("ProbeHybridHandshake: %v", err)
	}
	if state.Version != "TLS 1.3" || state.Curve != "X25519MLKEM768" {
		t.Fatalf("hybrid TLS state = %+v, want TLS 1.3 over X25519MLKEM768", state)
	}
}
