package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/pqc"
	"trstctl.com/trstctl/internal/profile"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// TestServedProtocolsIssueHybridPQCLeaves is the PQC-04 acceptance: the SAME served
// protocol issuer used by ACME and CMP honors a hybrid-only certificate profile,
// verifies the CSR's ML-DSA proof-of-possession, and emits a CA-signed transition
// leaf carrying the ML-DSA-44 + ECDSA-P256 composite binding.
func TestServedProtocolsIssueHybridPQCLeaves(t *testing.T) {
	var challengeAddr string
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, challengeAddr)
		},
	}
	validators := acmesrv.Validators{
		HTTP01: acmesrv.HTTP01Validator{Client: &http.Client{Transport: transport, Timeout: 5 * time.Second}},
		DNS01:  acmesrv.DNS01Validator{},
	}
	const profileName = "hybrid-protocol"
	h := newServedHarness(t,
		config.Protocols{
			ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
			CMP:  config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		},
		func(d *Deps) {
			d.ACMEValidators = &validators
			d.DefaultProfile = profileName
		},
	)
	storeServerTestProfile(t, h.store, h.tenant, profileName, profile.CertificateProfile{
		Name:                 profileName,
		AllowedKeyAlgorithms: []string{crypto.HybridMLDSA44ECDSAP256Algorithm},
		AllowedProtocols:     []string{"acme", "cmp"},
		MaxValidity:          profile.Duration(30 * 24 * time.Hour),
	})

	acmeDomain := "hybrid-acme.served.test"
	acmeLeaf := servedACMEIssueCSR(t, h, &challengeAddr, acmeDomain, buildServedHybridCSR(t, acmeDomain))
	assertServedHybridProtocolLeaf(t, acmeLeaf, h.caPEM, acmeDomain)

	cmpDomain := "hybrid-cmp.served.test"
	clientCertDER, clientKeyPKCS8, _ := newSCEPClient(t, "hybrid-cmp-transport")
	reqDER, err := crypto.BuildCMPRequest(
		buildServedHybridCSR(t, cmpDomain),
		clientCertDER,
		clientKeyPKCS8,
		[]byte("served-cmp-pqc-txn"),
		[]byte("nonce-pqc-123456"),
	)
	if err != nil {
		t.Fatalf("build CMP hybrid request: %v", err)
	}
	resp, err := h.ts.Client().Post(h.ts.URL+"/cmp", "application/pkixcmp", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatalf("CMP hybrid PKIOperation: %v", err)
	}
	replyDER, _ := readAllClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CMP hybrid status %d: %s", resp.StatusCode, replyDER)
	}
	cmpLeaf, err := crypto.ParseCMPResponse(replyDER)
	if err != nil {
		t.Fatalf("parse CMP hybrid response: %v", err)
	}
	assertServedHybridProtocolLeaf(t, cmpLeaf, h.caPEM, cmpDomain)
}

func servedACMEIssueCSR(t *testing.T, h *servedHarness, challengeAddr *string, domain string, csr []byte) []byte {
	t.Helper()
	ctx := context.Background()
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("acme client: %v", err)
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register ACME account: %v", err)
	}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("authorize ACME hybrid order: %v", err)
	}
	mux := http.NewServeMux()
	chalSrv := httptest.NewServer(mux)
	t.Cleanup(chalSrv.Close)
	*challengeAddr = strings.TrimPrefix(chalSrv.URL, "http://")
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("get ACME authorization: %v", err)
		}
		var chal *xacme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
			}
		}
		if chal == nil {
			t.Fatal("served ACME offered no http-01 challenge")
		}
		resp, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			t.Fatalf("challenge response: %v", err)
		}
		mux.HandleFunc(client.HTTP01ChallengePath(chal.Token), func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, resp)
		})
		if _, err := client.Accept(ctx, chal); err != nil {
			t.Fatalf("accept ACME challenge: %v", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("wait ACME authorization: %v", err)
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("wait ACME order: %v", err)
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		t.Fatalf("finalize ACME hybrid cert: %v", err)
	}
	if len(chain) == 0 {
		t.Fatal("served ACME returned no hybrid certificate")
	}
	return chain[0]
}

func buildServedHybridCSR(t *testing.T, domain string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	t.Cleanup(key.Destroy)
	mldsaKey, err := pqc.GenerateKey(crypto.MLDSA44)
	if err != nil {
		t.Fatalf("generate ML-DSA key: %v", err)
	}
	t.Cleanup(mldsaKey.Destroy)
	hybridExt, err := pqc.HybridLeafCSRExtraExtension(key.Public(), mldsaKey)
	if err != nil {
		t.Fatalf("hybrid CSR extension: %v", err)
	}
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName:      domain,
		DNSNames:        []string{domain},
		ExtraExtensions: []crypto.CertificateExtension{hybridExt},
	}, key)
	if err != nil {
		t.Fatalf("build hybrid CSR: %v", err)
	}
	return csr
}

func assertServedHybridProtocolLeaf(t *testing.T, leafDER, caPEM []byte, domain string) {
	t.Helper()
	if err := crypto.VerifyLeafSignedByCA(leafDER, caCertDER(t, caPEM)); err != nil {
		t.Fatalf("hybrid protocol leaf does not verify against served CA: %v", err)
	}
	if err := pqc.VerifyHybridLeaf(leafDER); err != nil {
		t.Fatalf("protocol leaf is not a verified hybrid leaf: %v", err)
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatalf("inspect hybrid protocol leaf: %v", err)
	}
	if info.KeyAlgorithm != crypto.HybridMLDSA44ECDSAP256Algorithm {
		t.Fatalf("hybrid protocol leaf key algorithm = %q, want %q", info.KeyAlgorithm, crypto.HybridMLDSA44ECDSAP256Algorithm)
	}
	if !protoContains(info.DNSNames, domain) {
		t.Fatalf("hybrid protocol leaf DNSNames=%v, missing %q", info.DNSNames, domain)
	}
}
