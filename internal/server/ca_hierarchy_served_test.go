package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func TestServedCAHierarchyCeremonyAndLeafIssuance(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	openerToken := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "ca-operator", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverOne := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "custodian-one", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverTwo := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "custodian-two", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})

	rootSpec := map[string]any{
		"common_name":           "trstctl customer root",
		"max_path_len":          1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"svc.example.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	rootCeremony := createCACeremony(t, h, openerToken, "create_root", "", rootSpec, 2, "root-ceremony")

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/roots", openerToken, "root-before-quorum", map[string]any{
		"ceremony_id": rootCeremony.ID,
		"spec":        rootSpec,
	})
	if code != http.StatusConflict || !strings.Contains(string(body), "quorum") {
		t.Fatalf("root before quorum = %d body=%s; want 409 quorum problem", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+rootCeremony.ID+"/approvals", openerToken, "root-self-approval", nil)
	if code != http.StatusConflict {
		t.Fatalf("root self-approval = %d body=%s; want 409 separation-of-duties refusal", code, body)
	}
	approveCACeremony(t, h, approverOne, rootCeremony.ID, 1, "root-approval-one")
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/roots", openerToken, "root-one-approval", map[string]any{
		"ceremony_id": rootCeremony.ID,
		"spec":        rootSpec,
	})
	if code != http.StatusConflict || !strings.Contains(string(body), "quorum") {
		t.Fatalf("root after one approval = %d body=%s; want 409 quorum problem", code, body)
	}
	approveCACeremony(t, h, approverTwo, rootCeremony.ID, 2, "root-approval-two")
	root := createRootCA(t, h, openerToken, rootCeremony.ID, rootSpec, "root-create")
	if root.Kind != "root" || root.CommonName != rootSpec["common_name"] || root.CertificatePEM == "" || root.SignerHandle == "" {
		t.Fatalf("root response = %+v; want root with certificate and signer handle", root)
	}

	interSpec := map[string]any{
		"common_name":           "trstctl customer issuing intermediate",
		"ttl_seconds":           int64((180 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"svc.example.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	interCeremony := createCACeremony(t, h, openerToken, "create_intermediate", root.ID, interSpec, 2, "intermediate-ceremony")
	approveCACeremony(t, h, approverOne, interCeremony.ID, 1, "intermediate-approval-one")
	approveCACeremony(t, h, approverTwo, interCeremony.ID, 2, "intermediate-approval-two")
	inter := createIntermediateCA(t, h, openerToken, interCeremony.ID, root.ID, interSpec, "intermediate-create")
	if inter.Kind != "intermediate" || inter.ParentID == nil || *inter.ParentID != root.ID || inter.SignerHandle == "" {
		t.Fatalf("intermediate response = %+v; want child of root with signer handle", inter)
	}

	client := h.signer.Client()
	leafSigner, err := client.GenerateKey(context.Background(), crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate leaf key in signer: %v", err)
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "leaf.svc.example.test",
		DNSNames:   []string{"leaf.svc.example.test"},
	}, leafSigner)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+inter.ID+"/issue", openerToken, "hierarchy-leaf-issue", map[string]any{
		"csr_pem":     csrPEM,
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if code != http.StatusCreated {
		t.Fatalf("issue hierarchy leaf = %d body=%s; want 201", code, body)
	}
	var issued struct {
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	if err := json.Unmarshal(body, &issued); err != nil || issued.CertificatePEM == "" || issued.Serial == "" {
		t.Fatalf("decode issued leaf: %v body=%s", err, body)
	}
	leafDER := caCertDER(t, []byte(issued.CertificatePEM))
	if err := crypto.VerifyLeafSignedByCA(leafDER, caCertDER(t, []byte(inter.CertificatePEM))); err != nil {
		t.Fatalf("leaf was not signed by served hierarchy intermediate: %v", err)
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatalf("inspect leaf: %v", err)
	}
	if info.Subject != "CN=leaf.svc.example.test" || len(info.DNSNames) != 1 || info.DNSNames[0] != "leaf.svc.example.test" {
		t.Fatalf("leaf identity = subject %q DNS %v; want hierarchy-issued leaf.svc.example.test", info.Subject, info.DNSNames)
	}
	if !h.hasEvent(t, "ca.root.created") || !h.hasEvent(t, "ca.intermediate.created") || !h.hasEvent(t, "ca.endentity.issued") {
		t.Fatal("hierarchy create/issue events were not recorded")
	}
}

type servedCACeremony struct {
	ID        string `json:"id"`
	Purpose   string `json:"purpose"`
	Threshold int    `json:"threshold"`
	Status    string `json:"status"`
	Approvals int    `json:"approvals"`
}

type servedCAAuthority struct {
	ID             string  `json:"id"`
	ParentID       *string `json:"parent_id"`
	CommonName     string  `json:"common_name"`
	Kind           string  `json:"kind"`
	Status         string  `json:"status"`
	CertificatePEM string  `json:"certificate_pem"`
	SignerHandle   string  `json:"signer_handle"`
}

func createCACeremony(t *testing.T, h *servedHarness, token, operation, parentID string, spec map[string]any, threshold int, idem string) servedCACeremony {
	t.Helper()
	body := map[string]any{"operation": operation, "threshold": threshold, "spec": spec}
	if parentID != "" {
		body["parent_id"] = parentID
	}
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", token, idem, body)
	if code != http.StatusCreated {
		t.Fatalf("create %s ceremony = %d body=%s; want 201", operation, code, raw)
	}
	var got servedCACeremony
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" || got.Threshold != threshold || got.Status != "pending" {
		t.Fatalf("decode %s ceremony: %v got=%+v body=%s", operation, err, got, raw)
	}
	return got
}

func approveCACeremony(t *testing.T, h *servedHarness, token, ceremonyID string, wantApprovals int, idem string) {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremonyID+"/approvals", token, idem, nil)
	if code != http.StatusOK {
		t.Fatalf("approve ceremony %s = %d body=%s; want 200", ceremonyID, code, raw)
	}
	var got servedCACeremony
	if err := json.Unmarshal(raw, &got); err != nil || got.Approvals != wantApprovals {
		t.Fatalf("decode approval count: %v got=%+v body=%s", err, got, raw)
	}
}

func createRootCA(t *testing.T, h *servedHarness, token, ceremonyID string, spec map[string]any, idem string) servedCAAuthority {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/roots", token, idem, map[string]any{
		"ceremony_id": ceremonyID,
		"spec":        spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("create root CA = %d body=%s; want 201", code, raw)
	}
	var got servedCAAuthority
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" {
		t.Fatalf("decode root CA: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func createIntermediateCA(t *testing.T, h *servedHarness, token, ceremonyID, parentID string, spec map[string]any, idem string) servedCAAuthority {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/intermediates", token, idem, map[string]any{
		"ceremony_id": ceremonyID,
		"parent_id":   parentID,
		"spec":        spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("create intermediate CA = %d body=%s; want 201", code, raw)
	}
	var got servedCAAuthority
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" {
		t.Fatalf("decode intermediate CA: %v got=%+v body=%s", err, got, raw)
	}
	return got
}
