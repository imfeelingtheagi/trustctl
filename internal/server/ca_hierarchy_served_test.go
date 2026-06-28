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
	"trstctl.com/trstctl/internal/signing"
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

func TestServedCAHierarchySignsExternalIntermediateCSRRequiresCeremony(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "spire-upstream-operator", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approver := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "spire-upstream-approver", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverTwo := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "spire-upstream-approver-two", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	certsIssueOnly := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "leaf-issuer", []string{
		"certs:issue",
	})

	rootSpec := map[string]any{
		"common_name":           "trstctl SPIRE upstream root",
		"max_path_len":          1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"example.org"},
		"signature_algorithm":   "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, token, "create_root", "", rootSpec, 1, "spire-root-ceremony")
	approveCACeremony(t, h, approver, ceremony.ID, 1, "spire-root-approval")
	root := createRootCA(t, h, token, ceremony.ID, rootSpec, "spire-root-create")

	spireCAKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(spireCAKey.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "SPIRE Server CA",
	}, spireCAKey)
	if err != nil {
		t.Fatalf("create SPIRE intermediate CSR: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	intermediateSpec := map[string]any{
		"common_name":           "SPIRE Server CA",
		"max_path_len":          0,
		"ttl_seconds":           int64((24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"example.org"},
		"extended_key_usages":   []string{"serverAuth"},
	}
	issueBody := map[string]any{
		"csr_pem": csrPEM,
		"spec":    intermediateSpec,
	}

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/intermediates/csr", certsIssueOnly, "spire-intermediate-csr-certs-only", issueBody)
	if code != http.StatusForbidden {
		t.Fatalf("certs:issue-only external intermediate CSR = %d body=%s; want 403 issuers:write", code, body)
	}

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/intermediates/csr", token, "spire-intermediate-csr-no-ceremony", issueBody)
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "ceremony_id") {
		t.Fatalf("external intermediate CSR without ceremony = %d body=%s; want 422 ceremony_id", code, body)
	}

	intermediateCeremony := createCACeremonyWithCSR(t, h, token, root.ID, csrPEM, intermediateSpec, 2, "spire-intermediate-csr-ceremony")
	issueBody["ceremony_id"] = intermediateCeremony.ID

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/intermediates/csr", token, "spire-intermediate-csr-before-quorum", issueBody)
	if code != http.StatusConflict || !strings.Contains(string(body), "quorum") {
		t.Fatalf("external intermediate CSR before quorum = %d body=%s; want 409 quorum problem", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+intermediateCeremony.ID+"/approvals", token, "spire-intermediate-csr-self-approval", nil)
	if code != http.StatusConflict {
		t.Fatalf("external intermediate CSR self-approval = %d body=%s; want 409 separation-of-duties refusal", code, body)
	}
	approveCACeremony(t, h, approver, intermediateCeremony.ID, 1, "spire-intermediate-csr-approval-one")

	mismatchedSpec := map[string]any{
		"common_name":           "SPIRE Server CA",
		"max_path_len":          0,
		"ttl_seconds":           int64((24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"wrong.example.org"},
		"extended_key_usages":   []string{"serverAuth"},
	}
	mismatchedCeremony := createCACeremonyWithCSR(t, h, token, root.ID, csrPEM, mismatchedSpec, 1, "spire-intermediate-csr-mismatch-ceremony")
	approveCACeremony(t, h, approver, mismatchedCeremony.ID, 1, "spire-intermediate-csr-mismatch-approval")
	mismatchedBody := map[string]any{
		"ceremony_id": mismatchedCeremony.ID,
		"csr_pem":     csrPEM,
		"spec":        intermediateSpec,
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/intermediates/csr", token, "spire-intermediate-csr-purpose-mismatch", mismatchedBody)
	if code != http.StatusConflict || !strings.Contains(string(body), "purpose") {
		t.Fatalf("external intermediate CSR purpose mismatch = %d body=%s; want 409 purpose mismatch", code, body)
	}

	approveCACeremony(t, h, approverTwo, intermediateCeremony.ID, 2, "spire-intermediate-csr-approval-two")
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/intermediates/csr", token, "spire-intermediate-csr", issueBody)
	if code != http.StatusCreated {
		t.Fatalf("sign external intermediate CSR = %d body=%s; want 201", code, body)
	}
	var issued struct {
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	if err := json.Unmarshal(body, &issued); err != nil || issued.CertificatePEM == "" || issued.Serial == "" {
		t.Fatalf("decode issued intermediate: %v body=%s", err, body)
	}
	childDER := caCertDER(t, []byte(issued.CertificatePEM))
	if err := crypto.VerifyLeafSignedByCA(childDER, caCertDER(t, []byte(root.CertificatePEM))); err != nil {
		t.Fatalf("SPIRE intermediate did not verify against trstctl root: %v", err)
	}
	info, err := certinfo.Inspect(childDER)
	if err != nil {
		t.Fatalf("inspect issued SPIRE intermediate: %v", err)
	}
	if !info.IsCA {
		t.Fatal("issued SPIRE authority is not a CA certificate")
	}
	if !h.hasEvent(t, "ca.intermediate_csr.issued") {
		t.Fatal("no ca.intermediate_csr.issued event was recorded for the served SPIRE path")
	}
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/intermediates/csr", token, "spire-intermediate-csr-replay-new-idem", issueBody)
	if code != http.StatusConflict || !strings.Contains(string(body), "pending") {
		t.Fatalf("external intermediate CSR ceremony replay = %d body=%s; want 409 consumed ceremony", code, body)
	}
}

func TestServedCAHierarchyOfflineRootWorkflow(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	operator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "offline-root-operator", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverOne := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "offline-root-custodian-one", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverTwo := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "offline-root-custodian-two", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})

	offlineRootKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(offlineRootKey.Destroy)
	rootProfile := crypto.HierarchyCAProfile{
		CommonName:          "offline airgapped root",
		MaxPathLen:          1,
		TTL:                 365 * 24 * time.Hour,
		PermittedDNSDomains: []string{"offline.example.test"},
		EKUs:                []string{"serverAuth"},
	}
	offlineRoot, err := crypto.SelfSignedHierarchyCA(offlineRootKey, rootProfile)
	if err != nil {
		t.Fatalf("create offline root fixture: %v", err)
	}
	rootPEM := string(offlineRoot.CertificatePEM)
	rootSpec := map[string]any{
		"common_name":           rootProfile.CommonName,
		"max_path_len":          rootProfile.MaxPathLen,
		"ttl_seconds":           int64(rootProfile.TTL.Seconds()),
		"permitted_dns_domains": rootProfile.PermittedDNSDomains,
		"extended_key_usages":   rootProfile.EKUs,
		"signature_algorithm":   "ecdsa-p256",
	}
	rootCeremony := createCACeremonyWithCertificate(t, h, operator, "import_offline_root", rootPEM, rootSpec, 2, "offline-root-ceremony")

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/offline-roots", operator, "offline-root-before-quorum", map[string]any{
		"ceremony_id":     rootCeremony.ID,
		"certificate_pem": rootPEM,
		"spec":            rootSpec,
	})
	if code != http.StatusConflict || !strings.Contains(string(body), "quorum") {
		t.Fatalf("offline root import before quorum = %d body=%s; want 409 quorum problem", code, body)
	}
	approveCACeremony(t, h, approverOne, rootCeremony.ID, 1, "offline-root-approval-one")
	approveCACeremony(t, h, approverTwo, rootCeremony.ID, 2, "offline-root-approval-two")
	root := importOfflineRootCA(t, h, operator, rootCeremony.ID, rootPEM, rootSpec, "offline-root-import")
	if root.Kind != "root" || root.SignerHandle != "" || root.CertificatePEM == "" {
		t.Fatalf("offline root = %+v; want imported public root with no signer handle", root)
	}

	leafCSRDER := hierarchyLeafCSR(t, "root-hotpath.offline.example.test")
	leafCSRPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: leafCSRDER}))
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/issue", operator, "offline-root-hotpath-issue", map[string]any{
		"csr_pem":     leafCSRPEM,
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("offline root hot-path leaf issue = %d body=%s; want 503 because root key is absent", code, body)
	}

	interSpec := map[string]any{
		"common_name":           "offline issuing intermediate",
		"max_path_len":          0,
		"ttl_seconds":           int64((30 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"offline.example.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	interCeremony := createCACeremony(t, h, operator, "create_offline_intermediate", root.ID, interSpec, 2, "offline-intermediate-ceremony")
	approveCACeremony(t, h, approverOne, interCeremony.ID, 1, "offline-intermediate-approval-one")
	approveCACeremony(t, h, approverTwo, interCeremony.ID, 2, "offline-intermediate-approval-two")
	csr := createOfflineIntermediateCSR(t, h, operator, root.ID, interCeremony.ID, interSpec, "offline-intermediate-csr")
	if csr.SignerHandle == "" || csr.ParentID != root.ID || csr.CSRPem == "" {
		t.Fatalf("offline intermediate CSR = %+v; want signer handle, parent id, and CSR PEM", csr)
	}
	csrDER := csrDERFromPEMForTest(t, csr.CSRPem)
	csrInfo, err := crypto.InspectCSR(csrDER)
	if err != nil {
		t.Fatalf("inspect offline intermediate CSR: %v", err)
	}
	if csrInfo.CommonName != interSpec["common_name"] {
		t.Fatalf("offline intermediate CSR CN = %q, want %q", csrInfo.CommonName, interSpec["common_name"])
	}
	offlineIntermediate, err := crypto.SignIntermediateHierarchyCAFromCSR(offlineRoot.CertificateDER, offlineRootKey, csrDER, crypto.HierarchyCAProfile{
		CommonName:          "offline issuing intermediate",
		MaxPathLen:          0,
		TTL:                 30 * 24 * time.Hour,
		PermittedDNSDomains: []string{"offline.example.test"},
		EKUs:                []string{"serverAuth"},
	})
	if err != nil {
		t.Fatalf("offline-sign intermediate CSR: %v", err)
	}
	inter := importOfflineIntermediateCA(t, h, operator, root.ID, interCeremony.ID, string(offlineIntermediate.CertificatePEM), interSpec, "offline-intermediate-import")
	if inter.Kind != "intermediate" || inter.ParentID == nil || *inter.ParentID != root.ID || inter.SignerHandle != csr.SignerHandle {
		t.Fatalf("offline intermediate = %+v; want child of offline root bound to CSR signer handle %q", inter, csr.SignerHandle)
	}

	leafCSRDER = hierarchyLeafCSR(t, "leaf.offline.example.test")
	leafCSRPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: leafCSRDER}))
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+inter.ID+"/issue", operator, "offline-intermediate-leaf", map[string]any{
		"csr_pem":     leafCSRPEM,
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if code != http.StatusCreated {
		t.Fatalf("issue leaf from offline-root intermediate = %d body=%s; want 201", code, body)
	}
	var issued struct {
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	if err := json.Unmarshal(body, &issued); err != nil || issued.CertificatePEM == "" || issued.Serial == "" {
		t.Fatalf("decode offline-root leaf: %v body=%s", err, body)
	}
	if err := crypto.VerifyLeafSignedByCA(caCertDER(t, []byte(issued.CertificatePEM)), caCertDER(t, []byte(inter.CertificatePEM))); err != nil {
		t.Fatalf("offline-root intermediate did not sign served leaf: %v", err)
	}
	if !h.hasEvent(t, "ca.root.created") || !h.hasEvent(t, "ca.intermediate_csr.issued") || !h.hasEvent(t, "ca.intermediate.created") || !h.hasEvent(t, "ca.endentity.issued") {
		t.Fatal("offline-root workflow did not emit the expected CA hierarchy events")
	}
}

func TestServedCAHierarchyImportsExistingSignerBackedChain(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	operator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "byo-ca-operator", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverOne := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "byo-ca-custodian-one", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})
	approverTwo := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "byo-ca-custodian-two", []string{
		"issuers:write", "issuers:read", "certs:issue",
	})

	externalRootKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(externalRootKey.Destroy)
	rootProfile := crypto.HierarchyCAProfile{
		CommonName:          "customer existing root",
		MaxPathLen:          1,
		TTL:                 365 * 24 * time.Hour,
		PermittedDNSDomains: []string{"imported.example.test"},
		EKUs:                []string{"serverAuth"},
	}
	externalRoot, err := crypto.SelfSignedHierarchyCA(externalRootKey, rootProfile)
	if err != nil {
		t.Fatalf("create external root fixture: %v", err)
	}

	client := h.signer.Client()
	importedHandle := "imported-existing-intermediate"
	importedSigner, err := client.GenerateDualControlKeyHandle(context.Background(), crypto.ECDSAP256, importedHandle,
		[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign, h.authz)
	if err != nil {
		t.Fatalf("pre-provision imported CA signer handle: %v", err)
	}
	wrongHandle := "imported-existing-wrong"
	wrongSigner, err := client.GenerateDualControlKeyHandle(context.Background(), crypto.ECDSAP256, wrongHandle,
		[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign, h.authz)
	if err != nil || wrongSigner == nil {
		t.Fatalf("pre-provision wrong signer handle: %v", err)
	}
	interProfile := crypto.HierarchyCAProfile{
		CommonName:          "customer existing issuing ca",
		MaxPathLen:          0,
		TTL:                 30 * 24 * time.Hour,
		PermittedDNSDomains: []string{"imported.example.test"},
		EKUs:                []string{"serverAuth"},
	}
	existingIntermediate, err := crypto.SignIntermediateHierarchyCA(externalRoot.CertificateDER, externalRootKey, importedSigner.Public(), interProfile)
	if err != nil {
		t.Fatalf("create externally signed intermediate fixture: %v", err)
	}
	chainPEM := string(existingIntermediate.CertificatePEM) + string(externalRoot.CertificatePEM)
	interSpec := map[string]any{
		"common_name":           interProfile.CommonName,
		"max_path_len":          interProfile.MaxPathLen,
		"ttl_seconds":           int64(interProfile.TTL.Seconds()),
		"permitted_dns_domains": interProfile.PermittedDNSDomains,
		"extended_key_usages":   interProfile.EKUs,
		"signature_algorithm":   "ecdsa-p256",
	}

	wrongCeremony := createImportExistingCACeremony(t, h, operator, chainPEM, wrongHandle, interSpec, 1, "byo-ca-wrong-ceremony")
	approveCACeremony(t, h, approverOne, wrongCeremony.ID, 1, "byo-ca-wrong-approval")
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported", operator, "byo-ca-wrong-import", map[string]any{
		"ceremony_id":     wrongCeremony.ID,
		"certificate_pem": chainPEM,
		"signer_handle":   wrongHandle,
		"spec":            interSpec,
	})
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "public key") {
		t.Fatalf("import existing CA with wrong signer = %d body=%s; want 422 public-key mismatch", code, body)
	}

	ceremony := createImportExistingCACeremony(t, h, operator, chainPEM, importedHandle, interSpec, 2, "byo-ca-ceremony")
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported", operator, "byo-ca-before-quorum", map[string]any{
		"ceremony_id":     ceremony.ID,
		"certificate_pem": chainPEM,
		"signer_handle":   importedHandle,
		"spec":            interSpec,
	})
	if code != http.StatusConflict || !strings.Contains(string(body), "quorum") {
		t.Fatalf("import existing CA before quorum = %d body=%s; want 409 quorum problem", code, body)
	}
	approveCACeremony(t, h, approverOne, ceremony.ID, 1, "byo-ca-approval-one")
	approveCACeremony(t, h, approverTwo, ceremony.ID, 2, "byo-ca-approval-two")
	imported := importExistingCA(t, h, operator, ceremony.ID, chainPEM, importedHandle, interSpec, "byo-ca-import")
	if imported.Kind != "intermediate" || imported.SignerHandle != importedHandle || imported.CommonName != interProfile.CommonName {
		t.Fatalf("imported CA = %+v; want signer-backed existing intermediate", imported)
	}
	if strings.Contains(imported.CertificatePEM, "PRIVATE KEY") || strings.Count(imported.CertificatePEM, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("imported CA certificate response leaked key material or lost chain: %q", imported.CertificatePEM)
	}

	leafCSRDER := hierarchyLeafCSR(t, "leaf.imported.example.test")
	leafCSRPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: leafCSRDER}))
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+imported.ID+"/issue", operator, "byo-ca-leaf", map[string]any{
		"csr_pem":     leafCSRPEM,
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if code != http.StatusCreated {
		t.Fatalf("issue leaf from imported existing CA = %d body=%s; want 201", code, body)
	}
	var issued struct {
		CertificatePEM string `json:"certificate_pem"`
		Serial         string `json:"serial"`
	}
	if err := json.Unmarshal(body, &issued); err != nil || issued.CertificatePEM == "" || issued.Serial == "" {
		t.Fatalf("decode imported-CA leaf: %v body=%s", err, body)
	}
	if err := crypto.VerifyLeafSignedByCA(caCertDER(t, []byte(issued.CertificatePEM)), caCertDER(t, []byte(imported.CertificatePEM))); err != nil {
		t.Fatalf("imported existing CA did not sign served leaf: %v", err)
	}
	if !h.hasEvent(t, "ca.authority.imported") || !h.hasEvent(t, "ca.endentity.issued") {
		t.Fatal("imported existing CA workflow did not emit the expected events")
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

type servedCAIntermediateCSR struct {
	CeremonyID   string `json:"ceremony_id"`
	ParentID     string `json:"parent_id"`
	CSRPem       string `json:"csr_pem"`
	SignerHandle string `json:"signer_handle"`
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

func createCACeremonyWithCertificate(t *testing.T, h *servedHarness, token, operation, certificatePEM string, spec map[string]any, threshold int, idem string) servedCACeremony {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", token, idem, map[string]any{
		"operation":       operation,
		"certificate_pem": certificatePEM,
		"threshold":       threshold,
		"spec":            spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("create %s ceremony = %d body=%s; want 201", operation, code, raw)
	}
	var got servedCACeremony
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" || got.Threshold != threshold || got.Status != "pending" {
		t.Fatalf("decode %s ceremony: %v got=%+v body=%s", operation, err, got, raw)
	}
	return got
}

func createImportExistingCACeremony(t *testing.T, h *servedHarness, token, certificatePEM, signerHandle string, spec map[string]any, threshold int, idem string) servedCACeremony {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", token, idem, map[string]any{
		"operation":       "import_existing_ca",
		"certificate_pem": certificatePEM,
		"signer_handle":   signerHandle,
		"threshold":       threshold,
		"spec":            spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("create import_existing_ca ceremony = %d body=%s; want 201", code, raw)
	}
	var got servedCACeremony
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" || got.Threshold != threshold || got.Status != "pending" {
		t.Fatalf("decode import_existing_ca ceremony: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func createCACeremonyWithCSR(t *testing.T, h *servedHarness, token, parentID, csrPEM string, spec map[string]any, threshold int, idem string) servedCACeremony {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", token, idem, map[string]any{
		"operation": "issue_intermediate_csr",
		"parent_id": parentID,
		"csr_pem":   csrPEM,
		"threshold": threshold,
		"spec":      spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("create issue_intermediate_csr ceremony = %d body=%s; want 201", code, raw)
	}
	var got servedCACeremony
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" || got.Threshold != threshold || got.Status != "pending" {
		t.Fatalf("decode issue_intermediate_csr ceremony: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func importExistingCA(t *testing.T, h *servedHarness, token, ceremonyID, certificatePEM, signerHandle string, spec map[string]any, idem string) servedCAAuthority {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported", token, idem, map[string]any{
		"ceremony_id":     ceremonyID,
		"certificate_pem": certificatePEM,
		"signer_handle":   signerHandle,
		"spec":            spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("import existing CA = %d body=%s; want 201", code, raw)
	}
	var got servedCAAuthority
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" {
		t.Fatalf("decode imported existing CA: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func importOfflineRootCA(t *testing.T, h *servedHarness, token, ceremonyID, certificatePEM string, spec map[string]any, idem string) servedCAAuthority {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/offline-roots", token, idem, map[string]any{
		"ceremony_id":     ceremonyID,
		"certificate_pem": certificatePEM,
		"spec":            spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("import offline root CA = %d body=%s; want 201", code, raw)
	}
	var got servedCAAuthority
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" {
		t.Fatalf("decode offline root CA: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func createOfflineIntermediateCSR(t *testing.T, h *servedHarness, token, parentID, ceremonyID string, spec map[string]any, idem string) servedCAIntermediateCSR {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+parentID+"/offline-intermediates/csr", token, idem, map[string]any{
		"ceremony_id": ceremonyID,
		"spec":        spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("create offline intermediate CSR = %d body=%s; want 201", code, raw)
	}
	var got servedCAIntermediateCSR
	if err := json.Unmarshal(raw, &got); err != nil || got.CSRPem == "" || got.SignerHandle == "" {
		t.Fatalf("decode offline intermediate CSR: %v got=%+v body=%s", err, got, raw)
	}
	return got
}

func importOfflineIntermediateCA(t *testing.T, h *servedHarness, token, parentID, ceremonyID, certificatePEM string, spec map[string]any, idem string) servedCAAuthority {
	t.Helper()
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+parentID+"/offline-intermediates", token, idem, map[string]any{
		"ceremony_id":     ceremonyID,
		"certificate_pem": certificatePEM,
		"spec":            spec,
	})
	if code != http.StatusCreated {
		t.Fatalf("import offline intermediate CA = %d body=%s; want 201", code, raw)
	}
	var got servedCAAuthority
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" {
		t.Fatalf("decode offline intermediate CA: %v got=%+v body=%s", err, got, raw)
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

func hierarchyLeafCSR(t *testing.T, dnsName string) []byte {
	t.Helper()
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: dnsName,
		DNSNames:   []string{dnsName},
	}, leafKey)
	if err != nil {
		t.Fatalf("create hierarchy leaf CSR: %v", err)
	}
	return csrDER
}

func csrDERFromPEMForTest(t *testing.T, csrPEM string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("CSR PEM = %q, want CERTIFICATE REQUEST block", csrPEM)
	}
	return block.Bytes
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
