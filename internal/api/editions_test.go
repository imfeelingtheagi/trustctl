package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
)

type editionsTestResponse struct {
	license.Info
	FIPS struct {
		ModuleActive                 bool     `json:"module_active"`
		Required                     bool     `json:"required"`
		SelfTestPassed               bool     `json:"self_test_passed"`
		CapabilityID                 string   `json:"capability_id"`
		ValidatedModulePath          bool     `json:"validated_module_path"`
		Standard                     string   `json:"standard"`
		Module                       string   `json:"module"`
		BuildTarget                  string   `json:"build_target"`
		RuntimeActivation            []string `json:"runtime_activation"`
		CIGate                       string   `json:"ci_gate"`
		CryptoBoundary               string   `json:"crypto_boundary"`
		ProductCertificationResidual string   `json:"product_certification_residual"`
	} `json:"fips"`
}

func TestEditionsEndpointReturnsCommunityAndFIPSPosture(t *testing.T) {
	var got editionsTestResponse
	getEditions(t, api.New(nil, nil, nil), &got)

	if got.Tier != license.TierCommunity || got.State != license.StateCommunity {
		t.Fatalf("community editions header = tier %s state %s", got.Tier, got.State)
	}
	assertEditionsFeature(t, got.Features, license.FeatureFIPS, license.TierEnterprise, false, license.ModeOff)
	if got.FIPS.ModuleActive != crypto.FIPSEnabled() {
		t.Fatalf("fips.module_active=%t, want crypto.FIPSEnabled()=%t", got.FIPS.ModuleActive, crypto.FIPSEnabled())
	}
	if got.FIPS.Required {
		t.Fatal("editions posture must not turn FIPS into a runtime license requirement")
	}
	if !got.FIPS.SelfTestPassed {
		t.Fatal("editions posture must report the crypto power-on self-test result")
	}
}

func TestEditionsEndpointServesCAPKEY03ValidatedModulePath(t *testing.T) {
	var got editionsTestResponse
	getCanonicalEditions(t, api.New(nil, nil, nil), &got)

	if got.FIPS.CapabilityID != "CAP-KEY-03" {
		t.Fatalf("fips.capability_id=%q, want CAP-KEY-03", got.FIPS.CapabilityID)
	}
	if !got.FIPS.ValidatedModulePath {
		t.Fatalf("fips.validated_module_path=false; FIPS validated-module path is not served: %+v", got.FIPS)
	}
	for _, want := range []string{
		"FIPS 140-3",
		"Go Cryptographic Module",
		"make fips-build",
		"fips-capable build (GOFIPS140)",
	} {
		if !fipsPostureContains(got.FIPS, want) {
			t.Fatalf("served FIPS posture missing %q: %+v", want, got.FIPS)
		}
	}
	if !fipsPostureContains(got.FIPS, "internal/crypto") {
		t.Fatalf("served FIPS posture must identify the AN-3 crypto boundary: %+v", got.FIPS)
	}
	residual := strings.ToLower(got.FIPS.ProductCertificationResidual)
	if !strings.Contains(residual, "product nist cmvp certificate") || !strings.Contains(residual, "external residual") {
		t.Fatalf("served FIPS posture must keep product CMVP certification as an external residual, got %q", got.FIPS.ProductCertificationResidual)
	}
}

func TestEditionsEndpointReturnsLoadedLicense(t *testing.T) {
	mgr := testLicenseManager(t, license.TierEnterprise)
	var got editionsTestResponse
	getEditions(t, api.New(nil, nil, nil, api.WithLicense(mgr)), &got)

	if got.Tier != license.TierEnterprise || got.State != license.StateActive {
		t.Fatalf("licensed editions header = tier %s state %s", got.Tier, got.State)
	}
	if got.Customer != "Acme Robotics" || got.LicenseID != "lic_test_editions" {
		t.Fatalf("licensed identity fields missing: %+v", got.Info)
	}
	assertEditionsFeature(t, got.Features, license.FeatureFIPS, license.TierEnterprise, true, license.ModeEnabled)
}

func getEditions(t *testing.T, h http.Handler, out *editionsTestResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/editions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/editions = %d, body %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode editions response: %v", err)
	}
}

func getCanonicalEditions(t *testing.T, h http.Handler, out *editionsTestResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/editions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/editions = %d, body %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode editions response: %v", err)
	}
}

func fipsPostureContains(fips struct {
	ModuleActive                 bool     `json:"module_active"`
	Required                     bool     `json:"required"`
	SelfTestPassed               bool     `json:"self_test_passed"`
	CapabilityID                 string   `json:"capability_id"`
	ValidatedModulePath          bool     `json:"validated_module_path"`
	Standard                     string   `json:"standard"`
	Module                       string   `json:"module"`
	BuildTarget                  string   `json:"build_target"`
	RuntimeActivation            []string `json:"runtime_activation"`
	CIGate                       string   `json:"ci_gate"`
	CryptoBoundary               string   `json:"crypto_boundary"`
	ProductCertificationResidual string   `json:"product_certification_residual"`
}, want string) bool {
	lowWant := strings.ToLower(want)
	for _, candidate := range append([]string{
		fips.Standard,
		fips.Module,
		fips.BuildTarget,
		fips.CIGate,
		fips.CryptoBoundary,
		fips.ProductCertificationResidual,
	}, fips.RuntimeActivation...) {
		if strings.Contains(strings.ToLower(candidate), lowWant) {
			return true
		}
	}
	return false
}

func testLicenseManager(t *testing.T, tier license.Tier) *license.Manager {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := license.Sign(license.Claims{
		V:         1,
		ID:        "lic_test_editions",
		Customer:  "Acme Robotics",
		Tier:      tier,
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := license.Load(path, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

func assertEditionsFeature(t *testing.T, features []license.FeatureInfo, name license.Feature, tier license.Tier, licensed bool, mode license.Mode) {
	t.Helper()
	for _, f := range features {
		if f.Name == name {
			if f.Tier != tier || f.Licensed != licensed || f.Mode != mode {
				t.Fatalf("feature %s row = %+v, want tier=%s licensed=%t mode=%s", name, f, tier, licensed, mode)
			}
			return
		}
	}
	t.Fatalf("feature %s row missing from %+v", name, features)
}
