package profile_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trustctl.io/trustctl/internal/profile"
)

func webProfile() profile.CertificateProfile {
	return profile.CertificateProfile{
		Name: "web-server", Version: 3,
		AllowedKeyAlgorithms: []string{"ECDSA", "RSA"},
		MinRSABits:           3072,
		MinECDSABits:         256,
		AllowedEKUs:          []string{"serverAuth"},
		MaxValidity:          profile.Duration(90 * 24 * time.Hour),
		AllowedProtocols:     []string{"api", "acme"},
		AllowedDNSSuffixes:   []string{"example.com"},
	}
}

func TestProfileAcceptsCompliantRequest(t *testing.T) {
	r := profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, RequestedEKUs: []string{"serverAuth"},
		TTL: 30 * 24 * time.Hour, DNSNames: []string{"api.example.com"}, Protocol: "acme"}
	if err := webProfile().Validate(r); err != nil {
		t.Fatalf("compliant request should pass, got %v", err)
	}
}

func TestProfileRejectsDisallowedKeyAlgorithm(t *testing.T) {
	err := webProfile().Validate(profile.Request{KeyAlgorithm: "Ed25519", KeyBits: 256, Protocol: "api"})
	if err == nil || !strings.Contains(err.Error(), "key algorithm") {
		t.Fatalf("want key-algorithm rejection, got %v", err)
	}
}

func TestProfileRejectsWeakRSAKey(t *testing.T) {
	err := webProfile().Validate(profile.Request{KeyAlgorithm: "RSA", KeyBits: 2048, Protocol: "api"})
	if err == nil || !strings.Contains(err.Error(), "RSA") {
		t.Fatalf("want weak-RSA rejection, got %v", err)
	}
}

func TestProfileRejectsDisallowedEKU(t *testing.T) {
	err := webProfile().Validate(profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, RequestedEKUs: []string{"codeSigning"}, Protocol: "api"})
	if err == nil || !strings.Contains(err.Error(), "extended key usage") {
		t.Fatalf("want EKU rejection, got %v", err)
	}
}

func TestProfileRejectsOverLongValidity(t *testing.T) {
	err := webProfile().Validate(profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, TTL: 365 * 24 * time.Hour, Protocol: "api"})
	if err == nil || !strings.Contains(err.Error(), "caps validity") {
		t.Fatalf("want validity rejection, got %v", err)
	}
}

func TestProfileRejectsDisallowedProtocolAndDNS(t *testing.T) {
	if err := webProfile().Validate(profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, Protocol: "scep"}); err == nil {
		t.Error("scep is not an allowed protocol; want rejection")
	}
	if err := webProfile().Validate(profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, Protocol: "api", DNSNames: []string{"api.evil.test"}}); err == nil {
		t.Error("evil.test is outside the allowed suffix; want rejection")
	}
}

func TestProfileJSONRoundTrip(t *testing.T) {
	p := webProfile()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"2160h0m0s"`) {
		t.Errorf("max_validity should serialize as a duration string: %s", b)
	}
	var got profile.CertificateProfile
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if time.Duration(got.MaxValidity) != 90*24*time.Hour {
		t.Errorf("round-trip validity = %s, want 2160h", time.Duration(got.MaxValidity))
	}
}
