package oauthgrant

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFindingsNormalizesOAuthGrantMetadata(t *testing.T) {
	findings, err := Findings(json.RawMessage(`{
		"grants":[
			{
				"provider":"okta",
				"app_id":"0oa-payments",
				"app_name":"Payments BI Export",
				"principal":"payments-bi-export",
				"resource":"google-workspace",
				"scopes":["drive.readonly","admin.directory.user.readonly","drive.readonly"],
				"consent_type":"admin",
				"third_party":true,
				"owner":"finance-platform",
				"redirect_uris":["https://example.invalid/callback","https://example.invalid/callback"]
			}
		]
	}`))
	if err != nil {
		t.Fatalf("Findings returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Ref != "payments-bi-export" || f.Provenance != "oauth_grant:okta:0oa-payments:google-workspace" {
		t.Fatalf("unexpected finding identity: %+v", f)
	}
	if f.Fingerprint != f.Provenance {
		t.Fatalf("fingerprint = %q, want provenance", f.Fingerprint)
	}
	if f.RiskScore < 80 {
		t.Fatalf("risk score = %d, want sensitive third-party admin grant score", f.RiskScore)
	}
	scopes, ok := f.Metadata["scopes"].([]string)
	if !ok || len(scopes) != 2 {
		t.Fatalf("scopes metadata = %#v, want deduplicated []string", f.Metadata["scopes"])
	}
	redirectURIs, ok := f.Metadata["redirect_uris"].([]string)
	if !ok || len(redirectURIs) != 1 {
		t.Fatalf("redirect_uris metadata = %#v, want deduplicated []string", f.Metadata["redirect_uris"])
	}
}

func TestFindingsRejectsMissingScopeDenominator(t *testing.T) {
	_, err := Findings(json.RawMessage(`{
		"grants":[{"provider":"okta","app_id":"0oa-payments","resource":"google-workspace"}]
	}`))
	if err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatalf("Findings error = %v, want missing scope rejection", err)
	}
}
