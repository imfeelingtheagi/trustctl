package api

import (
	"encoding/json"
	"testing"
)

func TestValidateDiscoverySourceRequiresCredentialReferences(t *testing.T) {
	_, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind: "cloud_certificate",
		Name: "bad-inline-cloud-credential",
		Config: json.RawMessage(`{
			"providers":[{
				"provider":"aws-acm",
				"region":"us-east-1",
				"secret_access_key":"inline-secret"
			}]
		}`),
	})
	if err == nil {
		t.Fatal("inline cloud credential material must be rejected; use *_ref fields")
	}

	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind: "cloud_certificate",
		Name: "good-referenced-cloud-credential",
		Config: json.RawMessage(`{
			"providers":[{
				"provider":"aws-acm",
				"region":"us-east-1",
				"access_key_id_ref":"env:AWS_ACCESS_KEY_ID",
				"secret_access_key_ref":"env:AWS_SECRET_ACCESS_KEY"
			}]
		}`),
	}); err != nil {
		t.Fatalf("credential-reference cloud config was rejected: %v", err)
	}
}
