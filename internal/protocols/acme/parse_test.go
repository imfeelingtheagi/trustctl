package acme_test

import (
	"encoding/base64"
	"testing"

	acmesrv "certctl.io/certctl/internal/protocols/acme"
)

func TestParseOrderRequest(t *testing.T) {
	good := []byte(`{"identifiers":[{"type":"dns","value":"a.example"},{"type":"dns","value":"b.example"}]}`)
	req, err := acmesrv.ParseOrderRequest(good)
	if err != nil {
		t.Fatalf("valid order rejected: %v", err)
	}
	if got := req.Domains(); len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Fatalf("domains = %v", got)
	}

	// notBefore/notAfter and other unknown fields are tolerated (RFC 8555).
	if _, err := acmesrv.ParseOrderRequest([]byte(`{"identifiers":[{"type":"dns","value":"x"}],"notBefore":"2026-01-01T00:00:00Z"}`)); err != nil {
		t.Fatalf("order with notBefore rejected: %v", err)
	}

	bad := []struct {
		name string
		json string
	}{
		{"not json", `}{`},
		{"no identifiers field", `{}`},
		{"empty identifiers", `{"identifiers":[]}`},
		{"non-dns type", `{"identifiers":[{"type":"ip","value":"10.0.0.1"}]}`},
		{"empty value", `{"identifiers":[{"type":"dns","value":""}]}`},
		{"invalid replaces", `{"identifiers":[{"type":"dns","value":"x"}],"replaces":"!!!not-a-certid!!!"}`},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := acmesrv.ParseOrderRequest([]byte(tc.json)); err == nil {
				t.Fatalf("expected %s to be rejected, got nil", tc.name)
			}
		})
	}
}

func TestParseFinalizeRequest(t *testing.T) {
	der := []byte{0x30, 0x82, 0x01, 0x02} // arbitrary non-empty bytes
	good := `{"csr":"` + base64.RawURLEncoding.EncodeToString(der) + `"}`
	got, err := acmesrv.ParseFinalizeRequest([]byte(good))
	if err != nil {
		t.Fatalf("valid finalize rejected: %v", err)
	}
	if string(got) != string(der) {
		t.Fatalf("csr = %x, want %x", got, der)
	}

	for _, tc := range []struct{ name, json string }{
		{"not json", `nope`},
		{"missing csr", `{}`},
		{"empty csr", `{"csr":""}`},
		{"std base64 not url", `{"csr":"++//=="}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := acmesrv.ParseFinalizeRequest([]byte(tc.json)); err == nil {
				t.Fatalf("expected %s to be rejected, got nil", tc.name)
			}
		})
	}
}

// FuzzParseOrderRequest fuzzes the newOrder payload parser — the parser the
// server runs on every untrusted order body — for panics and to confirm it
// always fails closed (never returns a malformed-but-nil-error order). (B9/N3.)
func FuzzParseOrderRequest(f *testing.F) {
	f.Add([]byte(`{"identifiers":[{"type":"dns","value":"example.com"}]}`))
	f.Add([]byte(`{"identifiers":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"identifiers":[{"type":"dns","value":"x"}],"replaces":"abc"}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"identifiers":[{"type":"dns","value":""}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := acmesrv.ParseOrderRequest(data)
		if err != nil {
			return
		}
		// On success every identifier must be a non-empty dns identifier.
		if len(req.Identifiers) == 0 {
			t.Fatalf("accepted an order with no identifiers: %q", data)
		}
		for _, id := range req.Identifiers {
			if id.Type != "dns" || id.Value == "" {
				t.Fatalf("accepted a bad identifier %+v from %q", id, data)
			}
		}
	})
}

// FuzzParseFinalizeRequest fuzzes the finalize payload parser for panics and to
// confirm it never returns an empty CSR with a nil error.
func FuzzParseFinalizeRequest(f *testing.F) {
	f.Add([]byte(`{"csr":"MIIBAg"}`))
	f.Add([]byte(`{"csr":""}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`garbage`))
	f.Fuzz(func(t *testing.T, data []byte) {
		der, err := acmesrv.ParseFinalizeRequest(data)
		if err != nil {
			return
		}
		if len(der) == 0 {
			t.Fatalf("accepted an empty CSR with nil error from %q", data)
		}
	})
}
