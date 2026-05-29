package acme_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	acmesrv "certctl.io/certctl/internal/protocols/acme"
)

// TestHTTP01Validator validates the real http-01 check against a server serving
// the key authorization, and rejects a wrong one.
func TestHTTP01Validator(t *testing.T) {
	const token = "tok-123"
	const keyAuth = "tok-123.thumbprint"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/acme-challenge/"+token {
			_, _ = w.Write([]byte(keyAuth))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)
	domain := strings.TrimPrefix(ts.URL, "http://") // host:port the validator will dial

	v := acmesrv.HTTP01Validator{}
	if err := v.Validate(context.Background(), acmesrv.ChallengeHTTP01, domain, token, keyAuth); err != nil {
		t.Errorf("valid http-01 rejected: %v", err)
	}
	if err := v.Validate(context.Background(), acmesrv.ChallengeHTTP01, domain, token, "wrong-key-auth"); err == nil {
		t.Error("http-01 accepted a mismatched key authorization")
	}
}
