package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAuthCallbackRejectsMissingNonce: the OIDC callback must reject a request
// that carries no nonce cookie, rather than proceeding with an empty (skipped)
// nonce — closing the replay window (B1's OIDC-nonce major).
func TestAuthCallbackRejectsMissingNonce(t *testing.T) {
	h, _ := authAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=good-code&state=s-123", nil)
	req.AddCookie(&http.Cookie{Name: "trustctl_oidc_state", Value: "s-123"})
	// Deliberately NO trustctl_oidc_nonce cookie.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusFound {
		t.Fatalf("callback without a nonce cookie returned 302 (it must be rejected): %s", rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "trustctl_session" && c.Value != "" {
			t.Fatal("callback without a nonce cookie established a session")
		}
	}
}
