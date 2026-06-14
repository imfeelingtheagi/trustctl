package authmethod

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/crypto"
)

func TestTokenMethodLoginAndReject(t *testing.T) {
	secret := []byte("s3cret")
	mac := hex.EncodeToString(crypto.HMACSHA256(secret, []byte("app1")))
	rec := &auditsink.Recorder{}
	m, _ := New(Config{TenantID: "t1", Audit: rec, Methods: []Method{
		TokenMethod{Secret: secret, Scopes: map[string][]string{"app1": {"read:db"}}},
	}})
	sess, err := m.Login(context.Background(), "token", []byte("app1."+mac))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if sess.TenantID != "t1" || sess.Principal != "app1" || len(sess.Scopes) != 1 {
		t.Errorf("session = %+v", sess)
	}
	if _, err := m.Login(context.Background(), "token", []byte("app1.deadbeef")); err == nil {
		t.Error("invalid token MAC accepted")
	}
	if rec.Count("auth.rejected") != 1 || rec.Count("auth.session.issued") != 1 {
		t.Error("auth events not audited as expected")
	}
}

func TestOIDCMethodLoginAndReject(t *testing.T) {
	signer, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer signer.Destroy()
	jwk, _ := crypto.PublicJWK(signer.Public(), "k1")
	jwks := crypto.JWKS{Keys: []crypto.JWK{jwk}}
	tok, _ := crypto.SignJWT(signer, "k1", map[string]any{
		"iss": "https://idp", "aud": "trustctl", "sub": "svc-1",
		"exp": time.Now().Add(time.Hour).Unix(), "scopes": []string{"read"},
	})
	m, _ := New(Config{TenantID: "t1", Methods: []Method{OIDCMethod{JWKS: jwks, Issuer: "https://idp", Audience: "trustctl"}}})
	sess, err := m.Login(context.Background(), "oidc", []byte(tok))
	if err != nil {
		t.Fatalf("OIDC login: %v", err)
	}
	if sess.Principal != "svc-1" {
		t.Errorf("principal = %q", sess.Principal)
	}
	attacker, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer attacker.Destroy()
	forged, _ := crypto.SignJWT(attacker, "k1", map[string]any{"iss": "https://idp", "aud": "trustctl", "sub": "evil", "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := m.Login(context.Background(), "oidc", []byte(forged)); err == nil {
		t.Error("forged OIDC token accepted")
	}
}

// TestOIDCExpIsMandatory is the GAP-002 acceptance: an OIDC/JWT with no exp
// claim (or exp==0) is an indefinite, replayable machine login and must be
// rejected; an expired token must be rejected; a valid bounded token must be
// accepted. The no-exp case fails pre-fix (the old guard only checked exp when
// present) and passes post-fix.
func TestOIDCExpIsMandatory(t *testing.T) {
	signer, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer signer.Destroy()
	jwk, _ := crypto.PublicJWK(signer.Public(), "k1")
	jwks := crypto.JWKS{Keys: []crypto.JWK{jwk}}
	m, _ := New(Config{TenantID: "t1", Methods: []Method{OIDCMethod{JWKS: jwks, Issuer: "https://idp", Audience: "trustctl"}}})

	base := map[string]any{"iss": "https://idp", "aud": "trustctl", "sub": "svc-noexp", "scopes": []string{"admin"}}

	// 1) No exp claim at all -> rejected.
	noExp, _ := crypto.SignJWT(signer, "k1", base)
	if _, err := m.Login(context.Background(), "oidc", []byte(noExp)); err == nil {
		t.Error("OIDC token with no exp claim was accepted (indefinite, replayable login)")
	}

	// 2) exp explicitly 0 -> rejected.
	withZero := map[string]any{}
	for k, v := range base {
		withZero[k] = v
	}
	withZero["exp"] = 0
	zeroExp, _ := crypto.SignJWT(signer, "k1", withZero)
	if _, err := m.Login(context.Background(), "oidc", []byte(zeroExp)); err == nil {
		t.Error("OIDC token with exp=0 was accepted")
	}

	// 3) Expired exp -> rejected.
	expired := map[string]any{}
	for k, v := range base {
		expired[k] = v
	}
	expired["exp"] = time.Now().Add(-time.Hour).Unix()
	expiredTok, _ := crypto.SignJWT(signer, "k1", expired)
	if _, err := m.Login(context.Background(), "oidc", []byte(expiredTok)); err == nil {
		t.Error("expired OIDC token was accepted")
	}

	// 4) Valid bounded exp -> accepted.
	valid := map[string]any{}
	for k, v := range base {
		valid[k] = v
	}
	valid["sub"] = "svc-1"
	valid["exp"] = time.Now().Add(time.Hour).Unix()
	validTok, _ := crypto.SignJWT(signer, "k1", valid)
	sess, err := m.Login(context.Background(), "oidc", []byte(validTok))
	if err != nil {
		t.Fatalf("valid bounded OIDC token rejected: %v", err)
	}
	if sess.Principal != "svc-1" {
		t.Errorf("principal = %q, want svc-1", sess.Principal)
	}
}

func TestUnknownMethodRejected(t *testing.T) {
	m, _ := New(Config{TenantID: "t1"})
	if _, err := m.Login(context.Background(), "nope", nil); err == nil {
		t.Error("unknown method accepted")
	}
}
