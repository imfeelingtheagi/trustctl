package api

import (
	"context"
	"net/http"
	"time"

	"trustctl.io/trustctl/internal/api/problem"
	"trustctl.io/trustctl/internal/auth"
	"trustctl.io/trustctl/internal/crypto"
)

// Cookie names for the browser OIDC login + session flow.
const (
	sessionCookieName = "trustctl_session"
	stateCookieName   = "trustctl_oidc_state"
	nonceCookieName   = "trustctl_oidc_nonce"
	// csrfCookieName carries the double-submit CSRF token. Unlike the session
	// cookie it is NOT HttpOnly: the SPA reads it and echoes it in the
	// X-CSRF-Token header on every mutating request, which a cross-site attacker
	// cannot do (they can ride the cookie but cannot read it to set the header).
	csrfCookieName = "trustctl_csrf"
	// csrfHeaderName is the header the SPA echoes the CSRF token in.
	csrfHeaderName = "X-CSRF-Token"
)

// AuthConfig configures the browser OIDC login and session bridge the web UI
// uses (F12). The OIDC machinery itself is S3.6's: the code exchange and
// id_token verification are seams so production wires the real provider while
// tests inject fakes.
type AuthConfig struct {
	AuthEndpoint  string // provider authorization endpoint
	ClientID      string
	RedirectURI   string   // this server's /auth/callback URL, registered with the provider
	DefaultTenant string   // tenant assigned to a logged-in user (until per-user mapping lands)
	DefaultRoles  []string // RBAC roles a logged-in OIDC user receives (until per-user mapping lands)
	// Exchange swaps an authorization code for an id_token at the provider.
	Exchange func(ctx context.Context, code string) (idToken string, err error)
	// VerifyIDToken validates an id_token against the expected nonce and returns
	// its claims (production: auth.OIDCVerifier.Verify).
	VerifyIDToken func(idToken, nonce string) (auth.Claims, error)
	Sessions      *auth.SessionIssuer
	LoginRedirect string // where to send the browser after login (default "/")
	Secure        bool   // set the Secure flag on cookies (true behind TLS)
}

type meResponse struct {
	Subject  string `json:"subject"`
	TenantID string `json:"tenant_id"`
	Email    string `json:"email,omitempty"`
}

// authLogin starts the OIDC flow: it sets short-lived state and nonce cookies
// and redirects the browser to the provider.
func (a *API) authLogin(w http.ResponseWriter, r *http.Request) {
	state, err := auth.RandomState()
	if err != nil {
		a.writeError(w, err)
		return
	}
	nonce, err := auth.RandomState()
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.setTransientCookie(w, stateCookieName, state)
	a.setTransientCookie(w, nonceCookieName, nonce)
	url := auth.AuthCodeURL(a.auth.AuthEndpoint, a.auth.ClientID, a.auth.RedirectURI, state, nonce)
	http.Redirect(w, r, url, http.StatusFound)
}

// authCallback completes the flow: verify state, exchange the code, verify the
// id_token against the nonce, mint a session, and redirect to the UI.
func (a *API) authCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil || stateCookie.Value == "" || stateCookie.Value != q.Get("state") {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid OIDC state"))
		return
	}
	code := q.Get("code")
	if code == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "missing authorization code"))
		return
	}
	idToken, err := a.auth.Exchange(r.Context(), code)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadGateway, "token exchange failed"))
		return
	}
	// The nonce cookie is mandatory: without it, verification cannot bind the
	// id_token to this login attempt, so reject rather than proceed with an empty
	// (skipped) nonce (closing the replay window).
	nonceCookie, err := r.Cookie(nonceCookieName)
	if err != nil || nonceCookie.Value == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "missing OIDC nonce"))
		return
	}
	claims, err := a.auth.VerifyIDToken(idToken, nonceCookie.Value)
	if err != nil {
		a.writeError(w, errStatus(http.StatusUnauthorized, "id_token verification failed"))
		return
	}
	token, err := a.auth.Sessions.Issue(claims.Subject, a.auth.DefaultTenant, claims.Email, a.auth.DefaultRoles)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.setSessionCookie(w, token)
	// Issue a fresh double-submit CSRF token bound to this session (SEC-007). The SPA
	// reads it from the non-HttpOnly cookie and echoes it in X-CSRF-Token on every
	// mutating request; enforceCSRF rejects a session-authenticated mutation whose
	// header does not match the cookie, so a cross-site forged POST (which cannot read
	// the cookie to set the header) fails closed.
	csrf, err := auth.RandomState()
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.setCSRFCookie(w, csrf)
	a.clearCookie(w, stateCookieName)
	a.clearCookie(w, nonceCookieName)
	redirect := a.auth.LoginRedirect
	if redirect == "" {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// authMe returns the current session's principal, or 401 if unauthenticated.
func (a *API) authMe(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.sessionFrom(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	a.writeJSON(w, http.StatusOK, meResponse{Subject: sess.Subject, TenantID: sess.TenantID, Email: sess.Email})
}

// authLogout clears the session and CSRF cookies.
func (a *API) authLogout(w http.ResponseWriter, _ *http.Request) {
	a.clearCookie(w, sessionCookieName)
	a.clearCookie(w, csrfCookieName)
	w.WriteHeader(http.StatusNoContent)
}

// enforceCSRF implements double-submit CSRF protection for the cookie-session path
// (SEC-007). It applies ONLY to requests authenticated by the session cookie: a
// bearer-token (Authorization header) request is CSRF-immune (a browser does not
// attach the header cross-site) and is exempt, as are safe methods (GET/HEAD/
// OPTIONS, which must not mutate). For a session-authenticated mutating request it
// requires the X-CSRF-Token header to be present and to constant-time-equal the
// trustctl_csrf cookie; a cross-site attacker can ride the session cookie but
// cannot read the CSRF cookie to set the header, so a forged POST is rejected. It
// returns true when the request may proceed and false (after writing 403) otherwise.
func (a *API) enforceCSRF(w http.ResponseWriter, r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	// Bearer-token callers are not cookie-driven and cannot be CSRF'd.
	if r.Header.Get("Authorization") != "" {
		return true
	}
	// Only the cookie-session path needs the check; if there is no session cookie the
	// request is not session-authenticated and other auth (or rejection) applies.
	if _, err := r.Cookie(sessionCookieName); err != nil {
		return true
	}
	cookie, err := r.Cookie(csrfCookieName)
	header := r.Header.Get(csrfHeaderName)
	if err != nil || cookie.Value == "" || header == "" ||
		!crypto.ConstantTimeEqual([]byte(cookie.Value), []byte(header)) {
		a.writeProblem(w, problem.New(http.StatusForbidden, "missing or invalid CSRF token"))
		return false
	}
	return true
}

func (a *API) sessionFrom(r *http.Request) (auth.Session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return auth.Session{}, false
	}
	sess, err := a.auth.Sessions.Verify(c.Value)
	if err != nil {
		return auth.Session{}, false
	}
	return sess, true
}

func (a *API) setTransientCookie(w http.ResponseWriter, name, value string) {
	// SameSite=Lax (not Strict): the OIDC state/nonce cookies must survive the
	// top-level cross-site redirect back from the identity provider, which Strict
	// would drop. They are short-lived and unprivileged.
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true,
		Secure: a.auth.Secure, SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
}

func (a *API) setSessionCookie(w http.ResponseWriter, value string) {
	// SameSite=Strict on the session cookie: the browser never attaches it to a
	// cross-site request, which (with the double-submit CSRF token) is the SEC-007
	// hardening. The post-login redirect is same-site (this server's /), so Strict
	// does not break the flow.
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: value, Path: "/", HttpOnly: true,
		Secure: a.auth.Secure, SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(12 * time.Hour),
	})
}

// setCSRFCookie sets the double-submit CSRF token cookie. It is intentionally NOT
// HttpOnly so the SPA can read it and echo it in the X-CSRF-Token header; that is
// safe because the token is not a credential on its own (a session cookie is still
// required) and a cross-site attacker cannot read it (SameSite=Strict + same-origin
// script access only). SEC-007.
func (a *API) setCSRFCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookieName, Value: value, Path: "/", HttpOnly: false,
		Secure: a.auth.Secure, SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(12 * time.Hour),
	})
}

func (a *API) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", HttpOnly: true,
		Secure: a.auth.Secure, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}
