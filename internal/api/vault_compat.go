package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

const (
	vaultCompatRequestID = "trstctl-vault-compat"
	vaultKVSecretMount   = "secret"
	vaultPKIMount        = "pki"
)

// mountVaultCompat registers VAULT-01's compatibility shim. These are not native
// trstctl API resources, so they stay out of the OpenAPI registry, but every
// state-changing path still goes through the same tenant, RBAC, idempotency, audit,
// and sealed-at-rest implementation as /api/v1/secrets/*.
func (a *API) mountVaultCompat(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/sys/health", a.vaultHealth)
	mux.HandleFunc("GET /v1/sys/internal/ui/mounts/{path...}", a.vaultAuth("", a.vaultMountInfo))
	mux.HandleFunc("GET /v1/auth/token/lookup-self", a.vaultAuth("", a.vaultTokenLookupSelf))
	mux.HandleFunc("POST /v1/auth/token/lookup-self", a.vaultAuth("", a.vaultTokenLookupSelf))
	mux.HandleFunc("GET /v1/secret/data/{name...}", a.vaultAuth(authz.SecretsRead, a.vaultKVRead))
	mux.HandleFunc("POST /v1/secret/data/{name...}", a.vaultAuth(authz.SecretsWrite, a.vaultKVWrite))
	mux.HandleFunc("PUT /v1/secret/data/{name...}", a.vaultAuth(authz.SecretsWrite, a.vaultKVWrite))
	mux.HandleFunc("POST /v1/pki/issue/{role}", a.vaultAuth(authz.SecretsWrite, a.vaultPKIIssue))
	mux.HandleFunc("PUT /v1/pki/issue/{role}", a.vaultAuth(authz.SecretsWrite, a.vaultPKIIssue))
}

func (a *API) vaultAuth(perm authz.Permission, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, err := a.principal(r)
		if err != nil {
			writeVaultError(w, http.StatusForbidden, "permission denied")
			return
		}
		if perm != "" {
			target := authz.Scope{TenantID: principal.TenantID, Project: r.Header.Get("X-Project")}
			if !principal.Can(perm, target) {
				writeVaultError(w, http.StatusForbidden, "permission denied")
				return
			}
			if err := a.checkABAC(r.Context(), r, principal, perm, target); err != nil {
				writeVaultError(w, vaultStatus(err), err.Error())
				return
			}
		}
		if a.rateLimiter != nil {
			allowed, retryAfter, err := a.rateLimiter.Allow(r.Context(), principal.TenantID)
			if err != nil {
				writeVaultError(w, http.StatusInternalServerError, "internal error")
				return
			}
			if !allowed {
				if retryAfter > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds()+0.999)))
				}
				writeVaultError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}
		ctx := context.WithValue(r.Context(), principalCtxKey, principal)
		ctx = events.ContextWithActor(ctx, events.Actor{Subject: principal.Subject, Roles: principalRoles(principal)})
		h(w, r.WithContext(ctx))
	}
}

func vaultStatus(err error) int {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.status
	}
	return http.StatusForbidden
}

type vaultEnvelope struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          any    `json:"data,omitempty"`
	Warnings      any    `json:"warnings"`
}

func newVaultEnvelope(data any) vaultEnvelope {
	return vaultEnvelope{
		RequestID: vaultCompatRequestID,
		Data:      data,
		Warnings:  nil,
	}
}

func writeVaultJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer secret.Wipe(body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeVaultError(w http.ResponseWriter, status int, detail string) {
	if status == 0 {
		status = http.StatusInternalServerError
	}
	if detail == "" {
		detail = http.StatusText(status)
	}
	writeVaultJSON(w, status, map[string][]string{"errors": {detail}})
}

func (a *API) vaultHealth(w http.ResponseWriter, _ *http.Request) {
	writeVaultJSON(w, http.StatusOK, map[string]any{
		"initialized": true,
		"sealed":      false,
		"standby":     false,
		"version":     "trstctl-vault-compat",
	})
}

func (a *API) vaultMountInfo(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.PathValue("path"), "/")
	switch {
	case path == vaultKVSecretMount || strings.HasPrefix(path, vaultKVSecretMount+"/"):
		writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{
			"path":    vaultKVSecretMount + "/",
			"type":    "kv",
			"options": map[string]string{"version": "2"},
		}))
	case path == vaultPKIMount || strings.HasPrefix(path, vaultPKIMount+"/"):
		writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{
			"path": vaultPKIMount + "/",
			"type": "pki",
		}))
	default:
		writeVaultError(w, http.StatusNotFound, "no handler for route")
	}
}

func (a *API) vaultTokenLookupSelf(w http.ResponseWriter, r *http.Request) {
	principal, ok := a.principalFor(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	writeVaultJSON(w, http.StatusOK, newVaultEnvelope(map[string]any{
		"id":           "trstctl-api-token",
		"accessor":     "",
		"display_name": principal.Subject,
		"entity_id":    principal.Subject,
		"meta":         map[string]string{"tenant_id": principal.TenantID},
		"num_uses":     0,
		"orphan":       true,
		"path":         "auth/token/create",
		"policies":     principalRoles(principal),
		"renewable":    false,
		"ttl":          0,
	}))
}

type vaultKVWriteRequest struct {
	Data    json.RawMessage            `json:"data"`
	Options map[string]json.RawMessage `json:"options,omitempty"`
}

type vaultKVMetadata struct {
	CreatedTime  string         `json:"created_time"`
	DeletionTime string         `json:"deletion_time"`
	Destroyed    bool           `json:"destroyed"`
	Version      int            `json:"version"`
	Custom       map[string]any `json:"custom_metadata"`
}

//trstctl:mutation
func (a *API) vaultKVWrite(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return
	}
	body, ok := a.captureVaultBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(body)
	name := strings.Trim(r.PathValue("name"), "/")
	if name == "" {
		writeVaultError(w, http.StatusBadRequest, "secret path is required")
		return
	}
	idempotencyKey := vaultIdempotencyKey(r, body)
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req vaultKVWriteRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if !rawJSONObject(req.Data) {
			return 0, nil, errStatus(http.StatusBadRequest, "data must be a JSON object")
		}
		value := append([]byte(nil), req.Data...)
		defer secret.Wipe(value)
		sealed, err := seal.Seal(a.secrets.be.KEK, value, sealAAD(tenantID, name))
		if err != nil {
			return 0, nil, err
		}
		rec, err := a.upsertVaultKVSecret(ctx, tenantID, name, sealed)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, newVaultEnvelope(vaultKVMetadata{
			CreatedTime:  rec.UpdatedAt.UTC().Format(time.RFC3339Nano),
			DeletionTime: "",
			Destroyed:    false,
			Version:      rec.Version,
			Custom:       nil,
		}), nil
	})
}

func (a *API) upsertVaultKVSecret(ctx context.Context, tenantID, name string, sealed []byte) (store.Secret, error) {
	if _, err := a.secrets.be.Store.GetSecret(ctx, tenantID, name); err != nil {
		if !errors.Is(err, store.ErrSecretNotFound) {
			return store.Secret{}, err
		}
		rec, putErr := a.secrets.be.Store.PutSecret(ctx, tenantID, name, sealed)
		if putErr != nil {
			if errors.Is(putErr, store.ErrSecretExists) {
				return a.upsertVaultKVSecret(ctx, tenantID, name, sealed)
			}
			return store.Secret{}, putErr
		}
		a.auditSecretVersion(ctx, tenantID, rec, nil)
		a.auditSecret(ctx, "secret.created", tenantID, rec.Name, rec.Version)
		return rec, nil
	}
	if err := a.requireSecretApproval(ctx, tenantID, name, "rotate"); err != nil {
		return store.Secret{}, err
	}
	rec, err := a.secrets.be.Store.RotateSecret(ctx, tenantID, name, sealed)
	if err != nil {
		return store.Secret{}, err
	}
	a.auditSecretVersion(ctx, tenantID, rec, nil)
	a.auditSecret(ctx, "secret.rotated", tenantID, rec.Name, rec.Version)
	return rec, nil
}

func (a *API) vaultKVRead(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	name := strings.Trim(r.PathValue("name"), "/")
	if name == "" {
		writeVaultError(w, http.StatusBadRequest, "secret path is required")
		return
	}
	rec, err := a.secrets.be.Store.GetSecret(r.Context(), tenantID, name)
	if err != nil {
		if errors.Is(err, store.ErrSecretNotFound) {
			writeVaultError(w, http.StatusNotFound, "no such secret")
			return
		}
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	value, err := seal.Open(a.secrets.be.KEK, rec.Sealed, sealAAD(tenantID, name))
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer secret.Wipe(value)
	a.writeVaultKVRead(w, rec, value)
}

func (a *API) writeVaultKVRead(w http.ResponseWriter, rec store.Secret, value []byte) {
	meta := vaultKVMetadata{
		CreatedTime:  rec.UpdatedAt.UTC().Format(time.RFC3339Nano),
		DeletionTime: "",
		Destroyed:    false,
		Version:      rec.Version,
		Custom:       nil,
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer secret.Wipe(metaJSON)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"request_id":"` + vaultCompatRequestID + `","lease_id":"","renewable":false,"lease_duration":0,"data":{"data":`))
	if rawJSONObject(value) {
		_, _ = w.Write(value)
	} else {
		quoted := appendJSONQuotedBytes([]byte(`{"value":`), value)
		quoted = append(quoted, '}')
		_, _ = w.Write(quoted)
		secret.Wipe(quoted)
	}
	_, _ = w.Write([]byte(`,"metadata":`))
	_, _ = w.Write(metaJSON)
	_, _ = w.Write([]byte(`},"warnings":null}`))
}

type vaultPKIIssueRequest struct {
	CommonName string `json:"common_name"`
	TTL        string `json:"ttl"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type vaultPKIIssueData struct {
	SerialNumber string          `json:"serial_number"`
	Certificate  secretJSONBytes `json:"certificate"`
	PrivateKey   secretJSONBytes `json:"private_key"`
}

type vaultPKIIssueResponse struct {
	RequestID     string            `json:"request_id"`
	LeaseID       string            `json:"lease_id"`
	Renewable     bool              `json:"renewable"`
	LeaseDuration int               `json:"lease_duration"`
	Data          vaultPKIIssueData `json:"data"`
	Warnings      any               `json:"warnings"`
}

func (r vaultPKIIssueResponse) wipeSecrets() {
	r.Data.Certificate.wipe()
	r.Data.PrivateKey.wipe()
}

//trstctl:mutation
func (a *API) vaultPKIIssue(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		writeVaultError(w, http.StatusNotFound, "secrets surface is not enabled")
		return
	}
	body, ok := a.captureVaultBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(body)
	caCertDER, caSigner := a.secrets.resolveCA()
	if caSigner == nil || len(caCertDER) == 0 {
		writeVaultError(w, http.StatusServiceUnavailable, "dynamic PKI secret issuance unavailable")
		return
	}
	idempotencyKey := vaultIdempotencyKey(r, body)
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req vaultPKIIssueRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.CommonName = strings.TrimSpace(req.CommonName)
		if req.CommonName == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "common_name is required")
		}
		ttl, err := parseVaultTTL(req.TTL, req.TTLSeconds)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		provider := a.secrets.pkiProvider(tenantID, caCertDER, caSigner)
		cred, err := provider.Generate(ctx, dynsecret.GenerateRequest{
			Role: req.CommonName,
			TTL:  ttl,
		})
		if err != nil {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, err.Error())
		}
		certPEM, keyPEM := splitCertKeyPEM(cred.Secret)
		secret.Wipe(cred.Secret)
		resp := vaultPKIIssueResponse{
			RequestID:     vaultCompatRequestID,
			LeaseDuration: int(ttl.Seconds()),
			Data: vaultPKIIssueData{
				SerialNumber: cred.BackendRef,
				Certificate:  secretJSONBytes(certPEM),
				PrivateKey:   secretJSONBytes(keyPEM),
			},
			Warnings: nil,
		}
		a.auditSecret(ctx, "pkisecret.issued", tenantID, req.CommonName, 0)
		return http.StatusOK, resp, nil
	})
}

func parseVaultTTL(raw string, seconds int) (time.Duration, error) {
	if raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return 0, fmt.Errorf("ttl must be a Go duration such as 1h")
		}
		if d <= 0 {
			return 0, fmt.Errorf("ttl must be positive")
		}
		return d, nil
	}
	if seconds > 0 {
		return time.Duration(seconds) * time.Second, nil
	}
	return time.Hour, nil
}

func (a *API) captureVaultBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Body == nil {
		writeVaultError(w, http.StatusBadRequest, "request body is required")
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, defaultRESTJSONBodyLimit+1))
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, "invalid request body")
		return nil, false
	}
	if int64(len(body)) > defaultRESTJSONBodyLimit {
		secret.Wipe(body)
		writeVaultError(w, http.StatusRequestEntityTooLarge, "JSON request body too large")
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, true
}

func vaultIdempotencyKey(r *http.Request, body []byte) string {
	if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
		return key
	}
	material := make([]byte, 0, len(r.Method)+len(r.URL.Path)+1+len(body))
	material = append(material, r.Method...)
	material = append(material, ' ')
	material = append(material, r.URL.Path...)
	material = append(material, '\n')
	material = append(material, body...)
	digest := crypto.SHA256Hex(material)
	secret.Wipe(material)
	return "vault:" + digest
}

func rawJSONObject(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '{' || raw[len(raw)-1] != '}' || !json.Valid(raw) {
		return false
	}
	var obj map[string]json.RawMessage
	return json.Unmarshal(raw, &obj) == nil
}
