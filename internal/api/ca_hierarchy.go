package api

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/store"
)

var (
	ErrCAHierarchyUnavailable = errors.New("api: CA hierarchy surface is not enabled")
	ErrCAHierarchyInvalid     = errors.New("api: invalid CA hierarchy request")
	ErrCAHierarchyConflict    = errors.New("api: CA hierarchy request conflicts with current ceremony state")
)

// CAHierarchyService is the served private-CA hierarchy backend (F48). The
// implementation lives in internal/server so it can bind to the isolated signer;
// the API owns only the JSON contract and RBAC/idempotency wrapper.
type CAHierarchyService interface {
	StartCeremony(ctx context.Context, tenantID string, req CACeremonyStartRequest) (CAKeyCeremony, error)
	GetCeremony(ctx context.Context, tenantID, id string) (CAKeyCeremony, error)
	ApproveCeremony(ctx context.Context, tenantID, id string) (CAKeyCeremony, error)
	ListAuthorities(ctx context.Context, tenantID string) ([]CAAuthority, error)
	CreateRoot(ctx context.Context, tenantID string, req CACreateRootRequest) (CAAuthority, error)
	CreateIntermediate(ctx context.Context, tenantID string, req CACreateIntermediateRequest) (CAAuthority, error)
	IssueLeaf(ctx context.Context, tenantID, caID string, req CAIssueLeafRequest) (CAIssuedLeaf, error)
}

// WithCAHierarchy wires the served CA hierarchy surface. When unset, the routes
// fail closed with 503 instead of pretending CA creation is available.
func WithCAHierarchy(svc CAHierarchyService) Option {
	return func(c *config) { c.caHierarchy = svc }
}

type CASpec struct {
	CommonName          string   `json:"common_name"`
	PermittedDNSDomains []string `json:"permitted_dns_domains"`
	MaxPathLen          int      `json:"max_path_len"`
	ExtendedKeyUsages   []string `json:"extended_key_usages"`
	TTLSeconds          int64    `json:"ttl_seconds"`
	SignatureAlgorithm  string   `json:"signature_algorithm"`
}

type CACeremonyStartRequest struct {
	Operation string `json:"operation"`
	ParentID  string `json:"parent_id"`
	Threshold int    `json:"threshold"`
	Spec      CASpec `json:"spec"`
}

type CACreateRootRequest struct {
	CeremonyID string `json:"ceremony_id"`
	Spec       CASpec `json:"spec"`
}

type CACreateIntermediateRequest struct {
	CeremonyID string `json:"ceremony_id"`
	ParentID   string `json:"parent_id"`
	Spec       CASpec `json:"spec"`
}

type CAIssueLeafRequest struct {
	CSRDER     []byte
	TTLSeconds int64
}

type caIssueLeafJSON struct {
	CSRPem     string `json:"csr_pem"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

type CAKeyCeremony struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Purpose   string    `json:"purpose"`
	Threshold int       `json:"threshold"`
	Status    string    `json:"status"`
	Approvals int       `json:"approvals"`
	Opener    string    `json:"opener,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type CAAuthority struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	ParentID          *string    `json:"parent_id,omitempty"`
	CommonName        string     `json:"common_name"`
	Kind              string     `json:"kind"`
	Status            string     `json:"status"`
	CertificatePEM    string     `json:"certificate_pem"`
	SignerHandle      string     `json:"signer_handle"`
	Serial            string     `json:"serial"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	MaxPathLen        int        `json:"max_path_len"`
	PermittedDNSNames []string   `json:"permitted_dns_names"`
	ExtendedKeyUsages []string   `json:"extended_key_usages"`
	CreatedAt         time.Time  `json:"created_at"`
}

type CAIssuedLeaf struct {
	CertificatePEM string    `json:"certificate_pem"`
	Serial         string    `json:"serial"`
	NotAfter       time.Time `json:"not_after"`
}

//trstctl:mutation
func (a *API) createCACeremony(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CACeremonyStartRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		c, err := a.caHierarchy.StartCeremony(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, c, nil
	})
}

func (a *API) getCACeremony(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.caHierarchy == nil {
		a.writeError(w, ErrCAHierarchyUnavailable)
		return
	}
	c, err := a.caHierarchy.GetCeremony(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, c)
}

//trstctl:mutation
func (a *API) approveCACeremony(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		c, err := a.caHierarchy.ApproveCeremony(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, c, nil
	})
}

func (a *API) listCAAuthorities(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.caHierarchy == nil {
		a.writeError(w, ErrCAHierarchyUnavailable)
		return
	}
	items, err := a.caHierarchy.ListAuthorities(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

//trstctl:mutation
func (a *API) createRootCA(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CACreateRootRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		ca, err := a.caHierarchy.CreateRoot(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, ca, nil
	})
}

//trstctl:mutation
func (a *API) createIntermediateCA(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req CACreateIntermediateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		ca, err := a.caHierarchy.CreateIntermediate(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, ca, nil
	})
}

//trstctl:mutation
func (a *API) issueHierarchyLeaf(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.caHierarchy == nil {
			return 0, nil, ErrCAHierarchyUnavailable
		}
		var req caIssueLeafJSON
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		block, _ := pem.Decode([]byte(req.CSRPem))
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			return 0, nil, errStatus(http.StatusBadRequest, "csr_pem must contain one CERTIFICATE REQUEST PEM block")
		}
		issued, err := a.caHierarchy.IssueLeaf(ctx, tenantID, id, CAIssueLeafRequest{
			CSRDER:     block.Bytes,
			TTLSeconds: req.TTLSeconds,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, issued, nil
	})
}

func (a *API) writeCAHierarchyError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrCAHierarchyUnavailable):
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "CA hierarchy surface is not enabled"))
	case errors.Is(err, ErrCAHierarchyInvalid):
		a.writeProblem(w, problem.New(http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), ErrCAHierarchyInvalid.Error()+": ")))
	case errors.Is(err, ErrCAHierarchyConflict),
		errors.Is(err, store.ErrSelfApproval),
		errors.Is(err, store.ErrKeyCeremonyNotPending),
		errors.Is(err, store.ErrKeyCeremonyPurposeMismatch),
		errors.Is(err, store.ErrKeyCeremonyQuorumNotMet):
		a.writeProblem(w, problem.New(http.StatusConflict, err.Error()))
	default:
		return false
	}
	return true
}
