package ca

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	"trustctl.io/trustctl/internal/orchestrator"
	"trustctl.io/trustctl/internal/store"
)

// IssuanceService issues certificates through a CA on the platform's safety
// rails: idempotency (AN-5) so a retried request never mints two certificates,
// and an outbox record (AN-6) so every issuance is observable. It is the path
// the orchestrator drives and the seam the upstream CA plugins (e.g. Let's
// Encrypt) plug into behind the same CA interface.
type IssuanceService struct {
	ca     CA
	idem   *orchestrator.Idempotency
	outbox *orchestrator.Outbox
	store  *store.Store
}

// NewIssuanceService wires an issuance service over a CA and the platform's
// idempotency and outbox.
func NewIssuanceService(ca CA, idem *orchestrator.Idempotency, outbox *orchestrator.Outbox, st *store.Store) *IssuanceService {
	return &IssuanceService{ca: ca, idem: idem, outbox: outbox, store: st}
}

// Issue signs the request under idempotencyKey: the first call mints the
// certificate and records the issuance in the outbox; a replay with the same key
// returns the original certificate without minting again.
func (s *IssuanceService) Issue(ctx context.Context, req IssueRequest, idempotencyKey string) (Certificate, error) {
	raw, err := s.idem.Do(ctx, req.TenantID, idempotencyKey, func(ctx context.Context) ([]byte, error) {
		cert, err := s.ca.Issue(ctx, req)
		if err != nil {
			return nil, err
		}
		if err := s.record(ctx, req.TenantID, idempotencyKey, cert); err != nil {
			return nil, err
		}
		return json.Marshal(cert)
	})
	if err != nil {
		return Certificate{}, err
	}
	var cert Certificate
	if err := json.Unmarshal(raw, &cert); err != nil {
		return Certificate{}, err
	}
	return cert, nil
}

// record writes a ca.issue outbox entry so the issuance is observable (AN-6).
func (s *IssuanceService) record(ctx context.Context, tenantID, key string, cert Certificate) error {
	payload, err := json.Marshal(struct {
		Serial string `json:"serial"`
		Issuer string `json:"issuer"`
	}{cert.Serial, cert.Issuer})
	if err != nil {
		return err
	}
	return s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID:       tenantID,
			Destination:    "ca.issue",
			IdempotencyKey: key,
			Payload:        payload,
		})
		return err
	})
}
