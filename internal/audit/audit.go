// Package audit exposes query, search, filter, and signed-export surfaces over
// the event-sourced audit log (F9). The AN-2 event log remains the source of
// truth: this package reads it via Replay and derives views; it never writes a
// separate audit store. Every query is tenant-scoped (AN-1). Evidence bundles are
// signed through the crypto boundary (internal/crypto/jose) so an auditor can
// verify their integrity offline.
package audit

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"certctl.io/certctl/internal/crypto/jose"
	"certctl.io/certctl/internal/events"
)

// Record is one audit entry: a projection of an event for an auditor.
type Record struct {
	Sequence uint64          `json:"sequence"`
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	TenantID string          `json:"tenant_id"`
	Time     time.Time       `json:"time"`
	Data     json.RawMessage `json:"data,omitempty"`
}

// Query selects a slice of the audit log. TenantID is required for tenant
// isolation; the zero value of the other fields means "unbounded".
type Query struct {
	TenantID     string    `json:"tenant_id"`
	Types        []string  `json:"types,omitempty"`          // exact event-type filter
	Since        time.Time `json:"since,omitempty"`          // inclusive lower time bound
	Until        time.Time `json:"until,omitempty"`          // inclusive upper time bound
	AsOfSequence uint64    `json:"as_of_sequence,omitempty"` // point-in-time: only events with Sequence <= this
	Contains     string    `json:"contains,omitempty"`       // substring match on type or data
	Limit        int       `json:"limit,omitempty"`          // cap on records returned (0 = all)
}

// Service answers audit queries and exports signed evidence bundles over the
// event log.
type Service struct {
	log    *events.Log
	signer *jose.SigningKey
	now    func() time.Time
}

// NewService returns an audit service over the event log, signing evidence
// bundles with signer.
func NewService(log *events.Log, signer *jose.SigningKey) *Service {
	return &Service{log: log, signer: signer, now: time.Now}
}

// Search returns the records matching q, in append order. It replays the log and
// applies the filters; the event log stays the source of truth.
func (s *Service) Search(ctx context.Context, q Query) ([]Record, error) {
	out := []Record{}
	err := s.log.Replay(ctx, 0, func(e events.Event) error {
		if !q.matches(e) {
			return nil
		}
		out = append(out, Record{
			Sequence: e.Sequence, ID: e.ID, Type: e.Type,
			TenantID: e.TenantID, Time: e.Time, Data: json.RawMessage(e.Data),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func (q Query) matches(e events.Event) bool {
	if q.TenantID != "" && e.TenantID != q.TenantID { // AN-1
		return false
	}
	if q.AsOfSequence != 0 && e.Sequence > q.AsOfSequence {
		return false
	}
	if !q.Since.IsZero() && e.Time.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && e.Time.After(q.Until) {
		return false
	}
	if len(q.Types) > 0 && !contains(q.Types, e.Type) {
		return false
	}
	if q.Contains != "" && !strings.Contains(e.Type, q.Contains) && !strings.Contains(string(e.Data), q.Contains) {
		return false
	}
	return true
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// Bundle is a self-contained, signable export of audit records.
type Bundle struct {
	TenantID    string    `json:"tenant_id"`
	GeneratedAt time.Time `json:"generated_at"`
	Query       Query     `json:"query"`
	Records     []Record  `json:"records"`
	Count       int       `json:"count"`
}

// Export runs the query and returns the matching records as a signed evidence
// bundle (a compact JWS whose payload is the Bundle). An auditor verifies it with
// VerifyBundle and the service's verification keys.
func (s *Service) Export(ctx context.Context, q Query) (string, error) {
	recs, err := s.Search(ctx, q)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(Bundle{
		TenantID: q.TenantID, GeneratedAt: s.now().UTC(), Query: q, Records: recs, Count: len(recs),
	})
	if err != nil {
		return "", err
	}
	return s.signer.Sign(payload)
}

// VerificationKeys returns the public key set that verifies bundles exported by
// this service.
func (s *Service) VerificationKeys() *jose.JWKSet { return s.signer.JWKS() }

// VerifyBundle verifies a signed evidence bundle against keys and returns it. A
// bad signature is an error.
func VerifyBundle(signed string, keys *jose.JWKSet) (Bundle, error) {
	payload, err := keys.Verify(signed)
	if err != nil {
		return Bundle{}, err
	}
	var b Bundle
	if err := json.Unmarshal(payload, &b); err != nil {
		return Bundle{}, err
	}
	return b, nil
}
