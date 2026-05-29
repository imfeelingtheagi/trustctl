package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// IdentityKind is the discriminator for the Identity union.
type IdentityKind string

const (
	KindX509Certificate  IdentityKind = "x509_certificate"
	KindSSHCertificate   IdentityKind = "ssh_certificate"
	KindSSHKey           IdentityKind = "ssh_key"
	KindSecret           IdentityKind = "secret"
	KindAPIKey           IdentityKind = "api_key"
	KindWorkloadIdentity IdentityKind = "workload_identity"
)

// Identity is the abstract credential (X509Certificate | SSHCertificate | SSHKey
// | Secret | APIKey | WorkloadIdentity), discriminated by Kind. It stores
// metadata only — secret and key material live behind the crypto boundary
// (AN-3/AN-8), never in this row. It belongs to an Owner and, for issued
// credentials, was minted by an Issuer.
type Identity struct {
	ID         string
	TenantID   string
	Kind       IdentityKind
	Name       string
	OwnerID    string
	IssuerID   *string // nil for credentials with no issuer (e.g. a raw secret)
	Status     string
	NotBefore  *time.Time
	NotAfter   *time.Time
	Attributes json.RawMessage // kind-specific, non-secret metadata
	CreatedAt  time.Time
}

// jsonbOrEmpty renders raw JSON for a jsonb column, defaulting to an empty object
// so the NOT NULL DEFAULT '{}' columns always receive valid JSON.
func jsonbOrEmpty(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

// UpsertIdentity inserts or updates an identity in its tenant context
// (RLS-enforced).
func (s *Store) UpsertIdentity(ctx context.Context, id Identity) error {
	return s.WithTenant(ctx, id.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO identities
			        (id, tenant_id, kind, name, owner_id, issuer_id, status, not_before, not_after, attributes)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
			 ON CONFLICT (id) DO UPDATE
			    SET kind = EXCLUDED.kind, name = EXCLUDED.name, owner_id = EXCLUDED.owner_id,
			        issuer_id = EXCLUDED.issuer_id, status = EXCLUDED.status,
			        not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after,
			        attributes = EXCLUDED.attributes`,
			id.ID, id.TenantID, string(id.Kind), id.Name, id.OwnerID, id.IssuerID,
			id.Status, id.NotBefore, id.NotAfter, jsonbOrEmpty(id.Attributes))
		return err
	})
}

// GetIdentity loads an identity in its tenant context.
func (s *Store) GetIdentity(ctx context.Context, tenantID, id string) (Identity, error) {
	var (
		it    Identity
		kind  string
		attrs []byte
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, kind, name, owner_id::text, issuer_id::text,
			        status, not_before, not_after, attributes, created_at
			   FROM identities WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&it.ID, &it.TenantID, &kind, &it.Name, &it.OwnerID, &it.IssuerID,
				&it.Status, &it.NotBefore, &it.NotAfter, &attrs, &it.CreatedAt)
	})
	it.Kind = IdentityKind(kind)
	it.Attributes = attrs
	return it, err
}

// ListIdentities returns all identities for a tenant.
func (s *Store) ListIdentities(ctx context.Context, tenantID string) ([]Identity, error) {
	var out []Identity
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, kind, name, owner_id::text, issuer_id::text,
			        status, not_before, not_after, attributes, created_at
			   FROM identities WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				it    Identity
				kind  string
				attrs []byte
			)
			if err := rows.Scan(&it.ID, &it.TenantID, &kind, &it.Name, &it.OwnerID, &it.IssuerID,
				&it.Status, &it.NotBefore, &it.NotAfter, &attrs, &it.CreatedAt); err != nil {
				return err
			}
			it.Kind = IdentityKind(kind)
			it.Attributes = attrs
			out = append(out, it)
		}
		return rows.Err()
	})
	return out, err
}
