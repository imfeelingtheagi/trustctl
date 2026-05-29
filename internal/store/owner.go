package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// OwnerKind enumerates who can own a credential.
type OwnerKind string

const (
	OwnerUser     OwnerKind = "user"
	OwnerTeam     OwnerKind = "team"
	OwnerWorkload OwnerKind = "workload"
	OwnerService  OwnerKind = "service"
)

// Owner is a credential owner (User | Team | Workload | Service).
type Owner struct {
	ID        string
	TenantID  string
	Kind      OwnerKind
	Name      string
	Email     string
	CreatedAt time.Time
}

// UpsertOwner inserts or updates an owner in its tenant context (RLS-enforced).
func (s *Store) UpsertOwner(ctx context.Context, o Owner) error {
	return s.WithTenant(ctx, o.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO owners (id, tenant_id, kind, name, email)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (id) DO UPDATE
			    SET kind = EXCLUDED.kind, name = EXCLUDED.name, email = EXCLUDED.email`,
			o.ID, o.TenantID, string(o.Kind), o.Name, o.Email)
		return err
	})
}

// GetOwner loads an owner in its tenant context.
func (s *Store) GetOwner(ctx context.Context, tenantID, id string) (Owner, error) {
	var (
		o    Owner
		kind string
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, kind, name, email, created_at
			   FROM owners WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&o.ID, &o.TenantID, &kind, &o.Name, &o.Email, &o.CreatedAt)
	})
	o.Kind = OwnerKind(kind)
	return o, err
}

// ListOwners returns all owners for a tenant.
func (s *Store) ListOwners(ctx context.Context, tenantID string) ([]Owner, error) {
	var out []Owner
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, kind, name, email, created_at
			   FROM owners WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				o    Owner
				kind string
			)
			if err := rows.Scan(&o.ID, &o.TenantID, &kind, &o.Name, &o.Email, &o.CreatedAt); err != nil {
				return err
			}
			o.Kind = OwnerKind(kind)
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}
