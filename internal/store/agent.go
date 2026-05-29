package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Agent is an in-network agent that performs discovery, deployment, and drift
// detection on behalf of the control plane.
type Agent struct {
	ID         string
	TenantID   string
	Name       string
	Status     string
	Version    string
	LastSeenAt *time.Time
	CreatedAt  time.Time
}

// UpsertAgent inserts or updates an agent in its tenant context.
func (s *Store) UpsertAgent(ctx context.Context, a Agent) error {
	return s.WithTenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO agents (id, tenant_id, name, status, version, last_seen_at)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 ON CONFLICT (id) DO UPDATE
			    SET name = EXCLUDED.name, status = EXCLUDED.status,
			        version = EXCLUDED.version, last_seen_at = EXCLUDED.last_seen_at`,
			a.ID, a.TenantID, a.Name, a.Status, a.Version, a.LastSeenAt)
		return err
	})
}

// GetAgent loads an agent in its tenant context.
func (s *Store) GetAgent(ctx context.Context, tenantID, id string) (Agent, error) {
	var a Agent
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, status, version, last_seen_at, created_at
			   FROM agents WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&a.ID, &a.TenantID, &a.Name, &a.Status, &a.Version, &a.LastSeenAt, &a.CreatedAt)
	})
	return a, err
}

// ListAgents returns all agents for a tenant.
func (s *Store) ListAgents(ctx context.Context, tenantID string) ([]Agent, error) {
	var out []Agent
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, status, version, last_seen_at, created_at
			   FROM agents WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Agent
			if err := rows.Scan(&a.ID, &a.TenantID, &a.Name, &a.Status, &a.Version, &a.LastSeenAt, &a.CreatedAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
