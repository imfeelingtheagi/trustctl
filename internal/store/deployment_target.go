package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// DeploymentTarget is a place credentials get deployed (a connector target),
// such as a Kubernetes cluster, a file path, a load balancer, or an SSH host.
type DeploymentTarget struct {
	ID        string
	TenantID  string
	Name      string
	Type      string
	Config    json.RawMessage // connector configuration; non-secret
	CreatedAt time.Time
}

// UpsertDeploymentTarget inserts or updates a target in its tenant context.
func (s *Store) UpsertDeploymentTarget(ctx context.Context, d DeploymentTarget) error {
	return s.WithTenant(ctx, d.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO deployment_targets (id, tenant_id, name, type, config)
			 VALUES ($1, $2, $3, $4, $5::jsonb)
			 ON CONFLICT (id) DO UPDATE
			    SET name = EXCLUDED.name, type = EXCLUDED.type, config = EXCLUDED.config`,
			d.ID, d.TenantID, d.Name, d.Type, jsonbOrEmpty(d.Config))
		return err
	})
}

// GetDeploymentTarget loads a target in its tenant context.
func (s *Store) GetDeploymentTarget(ctx context.Context, tenantID, id string) (DeploymentTarget, error) {
	var (
		d   DeploymentTarget
		cfg []byte
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, type, config, created_at
			   FROM deployment_targets WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&d.ID, &d.TenantID, &d.Name, &d.Type, &cfg, &d.CreatedAt)
	})
	d.Config = cfg
	return d, err
}

// ListDeploymentTargets returns all targets for a tenant.
func (s *Store) ListDeploymentTargets(ctx context.Context, tenantID string) ([]DeploymentTarget, error) {
	var out []DeploymentTarget
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, type, config, created_at
			   FROM deployment_targets WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				d   DeploymentTarget
				cfg []byte
			)
			if err := rows.Scan(&d.ID, &d.TenantID, &d.Name, &d.Type, &cfg, &d.CreatedAt); err != nil {
				return err
			}
			d.Config = cfg
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}
