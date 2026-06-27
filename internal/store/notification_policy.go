package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// NotificationRoutingPolicy is the tenant-scoped read model for notification
// channel routing. It stores only channel names, never channel credentials.
type NotificationRoutingPolicy struct {
	ID                 string
	TenantID           string
	Name               string
	ChannelsBySeverity map[string][]string
	DefaultChannels    []string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// GetNotificationRoutingPolicy loads one tenant-scoped notification routing
// policy. The tenant_id predicate is intentionally in SQL and RLS enforces it.
func (s *Store) GetNotificationRoutingPolicy(ctx context.Context, tenantID, id string) (NotificationRoutingPolicy, error) {
	var out NotificationRoutingPolicy
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanNotificationRoutingPolicy(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, channels_by_severity, default_channels, created_at, updated_at
			   FROM notification_routing_policies
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, id), &out)
	})
	return out, err
}

func scanNotificationRoutingPolicy(row rowScanner, p *NotificationRoutingPolicy) error {
	var matrix []byte
	var defaults []byte
	if err := row.Scan(&p.ID, &p.TenantID, &p.Name, &matrix, &defaults, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return err
	}
	if len(matrix) > 0 {
		if err := json.Unmarshal(matrix, &p.ChannelsBySeverity); err != nil {
			return err
		}
	}
	if len(defaults) > 0 {
		if err := json.Unmarshal(defaults, &p.DefaultChannels); err != nil {
			return err
		}
	}
	return nil
}
