package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// DiscoverySource is a tenant-owned scan source. Config is deliberately opaque
// JSON so source-specific connectors can carry references without the store
// learning secret shapes; API validation forbids inline secret values.
type DiscoverySource struct {
	ID        string
	TenantID  string
	Kind      string
	Name      string
	Config    json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
}

// DiscoverySchedule is a tenant-owned schedule for a discovery source.
type DiscoverySchedule struct {
	ID              string
	TenantID        string
	SourceID        string
	Name            string
	IntervalSeconds int
	Enabled         bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// DiscoveryRun is one queued/executed discovery run.
type DiscoveryRun struct {
	ID          string
	TenantID    string
	SourceID    string
	ScheduleID  *string
	Status      string
	DryRun      bool
	RequestedBy string
	Targets     int
	Discovered  int
	Failed      int
	Rejected    int
	Error       string
	StartedAt   *time.Time
	CompletedAt *time.Time
	CreatedAt   time.Time
}

// DiscoveryFinding is a metadata-only credential reference produced by a run.
type DiscoveryFinding struct {
	ID                string
	TenantID          string
	RunID             string
	SourceID          string
	Kind              string
	Ref               string
	Provenance        string
	Fingerprint       string
	RiskScore         int
	Metadata          json.RawMessage
	DiscoveredAt      time.Time
	TriageStatus      string
	ManagedIdentityID *string
	TriageActor       string
	TriageReason      string
	TriagedAt         *time.Time
}

// DiscoveryFindingTriageChange is the projected result of a
// discovery.finding.triage_changed event.
type DiscoveryFindingTriageChange struct {
	TenantID          string
	FindingID         string
	Status            string
	ManagedIdentityID *string
	Actor             string
	Reason            string
	ChangedAt         time.Time
}

func normalizeJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	return []byte(raw)
}

// ApplyDiscoverySourceUpsertedTx projects a discovery.source.upserted event.
func (s *Store) ApplyDiscoverySourceUpsertedTx(ctx context.Context, tx pgx.Tx, src DiscoverySource) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO discovery_sources (id, tenant_id, kind, name, config, created_at, updated_at)
		      VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		      SET kind = EXCLUDED.kind,
		          name = EXCLUDED.name,
		          config = EXCLUDED.config,
		          updated_at = EXCLUDED.updated_at`,
		src.ID, src.TenantID, src.Kind, src.Name, normalizeJSON(src.Config), src.CreatedAt, src.UpdatedAt)
	return err
}

// ApplyDiscoveryScheduleUpsertedTx projects a discovery.schedule.upserted event.
func (s *Store) ApplyDiscoveryScheduleUpsertedTx(ctx context.Context, tx pgx.Tx, sched DiscoverySchedule) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO discovery_schedules (id, tenant_id, source_id, name, interval_seconds, enabled, created_at, updated_at)
		      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		      SET source_id = EXCLUDED.source_id,
		          name = EXCLUDED.name,
		          interval_seconds = EXCLUDED.interval_seconds,
		          enabled = EXCLUDED.enabled,
		          updated_at = EXCLUDED.updated_at`,
		sched.ID, sched.TenantID, sched.SourceID, sched.Name, sched.IntervalSeconds, sched.Enabled, sched.CreatedAt, sched.UpdatedAt)
	return err
}

// ApplyDiscoveryRunQueuedTx projects a discovery.run.queued event.
func (s *Store) ApplyDiscoveryRunQueuedTx(ctx context.Context, tx pgx.Tx, run DiscoveryRun) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO discovery_runs
		        (id, tenant_id, source_id, schedule_id, status, dry_run, requested_by, created_at)
		      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		      SET status = EXCLUDED.status,
		          dry_run = EXCLUDED.dry_run,
		          requested_by = EXCLUDED.requested_by`,
		run.ID, run.TenantID, run.SourceID, run.ScheduleID, run.Status, run.DryRun, run.RequestedBy, run.CreatedAt)
	return err
}

// ApplyDiscoveryRunStartedTx projects a discovery.run.started event.
func (s *Store) ApplyDiscoveryRunStartedTx(ctx context.Context, tx pgx.Tx, tenantID, runID string, startedAt time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE discovery_runs
		    SET status = 'running', started_at = $3
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, runID, startedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ApplyDiscoveryFindingRecordedTx projects a discovery.finding.recorded event.
func (s *Store) ApplyDiscoveryFindingRecordedTx(ctx context.Context, tx pgx.Tx, f DiscoveryFinding) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO discovery_findings
		        (id, tenant_id, run_id, source_id, kind, ref, provenance, fingerprint, risk_score, metadata, discovered_at)
		      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		      SET kind = EXCLUDED.kind,
		          ref = EXCLUDED.ref,
		          provenance = EXCLUDED.provenance,
		          fingerprint = EXCLUDED.fingerprint,
		          risk_score = EXCLUDED.risk_score,
		          metadata = EXCLUDED.metadata,
		          discovered_at = EXCLUDED.discovered_at`,
		f.ID, f.TenantID, f.RunID, f.SourceID, f.Kind, f.Ref, f.Provenance, f.Fingerprint,
		f.RiskScore, normalizeJSON(f.Metadata), f.DiscoveredAt)
	return err
}

// ApplyDiscoveryFindingTriageChangedTx projects a discovery.finding.triage_changed event.
func (s *Store) ApplyDiscoveryFindingTriageChangedTx(ctx context.Context, tx pgx.Tx, ch DiscoveryFindingTriageChange) error {
	tag, err := tx.Exec(ctx,
		`UPDATE discovery_findings
		    SET triage_status = $3,
		        managed_identity_id = $4,
		        triage_actor = $5,
		        triage_reason = $6,
		        triaged_at = $7
		  WHERE tenant_id = $1 AND id = $2`,
		ch.TenantID, ch.FindingID, ch.Status, ch.ManagedIdentityID, ch.Actor, ch.Reason, ch.ChangedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ApplyDiscoveryRunCompletedTx projects a discovery.run.completed event.
func (s *Store) ApplyDiscoveryRunCompletedTx(ctx context.Context, tx pgx.Tx, run DiscoveryRun) error {
	tag, err := tx.Exec(ctx,
		`UPDATE discovery_runs
		    SET status = $3,
		        targets = $4,
		        discovered = $5,
		        failed = $6,
		        rejected = $7,
		        error = $8,
		        completed_at = $9
		  WHERE tenant_id = $1 AND id = $2`,
		run.TenantID, run.ID, run.Status, run.Targets, run.Discovered, run.Failed,
		run.Rejected, run.Error, run.CompletedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// GetDiscoverySource loads a source in its tenant context.
func (s *Store) GetDiscoverySource(ctx context.Context, tenantID, id string) (DiscoverySource, error) {
	var out DiscoverySource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDiscoverySource(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, kind, name, config, created_at, updated_at
			   FROM discovery_sources WHERE tenant_id = $1 AND id = $2`, tenantID, id), &out)
	})
	return out, err
}

// ListDiscoverySourcesPage lists tenant sources by id keyset.
func (s *Store) ListDiscoverySourcesPage(ctx context.Context, tenantID, afterID string, limit int) ([]DiscoverySource, error) {
	var out []DiscoverySource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, kind, name, config, created_at, updated_at
			   FROM discovery_sources
			  WHERE tenant_id = $1 AND id > $2
			  ORDER BY id LIMIT $3`, tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var src DiscoverySource
			if err := scanDiscoverySource(rows, &src); err != nil {
				return err
			}
			out = append(out, src)
		}
		return rows.Err()
	})
	return out, err
}

// ListDiscoverySchedulesPage lists tenant schedules by id keyset.
func (s *Store) ListDiscoverySchedulesPage(ctx context.Context, tenantID, afterID string, limit int) ([]DiscoverySchedule, error) {
	var out []DiscoverySchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, source_id::text, name, interval_seconds, enabled, created_at, updated_at
			   FROM discovery_schedules
			  WHERE tenant_id = $1 AND id > $2
			  ORDER BY id LIMIT $3`, tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sched DiscoverySchedule
			if err := rows.Scan(&sched.ID, &sched.TenantID, &sched.SourceID, &sched.Name,
				&sched.IntervalSeconds, &sched.Enabled, &sched.CreatedAt, &sched.UpdatedAt); err != nil {
				return err
			}
			out = append(out, sched)
		}
		return rows.Err()
	})
	return out, err
}

// GetDiscoverySchedule loads a schedule in its tenant context.
func (s *Store) GetDiscoverySchedule(ctx context.Context, tenantID, id string) (DiscoverySchedule, error) {
	var out DiscoverySchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, source_id::text, name, interval_seconds, enabled, created_at, updated_at
			   FROM discovery_schedules WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&out.ID, &out.TenantID, &out.SourceID, &out.Name, &out.IntervalSeconds, &out.Enabled, &out.CreatedAt, &out.UpdatedAt)
	})
	return out, err
}

// GetDiscoveryRun loads a run in its tenant context.
func (s *Store) GetDiscoveryRun(ctx context.Context, tenantID, id string) (DiscoveryRun, error) {
	var out DiscoveryRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDiscoveryRun(tx.QueryRow(ctx, `SELECT id::text, tenant_id::text, source_id::text, schedule_id::text, status, dry_run,
		              requested_by, targets, discovered, failed, rejected, error, started_at, completed_at, created_at
		         FROM discovery_runs
		        WHERE tenant_id = $1 AND id = $2`, tenantID, id), &out)
	})
	return out, err
}

// ListDiscoveryRunsPage lists tenant runs by id keyset.
func (s *Store) ListDiscoveryRunsPage(ctx context.Context, tenantID, afterID string, limit int) ([]DiscoveryRun, error) {
	var out []DiscoveryRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text, source_id::text, schedule_id::text, status, dry_run,
		              requested_by, targets, discovered, failed, rejected, error, started_at, completed_at, created_at
		         FROM discovery_runs
		        WHERE tenant_id = $1 AND id > $2
		     ORDER BY id LIMIT $3`, tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var run DiscoveryRun
			if err := scanDiscoveryRun(rows, &run); err != nil {
				return err
			}
			out = append(out, run)
		}
		return rows.Err()
	})
	return out, err
}

// ListDiscoveryFindingsPage lists tenant findings, optionally scoped to one run.
func (s *Store) ListDiscoveryFindingsPage(ctx context.Context, tenantID, runID, afterID string, limit int) ([]DiscoveryFinding, error) {
	var out []DiscoveryFinding
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		sql := `SELECT id::text, tenant_id::text, run_id::text, source_id::text, kind, ref,
		              provenance, fingerprint, risk_score, metadata, discovered_at,
		              triage_status, managed_identity_id::text, triage_actor, triage_reason, triaged_at
		         FROM discovery_findings
		        WHERE tenant_id = $1 AND id > $2`
		args := []any{tenantID, afterID, limit}
		if runID != "" {
			sql += ` AND run_id = $4`
			args = append(args, runID)
		}
		sql += ` ORDER BY id LIMIT $3`
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f DiscoveryFinding
			if err := scanDiscoveryFinding(rows, &f); err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// GetDiscoveryFinding loads one tenant-scoped discovery finding.
func (s *Store) GetDiscoveryFinding(ctx context.Context, tenantID, id string) (DiscoveryFinding, error) {
	var out DiscoveryFinding
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDiscoveryFinding(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, run_id::text, source_id::text, kind, ref,
			        provenance, fingerprint, risk_score, metadata, discovered_at,
			        triage_status, managed_identity_id::text, triage_actor, triage_reason, triaged_at
			   FROM discovery_findings
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &out)
	})
	return out, err
}

func scanDiscoverySource(row rowScanner, src *DiscoverySource) error {
	var cfg []byte
	if err := row.Scan(&src.ID, &src.TenantID, &src.Kind, &src.Name, &cfg, &src.CreatedAt, &src.UpdatedAt); err != nil {
		return err
	}
	src.Config = json.RawMessage(cfg)
	return nil
}

func scanDiscoveryRun(row rowScanner, run *DiscoveryRun) error {
	return row.Scan(&run.ID, &run.TenantID, &run.SourceID, &run.ScheduleID, &run.Status, &run.DryRun,
		&run.RequestedBy, &run.Targets, &run.Discovered, &run.Failed, &run.Rejected, &run.Error,
		&run.StartedAt, &run.CompletedAt, &run.CreatedAt)
}

func scanDiscoveryFinding(row rowScanner, f *DiscoveryFinding) error {
	var meta []byte
	if err := row.Scan(&f.ID, &f.TenantID, &f.RunID, &f.SourceID, &f.Kind, &f.Ref,
		&f.Provenance, &f.Fingerprint, &f.RiskScore, &meta, &f.DiscoveredAt,
		&f.TriageStatus, &f.ManagedIdentityID, &f.TriageActor, &f.TriageReason, &f.TriagedAt); err != nil {
		return err
	}
	f.Metadata = json.RawMessage(meta)
	return nil
}
