package projections

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trustctl.io/trustctl/internal/events"
	"trustctl.io/trustctl/internal/store"
)

// Event types for the served domain (AN-2). Every served mutation emits one of
// these; the read model is rebuilt by applying them. They are the contract
// between the command side (which appends them) and the projector (which builds
// the read model from them).
const (
	EventTenantRegistered    = "tenant.registered"
	EventOwnerCreated        = "owner.created"
	EventOwnerUpdated        = "owner.updated"
	EventOwnerDeleted        = "owner.deleted"
	EventIssuerCreated       = "issuer.created"
	EventIdentityCreated     = "identity.created"
	EventCertificateRecorded = "certificate.recorded"

	// identityPrefix marks the identity lifecycle events the orchestrator emits
	// (identity.issued, identity.deployed, …). The projector applies them as a
	// status change. identity.created is the one identity.* event that is not a
	// transition.
	identityPrefix = "identity."

	// initialIdentityStatus is the lifecycle status a newly-created identity
	// holds until a transition moves it (matches the identities.status column
	// default and orchestrator.StateRequested).
	initialIdentityStatus = "requested"
)

// Payloads. Each carries everything needed to reconstruct the read-model row
// (the surrogate id included), so a replay is deterministic. created_at is NOT a
// payload field: it is the event's own time, set by the projector, so a rebuild
// reproduces it exactly.

// OwnerCreated is the payload of an owner.created event.
type OwnerCreated struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// OwnerUpdated is the payload of an owner.updated event.
type OwnerUpdated struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// OwnerDeleted is the payload of an owner.deleted event.
type OwnerDeleted struct {
	ID string `json:"id"`
}

// IssuerCreated is the payload of an issuer.created event.
type IssuerCreated struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Chain     []string `json:"chain"`
	PublicKey string   `json:"public_key"`
	Internal  bool     `json:"internal"`
}

// IdentityCreated is the payload of an identity.created event.
type IdentityCreated struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Name       string          `json:"name"`
	OwnerID    string          `json:"owner_id"`
	IssuerID   *string         `json:"issuer_id"`
	Attributes json.RawMessage `json:"attributes"`
}

// CertificateRecorded is the payload of a certificate.recorded event.
type CertificateRecorded struct {
	ID                 string     `json:"id"`
	OwnerID            *string    `json:"owner_id"`
	Subject            string     `json:"subject"`
	SANs               []string   `json:"sans"`
	Issuer             string     `json:"issuer"`
	Serial             string     `json:"serial"`
	Fingerprint        string     `json:"fingerprint"`
	KeyAlgorithm       string     `json:"key_algorithm"`
	NotBefore          *time.Time `json:"not_before"`
	NotAfter           *time.Time `json:"not_after"`
	DeploymentLocation string     `json:"deployment_location"`
	Source             string     `json:"source"`
}

// identityTransition decodes the orchestrator's lifecycle event payload; the
// projector needs only the identity and the new status. (The contract is the
// JSON, so the projector does not import the orchestrator.)
type identityTransition struct {
	IdentityID string `json:"identity_id"`
	To         string `json:"to"`
}

// Projector derives PostgreSQL read models from the event stream (AN-2). The
// read model is always a projection of the log; nothing writes the served
// domain read model except through here.
type Projector struct {
	store *store.Store
}

// New returns a Projector that writes into s.
func New(s *store.Store) *Projector { return &Projector{store: s} }

type tenantRegistered struct {
	Name string `json:"name"`
}

// Apply applies a single event to the read model in its own tenant-scoped
// transaction. It is exported so the command side can project an event live,
// right after appending it, using the same logic a rebuild uses.
func (p *Projector) Apply(ctx context.Context, e events.Event) error {
	if e.Type == EventTenantRegistered {
		var payload tenantRegistered
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		return p.store.UpsertTenant(ctx, store.Tenant{
			TenantID: e.TenantID, Name: payload.Name, EventSeq: e.Sequence,
		})
	}
	// Domain entity events apply under the tenant's RLS context.
	return p.store.WithTenant(ctx, e.TenantID, func(tx pgx.Tx) error {
		return p.ApplyTx(ctx, tx, e)
	})
}

// ApplyTx applies a single domain event to the read model on the caller's
// transaction. The orchestrator uses it to project a lifecycle transition in the
// same transaction as the outbox enqueue (AN-6). Unknown event types are
// ignored, so projections are forward-compatible.
func (p *Projector) ApplyTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	switch e.Type {
	case EventOwnerCreated:
		var pl OwnerCreated
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyOwnerCreatedTx(ctx, tx, store.Owner{
			ID: pl.ID, TenantID: e.TenantID, Kind: store.OwnerKind(pl.Kind),
			Name: pl.Name, Email: pl.Email, CreatedAt: e.Time,
		})
	case EventOwnerUpdated:
		var pl OwnerUpdated
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyOwnerUpdatedTx(ctx, tx, store.Owner{
			ID: pl.ID, TenantID: e.TenantID, Kind: store.OwnerKind(pl.Kind), Name: pl.Name, Email: pl.Email,
		})
	case EventOwnerDeleted:
		var pl OwnerDeleted
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.DeleteOwnerTx(ctx, tx, e.TenantID, pl.ID)
	case EventIssuerCreated:
		var pl IssuerCreated
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyIssuerCreatedTx(ctx, tx, store.Issuer{
			ID: pl.ID, TenantID: e.TenantID, Kind: store.IssuerKind(pl.Kind), Name: pl.Name,
			Chain: pl.Chain, PublicKey: pl.PublicKey, Internal: pl.Internal, CreatedAt: e.Time,
		})
	case EventIdentityCreated:
		var pl IdentityCreated
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyIdentityCreatedTx(ctx, tx, store.Identity{
			ID: pl.ID, TenantID: e.TenantID, Kind: store.IdentityKind(pl.Kind), Name: pl.Name,
			OwnerID: pl.OwnerID, IssuerID: pl.IssuerID, Status: initialIdentityStatus,
			Attributes: pl.Attributes, CreatedAt: e.Time,
		})
	case EventCertificateRecorded:
		var pl CertificateRecorded
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.ApplyCertificateRecordedTx(ctx, tx, store.Certificate{
			ID: pl.ID, TenantID: e.TenantID, OwnerID: pl.OwnerID, Subject: pl.Subject, SANs: pl.SANs,
			Issuer: pl.Issuer, Serial: pl.Serial, Fingerprint: pl.Fingerprint, KeyAlgorithm: pl.KeyAlgorithm,
			NotBefore: pl.NotBefore, NotAfter: pl.NotAfter, DeploymentLocation: pl.DeploymentLocation,
			Source: pl.Source, CreatedAt: e.Time,
		})
	default:
		// An identity lifecycle transition (identity.issued, …) is a status change.
		if strings.HasPrefix(e.Type, identityPrefix) {
			var pl identityTransition
			if err := decode(e, &pl); err != nil {
				return err
			}
			return p.store.SetIdentityStatusTx(ctx, tx, e.TenantID, pl.IdentityID, pl.To)
		}
		return nil
	}
}

func decode(e events.Event, v any) error {
	if err := json.Unmarshal(e.Data, v); err != nil {
		return fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	return nil
}

// Project replays the log from the beginning and applies every event to the read
// model.
func (p *Projector) Project(ctx context.Context, log *events.Log) error {
	return log.Replay(ctx, 0, func(e events.Event) error {
		return p.Apply(ctx, e)
	})
}

// Rebuild discards the event-sourced read model and re-derives it from the whole
// log, reproducing the same state (AN-2). This is the disaster-recovery and
// migration primitive: the relational state is a pure function of the log.
func (p *Projector) Rebuild(ctx context.Context, log *events.Log) error {
	if err := p.store.TruncateReadModel(ctx); err != nil {
		return fmt.Errorf("projections: truncate: %w", err)
	}
	return p.Project(ctx, log)
}
