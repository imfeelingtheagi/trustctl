package projections

import (
	"context"
	"encoding/json"
	"errors"
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
	EventCertificateRevoked  = "certificate.revoked"

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

// CertificateRevoked is the payload of a certificate.revoked event. The
// inventoried certificate is keyed by fingerprint; the projector sets its status
// to revoked with the reason and time. Driving the status change through an event
// (rather than a direct read-table UPDATE) keeps it reconstructable from the log
// on a Rebuild() (AN-2).
type CertificateRevoked struct {
	Fingerprint string    `json:"fingerprint"`
	Serial      string    `json:"serial"`
	Reason      string    `json:"reason"`
	RevokedAt   time.Time `json:"revoked_at"`
}

// identityTransition decodes the orchestrator's lifecycle event payload. The
// projector applies the new status to the identity row AND appends the full
// transition to the identity_transitions read model (SPINE-001), so History/State
// read an indexed, tenant-scoped projection instead of replaying the whole log.
// (The contract is the JSON, so the projector does not import the orchestrator.)
type identityTransition struct {
	IdentityID string `json:"identity_id"`
	From       string `json:"from"`
	To         string `json:"to"`
	Reason     string `json:"reason,omitempty"`
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

// knownSchemaVersions records, per event type the projector decodes, the set of
// payload-shape versions it knows how to apply (SCHEMA-001). A *known* type that
// arrives with a version not in its set is rejected rather than decoded with the
// wrong shape — the failure mode the version field exists to prevent on a replay
// or rebuild. Adding a new payload shape for an existing type means adding its
// version here together with a decoder branch that handles it.
//
// An event type absent from this map is not version-gated: it is either an
// unknown type (ignored, keeping projections forward-compatible to new types) or
// an identity.* lifecycle transition (handled by prefix below). Only types with
// an explicit decoder are gated, because only they would mis-project silently.
var knownSchemaVersions = map[string]map[int]bool{
	EventOwnerCreated:        {1: true},
	EventOwnerUpdated:        {1: true},
	EventOwnerDeleted:        {1: true},
	EventIssuerCreated:       {1: true},
	EventIdentityCreated:     {1: true},
	EventCertificateRecorded: {1: true},
	EventCertificateRevoked:  {1: true},
}

// ErrUnknownSchemaVersion is returned by ApplyTx when a known event type carries
// a schema version the projector does not understand (SCHEMA-001). Failing here —
// rather than decoding the wrong shape — keeps a rebuild correct across schema
// evolution: a forgotten projector update surfaces as a hard error on replay, not
// a silently wrong read model.
var ErrUnknownSchemaVersion = errors.New("projections: unknown event schema version")

// schemaVersionOf normalizes the envelope version: a legacy/zero version is the
// baseline (DefaultSchemaVersion), matching how the event log reconstructs it.
func schemaVersionOf(e events.Event) int {
	if e.SchemaVersion == 0 {
		return events.DefaultSchemaVersion
	}
	return e.SchemaVersion
}

// ApplyTx applies a single domain event to the read model on the caller's
// transaction. The orchestrator uses it to project a lifecycle transition in the
// same transaction as the outbox enqueue (AN-6). Unknown event types are
// ignored, so projections are forward-compatible to *new* types; a *known* type
// carrying an unknown schema version is rejected (SCHEMA-001), so a payload-shape
// change to an existing type cannot silently mis-project on replay/rebuild.
func (p *Projector) ApplyTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	// Version gate (SCHEMA-001): for a type this projector decodes, the envelope's
	// schema version must be one it knows. An unrecognized version fails closed
	// rather than being decoded against the wrong struct.
	if versions, gated := knownSchemaVersions[e.Type]; gated {
		if v := schemaVersionOf(e); !versions[v] {
			return fmt.Errorf("%w: type %q v%d (seq %d)", ErrUnknownSchemaVersion, e.Type, v, e.Sequence)
		}
	}
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
	case EventCertificateRevoked:
		var pl CertificateRevoked
		if err := decode(e, &pl); err != nil {
			return err
		}
		return p.store.SetCertificateRevokedTx(ctx, tx, e.TenantID, pl.Fingerprint, pl.Reason, pl.RevokedAt)
	default:
		// An identity lifecycle transition (identity.issued, …) updates the
		// identity's status AND is recorded in the identity_transitions read model
		// so History/State are a bounded, tenant-scoped read rather than a full
		// cross-tenant log replay (SPINE-001). Both writes share this transaction,
		// so the projection of one transition is atomic.
		if strings.HasPrefix(e.Type, identityPrefix) {
			var pl identityTransition
			if err := decode(e, &pl); err != nil {
				return err
			}
			if err := p.store.SetIdentityStatusTx(ctx, tx, e.TenantID, pl.IdentityID, pl.To); err != nil {
				return err
			}
			return p.store.AppendIdentityTransitionTx(ctx, tx, e.TenantID, store.IdentityTransition{
				IdentityID: pl.IdentityID, Seq: e.Sequence, FromState: pl.From, ToState: pl.To,
				EventType: e.Type, Reason: pl.Reason, OccurredAt: e.Time,
			})
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
