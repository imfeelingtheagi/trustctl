package orchestrator

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"certctl.io/certctl/internal/events"
	"certctl.io/certctl/internal/projections"
	"certctl.io/certctl/internal/store"
)

// This file holds the served domain commands (AN-2). Each records the mutation
// as an event (the source of truth), then projects it into the read model
// through the projector — the sole read-model writer. The served API delegates
// to these instead of writing the read tables directly, so a rebuild from the
// log reproduces every change and the audit trail is complete.

// emit appends a domain event to the log and projects it into the read model,
// returning the stored event (with its assigned ID, time, and sequence). The
// append is the source of truth; the projection is the same logic a rebuild
// uses, so live state and a replayed state agree.
func (o *Orchestrator) emit(ctx context.Context, eventType, tenantID string, payload []byte) (events.Event, error) {
	ev, err := o.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: payload})
	if err != nil {
		return events.Event{}, err
	}
	if err := o.proj.Apply(ctx, ev); err != nil {
		return events.Event{}, err
	}
	return ev, nil
}

// CreateOwner records an owner.created event and returns the new owner.
func (o *Orchestrator) CreateOwner(ctx context.Context, tenantID, kind, name, email string) (store.Owner, error) {
	id := uuid.NewString()
	payload, err := json.Marshal(projections.OwnerCreated{ID: id, Kind: kind, Name: name, Email: email})
	if err != nil {
		return store.Owner{}, err
	}
	ev, err := o.emit(ctx, projections.EventOwnerCreated, tenantID, payload)
	if err != nil {
		return store.Owner{}, err
	}
	return store.Owner{ID: id, TenantID: tenantID, Kind: store.OwnerKind(kind), Name: name, Email: email, CreatedAt: ev.Time}, nil
}

// UpdateOwner records an owner.updated event. It returns a not-found error
// (mapped to 404) when the owner does not exist, without emitting an event — so
// a no-op never produces a spurious event.
func (o *Orchestrator) UpdateOwner(ctx context.Context, tenantID, id, kind, name, email string) error {
	if _, err := o.store.GetOwner(ctx, tenantID, id); err != nil {
		return err
	}
	payload, err := json.Marshal(projections.OwnerUpdated{ID: id, Kind: kind, Name: name, Email: email})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventOwnerUpdated, tenantID, payload)
	return err
}

// DeleteOwner records an owner.deleted event (404 if absent, no event emitted).
func (o *Orchestrator) DeleteOwner(ctx context.Context, tenantID, id string) error {
	if _, err := o.store.GetOwner(ctx, tenantID, id); err != nil {
		return err
	}
	payload, err := json.Marshal(projections.OwnerDeleted{ID: id})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventOwnerDeleted, tenantID, payload)
	return err
}

// CreateIssuer records an issuer.created event and returns the new issuer. The
// caller is expected to have validated it (the structural issuer rules).
func (o *Orchestrator) CreateIssuer(ctx context.Context, tenantID string, in store.Issuer) (store.Issuer, error) {
	id := uuid.NewString()
	chain := in.Chain
	if chain == nil {
		chain = []string{}
	}
	payload, err := json.Marshal(projections.IssuerCreated{
		ID: id, Kind: string(in.Kind), Name: in.Name, Chain: chain, PublicKey: in.PublicKey, Internal: in.Internal,
	})
	if err != nil {
		return store.Issuer{}, err
	}
	ev, err := o.emit(ctx, projections.EventIssuerCreated, tenantID, payload)
	if err != nil {
		return store.Issuer{}, err
	}
	out := in
	out.ID, out.TenantID, out.Chain, out.CreatedAt = id, tenantID, chain, ev.Time
	return out, nil
}

// CreateIdentity records an identity.created event and returns the new identity
// in its initial lifecycle status.
func (o *Orchestrator) CreateIdentity(ctx context.Context, tenantID string, in store.Identity) (store.Identity, error) {
	id := uuid.NewString()
	payload, err := json.Marshal(projections.IdentityCreated{
		ID: id, Kind: string(in.Kind), Name: in.Name, OwnerID: in.OwnerID, IssuerID: in.IssuerID, Attributes: in.Attributes,
	})
	if err != nil {
		return store.Identity{}, err
	}
	ev, err := o.emit(ctx, projections.EventIdentityCreated, tenantID, payload)
	if err != nil {
		return store.Identity{}, err
	}
	out := in
	out.ID, out.TenantID, out.Status, out.CreatedAt = id, tenantID, string(StateRequested), ev.Time
	return out, nil
}

// RecordCertificate records a certificate.recorded event (keyed by fingerprint)
// and returns the canonical inventoried row — whose id and created_at are stable
// across a re-ingest of the same certificate.
func (o *Orchestrator) RecordCertificate(ctx context.Context, tenantID string, in store.Certificate) (store.Certificate, error) {
	id := uuid.NewString()
	sans := in.SANs
	if sans == nil {
		sans = []string{}
	}
	payload, err := json.Marshal(projections.CertificateRecorded{
		ID: id, OwnerID: in.OwnerID, Subject: in.Subject, SANs: sans, Issuer: in.Issuer, Serial: in.Serial,
		Fingerprint: in.Fingerprint, KeyAlgorithm: in.KeyAlgorithm, NotBefore: in.NotBefore, NotAfter: in.NotAfter,
		DeploymentLocation: in.DeploymentLocation, Source: in.Source,
	})
	if err != nil {
		return store.Certificate{}, err
	}
	if _, err := o.emit(ctx, projections.EventCertificateRecorded, tenantID, payload); err != nil {
		return store.Certificate{}, err
	}
	return o.store.GetCertificateByFingerprint(ctx, tenantID, in.Fingerprint)
}
