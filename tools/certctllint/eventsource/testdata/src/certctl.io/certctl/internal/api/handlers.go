// Package api fixtures exercise AN-2: a //certctl:mutation handler must not
// write the read model directly through the store; it must emit an event.
package api

import "certctl.io/certctl/internal/store"

// emit stands in for appending a domain event to the log.
func emit(eventType string) error { _ = eventType; return nil }

// CreateOwnerBad writes the owners read table directly — the violation the
// audit found in the served handlers.
//
//certctl:mutation
func CreateOwnerBad(st *store.Store) error {
	_, err := st.CreateOwner("billing") // want "must not write the read model directly"
	return err
}

// UpsertCertBad writes the certificate read table directly.
//
//certctl:mutation
func UpsertCertBad(st *store.Store) error {
	return st.UpsertCertificate("fp-aaa") // want "must not write the read model directly"
}

// UpdateAndDeleteBad is two violations in one handler.
//
//certctl:mutation
func UpdateAndDeleteBad(st *store.Store) error {
	if err := st.UpdateOwner("id", "n"); err != nil { // want "must not write the read model directly"
		return err
	}
	return st.DeleteOwner("id") // want "must not write the read model directly"
}

// CreateOwnerGood emits an event instead, and may freely read the store to
// validate inputs. No direct read-model write, so it is compliant.
//
//certctl:mutation
func CreateOwnerGood(st *store.Store) error {
	if _, err := st.GetOwner("owner-1"); err != nil { // a read — allowed
		return err
	}
	return emit("owner.created")
}

// Unmarked is not a served mutation handler, so it is not constrained (it is the
// projector/command layer's job to write the read model).
func Unmarked(st *store.Store) error {
	_, err := st.CreateOwner("x")
	return err
}
