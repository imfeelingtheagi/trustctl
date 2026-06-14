// Package auditsink is the minimal write-seam for audited events used across the
// workload-identity, incident-response, and SSH-CA subsystems (Epochs 11–13).
//
// AN-2 makes every issuance and remediation an audited event. The existing
// internal/audit package is the *read* side (query/search/export over the event
// log); this package is the tiny *write* interface those subsystems depend on so
// they do not have to import the NATS-backed event log directly (which would make
// them impossible to unit-test). The control-plane assembly wires an adapter from
// this interface to events.Log.Append; unit tests use the Recorder double.
package auditsink

import (
	"context"
	"sync"
)

// Auditor records an audited event. eventType is a dotted name
// (e.g. "spiffe.svid.issued"); tenantID scopes it (AN-1); data is a JSON payload.
type Auditor interface {
	Audit(ctx context.Context, eventType, tenantID string, data []byte) error
}

// Nop discards events. A safe default when no auditor is wired.
type Nop struct{}

// Audit implements Auditor.
func (Nop) Audit(context.Context, string, string, []byte) error { return nil }

// Record is one captured audit event.
type Record struct {
	Type     string
	TenantID string
	Data     []byte
}

// Recorder is a thread-safe in-memory Auditor for tests: it lets a test assert
// the expected audit events were emitted (the AN-2 "is audited" acceptance).
type Recorder struct {
	mu      sync.Mutex
	records []Record
}

// Audit implements Auditor.
func (r *Recorder) Audit(_ context.Context, eventType, tenantID string, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	r.records = append(r.records, Record{Type: eventType, TenantID: tenantID, Data: cp})
	return nil
}

// Records returns a copy of all captured events.
func (r *Recorder) Records() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, len(r.records))
	copy(out, r.records)
	return out
}

// Count returns how many captured events have the given type.
func (r *Recorder) Count(eventType string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, rec := range r.records {
		if rec.Type == eventType {
			n++
		}
	}
	return n
}
