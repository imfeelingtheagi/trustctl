package secretstore

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
)

func newStore(t *testing.T, rec auditsink.Auditor) *Store {
	t.Helper()
	kek, _ := crypto.NewKEK()
	s, err := New(Config{TenantID: "t1", KEK: kek, Audit: rec})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStoreVersionRollback(t *testing.T) {
	s := newStore(t, nil)
	ctx := context.Background()
	if _, err := s.Put(ctx, "app/db", []byte("v1"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "app/db", []byte("v2"), ""); err != nil {
		t.Fatal(err)
	}
	got, ver, err := s.Get(ctx, "app/db")
	if err != nil || string(got) != "v2" || ver != 2 {
		t.Fatalf("get latest = %q v%d (err %v), want v2 v2", got, ver, err)
	}
	if vs := s.Versions("app/db"); len(vs) != 2 {
		t.Errorf("versions = %v, want 2", vs)
	}
	// Rollback to v1 creates v3 with v1's content.
	nv, err := s.Rollback(ctx, "app/db", 1)
	if err != nil || nv != 3 {
		t.Fatalf("rollback -> v%d (err %v), want v3", nv, err)
	}
	got, _, _ = s.Get(ctx, "app/db")
	if string(got) != "v1" {
		t.Errorf("after rollback latest = %q, want v1", got)
	}
}

func TestStoreIdempotentWrite(t *testing.T) {
	s := newStore(t, nil)
	ctx := context.Background()
	v1, _ := s.Put(ctx, "p", []byte("x"), "key-1")
	v2, _ := s.Put(ctx, "p", []byte("x"), "key-1") // replay
	if v1 != v2 {
		t.Errorf("idempotent replay made a new version: %d vs %d", v1, v2)
	}
	if vs := s.Versions("p"); len(vs) != 1 {
		t.Errorf("idempotent replay wrote %d versions, want 1", len(vs))
	}
}

func TestStoreEncryptionAtRestAndNoPlaintextInLog(t *testing.T) {
	rec := &auditsink.Recorder{}
	s := newStore(t, rec)
	ctx := context.Background()
	secret := []byte("TOPSECRET-PLAINTEXT")
	if _, err := s.Put(ctx, "app/key", secret, ""); err != nil {
		t.Fatal(err)
	}
	// AN-8: the plaintext must never appear in any audit/event payload.
	for _, r := range rec.Records() {
		if bytes.Contains(r.Data, secret) {
			t.Fatalf("plaintext leaked into event %q", r.Type)
		}
	}
}

func TestStoreVersionHistoryReconstructsFromEvents(t *testing.T) {
	rec := &auditsink.Recorder{}
	s := newStore(t, rec)
	ctx := context.Background()
	_, _ = s.Put(ctx, "app/db", []byte("v1"), "")
	_, _ = s.Put(ctx, "app/db", []byte("v2"), "")

	// Rebuild from the event log alone (AN-2 projection).
	records := rec.Records()
	var written writeEvent
	if err := json.Unmarshal(records[0].Data, &written); err != nil {
		t.Fatal(err)
	}
	if written.Envelope.Format != crypto.EnvelopeFormat || written.Envelope.Version != crypto.EnvelopeVersion {
		t.Fatalf("version-written event envelope metadata = %q v%d, want %q v%d",
			written.Envelope.Format, written.Envelope.Version, crypto.EnvelopeFormat, crypto.EnvelopeVersion)
	}
	rebuilt, err := Reconstruct(records, "t1")
	if err != nil {
		t.Fatal(err)
	}
	envs := rebuilt["app/db"]
	if len(envs) != 2 {
		t.Fatalf("reconstructed %d versions, want 2", len(envs))
	}
	kek := s.kek
	pt, err := crypto.OpenEnvelope(kek, envs[1], []byte("t1|app/db"))
	if err != nil || string(pt) != "v2" {
		t.Fatalf("decrypt reconstructed v2 = %q (err %v), want v2", pt, err)
	}
}

func TestStoreReconstructAcceptsLegacyEnvelopeVersion(t *testing.T) {
	kek, _ := crypto.NewKEK()
	env, err := crypto.SealEnvelope(kek, []byte("legacy-v1"), []byte("t1|app/db"))
	if err != nil {
		t.Fatal(err)
	}
	env.Format = ""
	env.Version = 0
	payload, err := json.Marshal(writeEvent{Path: "app/db", Version: 1, Envelope: env})
	if err != nil {
		t.Fatal(err)
	}

	rebuilt, err := Reconstruct([]auditsink.Record{{
		Type:     EventVersionWritten,
		TenantID: "t1",
		Data:     payload,
	}}, "t1")
	if err != nil {
		t.Fatal(err)
	}
	envs := rebuilt["app/db"]
	if len(envs) != 1 {
		t.Fatalf("reconstructed %d versions, want 1", len(envs))
	}
	if envs[0].Format != crypto.EnvelopeFormat || envs[0].Version != crypto.EnvelopeVersion {
		t.Fatalf("legacy envelope normalized to %q v%d, want %q v%d",
			envs[0].Format, envs[0].Version, crypto.EnvelopeFormat, crypto.EnvelopeVersion)
	}
	pt, err := crypto.OpenEnvelope(kek, envs[0], []byte("t1|app/db"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "legacy-v1" {
		t.Fatalf("legacy reconstructed plaintext = %q, want legacy-v1", pt)
	}
}

func TestStoreReconstructRejectsUnknownEnvelopeVersion(t *testing.T) {
	kek, _ := crypto.NewKEK()
	env, err := crypto.SealEnvelope(kek, []byte("future"), []byte("t1|app/db"))
	if err != nil {
		t.Fatal(err)
	}
	env.Version = crypto.EnvelopeVersion + 1
	payload, err := json.Marshal(writeEvent{Path: "app/db", Version: 1, Envelope: env})
	if err != nil {
		t.Fatal(err)
	}

	_, err = Reconstruct([]auditsink.Record{{
		Type:     EventVersionWritten,
		TenantID: "t1",
		Data:     payload,
	}}, "t1")
	if err == nil {
		t.Fatal("Reconstruct accepted an explicitly unknown envelope version")
	}
}

func TestStoreSoftDelete(t *testing.T) {
	s := newStore(t, nil)
	ctx := context.Background()
	_, _ = s.Put(ctx, "p", []byte("v1"), "")
	if err := s.Delete(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(ctx, "p"); err == nil {
		t.Error("Get returned a soft-deleted secret")
	}
}
