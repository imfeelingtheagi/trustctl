package backup_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"certctl.io/certctl/internal/backup"
	"certctl.io/certctl/internal/config"
	"certctl.io/certctl/internal/events"
)

const drTenant = "11111111-1111-1111-1111-111111111111"

func openLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func appendEvent(t *testing.T, log *events.Log, ctx context.Context, typ string, data string) {
	t.Helper()
	if _, err := log.Append(ctx, events.Event{Type: typ, TenantID: drTenant, Data: []byte(data)}); err != nil {
		t.Fatalf("append: %v", err)
	}
}

func collect(t *testing.T, log *events.Log) []events.Event {
	t.Helper()
	var got []events.Event
	if err := log.Replay(context.Background(), 0, func(e events.Event) error { got = append(got, e); return nil }); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	return got
}

// TestBackupRestoreRoundTrip is the R2.4 source-of-truth backup acceptance: the
// event log backs up to a portable stream and restores into a fresh log
// byte-for-byte — type, tenant, data, and the recorded actor (R2.1) all survive.
func TestBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	src := openLog(t)
	actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: "alice@example.com", Roles: []string{"admin"}})
	appendEvent(t, src, actorCtx, "owner.created", `{"name":"payments"}`)
	appendEvent(t, src, ctx, "certificate.recorded", `{"serial":"01"}`)
	appendEvent(t, src, actorCtx, "identity.issued", `{}`)

	var buf bytes.Buffer
	n, err := backup.WriteLog(ctx, src, &buf)
	if err != nil {
		t.Fatalf("WriteLog: %v", err)
	}
	if n != 3 {
		t.Fatalf("backed up %d events, want 3", n)
	}

	dst := openLog(t)
	m, err := backup.RestoreLog(ctx, dst, &buf)
	if err != nil {
		t.Fatalf("RestoreLog: %v", err)
	}
	if m != 3 {
		t.Fatalf("restored %d events, want 3", m)
	}

	got := collect(t, dst)
	if len(got) != 3 {
		t.Fatalf("restored log has %d events, want 3", len(got))
	}
	if got[0].Type != "owner.created" || got[0].TenantID != drTenant {
		t.Errorf("event 0 = %+v", got[0])
	}
	if got[0].Actor == nil || got[0].Actor.Subject != "alice@example.com" {
		t.Errorf("actor not preserved on restore: %+v", got[0].Actor)
	}
	if string(got[1].Data) != `{"serial":"01"}` {
		t.Errorf("data not preserved on restore: %s", got[1].Data)
	}
	if got[1].Actor != nil {
		t.Errorf("event 1 should remain unattributed, got %+v", got[1].Actor)
	}
}

// TestRestoreRefusesNonEmptyLog: restoring into a log that already has events is
// rejected, so a misdirected restore can't silently duplicate the stream.
func TestRestoreRefusesNonEmptyLog(t *testing.T) {
	ctx := context.Background()
	src := openLog(t)
	appendEvent(t, src, ctx, "owner.created", `{}`)
	var buf bytes.Buffer
	if _, err := backup.WriteLog(ctx, src, &buf); err != nil {
		t.Fatal(err)
	}

	dst := openLog(t)
	appendEvent(t, dst, ctx, "owner.created", `{}`)
	if _, err := backup.RestoreLog(ctx, dst, &buf); err == nil {
		t.Fatal("restore into a non-empty log must error")
	}
}

// TestRestoreRejectsBadHeader: a stream that is not a certctl backup is rejected.
func TestRestoreRejectsBadHeader(t *testing.T) {
	dst := openLog(t)
	if _, err := backup.RestoreLog(context.Background(), dst, strings.NewReader("garbage\n{}\n")); err == nil {
		t.Fatal("restore must reject a stream with no valid backup header")
	}
}
