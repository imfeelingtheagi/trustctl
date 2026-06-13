// Package backup serializes the event log — the AN-2 source of truth — to a
// portable, versioned stream, and restores it into a fresh log. Because the
// relational read model is a pure projection of the log (R1.1), restoring the log
// and rebuilding the projections reconstructs the whole control plane after a
// disaster (R2.4). The backup carries the full event envelope, including the
// recorded actor (R2.1), so the recovered audit trail is intact.
package backup

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"trustctl.io/trustctl/internal/events"
)

const (
	formatTag = "trustctl-event-log-backup"
	version   = 1
)

// header is the first line of a backup stream — a self-describing, versioned
// envelope so a restore can refuse a stranger's file or a future format.
type header struct {
	Format    string    `json:"format"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// record is one event as written to the backup. Sequence is intentionally omitted
// — it is reassigned contiguously when the events are re-appended on restore.
type record struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	TenantID string          `json:"tenant_id"`
	Time     time.Time       `json:"time"`
	Data     json.RawMessage `json:"data,omitempty"`
	Actor    *events.Actor   `json:"actor,omitempty"`
}

// WriteLog streams every event in log to w as a versioned backup and returns the
// count. The format is newline-delimited JSON: a header line followed by one
// record per event, in append order.
func WriteLog(ctx context.Context, log *events.Log, w io.Writer) (int, error) {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	if err := enc.Encode(header{Format: formatTag, Version: version, CreatedAt: time.Now().UTC()}); err != nil {
		return 0, err
	}
	n := 0
	err := log.Replay(ctx, 0, func(e events.Event) error {
		if err := enc.Encode(record{
			ID: e.ID, Type: e.Type, TenantID: e.TenantID, Time: e.Time,
			Data: json.RawMessage(e.Data), Actor: e.Actor,
		}); err != nil {
			return err
		}
		n++
		return nil
	})
	if err != nil {
		return n, err
	}
	return n, bw.Flush()
}

// RestoreLog reads a backup stream from r and appends its events, in order, into
// log — which must be empty, so a misdirected restore cannot duplicate a stream.
// It preserves each event's id, time, and actor; the sequence is reassigned
// contiguously by the log. It returns the count restored.
func RestoreLog(ctx context.Context, log *events.Log, r io.Reader) (int, error) {
	if !empty(ctx, log) {
		return 0, errors.New("backup: restore target log is not empty (restore into a fresh event store)")
	}
	dec := json.NewDecoder(bufio.NewReader(r))

	var h header
	if err := dec.Decode(&h); err != nil {
		return 0, fmt.Errorf("backup: read header: %w", err)
	}
	if h.Format != formatTag {
		return 0, fmt.Errorf("backup: not a trustctl event-log backup (format %q)", h.Format)
	}
	if h.Version != version {
		return 0, fmt.Errorf("backup: unsupported backup version %d (want %d)", h.Version, version)
	}

	n := 0
	for {
		var rec record
		err := dec.Decode(&rec)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return n, fmt.Errorf("backup: decode record %d: %w", n+1, err)
		}
		if _, err := log.Append(ctx, events.Event{
			ID: rec.ID, Type: rec.Type, TenantID: rec.TenantID, Time: rec.Time,
			Data: []byte(rec.Data), Actor: rec.Actor,
		}); err != nil {
			return n, fmt.Errorf("backup: append record %d: %w", n+1, err)
		}
		n++
	}
	return n, nil
}

// empty reports whether the log has no events (short-circuiting on the first one).
func empty(ctx context.Context, log *events.Log) bool {
	found := false
	stop := errors.New("stop")
	err := log.Replay(ctx, 0, func(events.Event) error { found = true; return stop })
	if err != nil && !errors.Is(err, stop) {
		// On a replay error, treat the log as non-empty so a restore never appends
		// into an unknown state.
		return false
	}
	return !found
}
