package secretsdk

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeFetcher struct {
	mu      sync.Mutex
	calls   int
	value   []byte
	ttl     time.Duration
	now     func() time.Time
	failNow bool // simulate a revoked credential
}

func (f *fakeFetcher) Fetch(_ context.Context, _ string) ([]byte, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failNow {
		return nil, time.Time{}, errors.New("credential revoked")
	}
	return f.value, f.now().Add(f.ttl), nil
}

func TestSDKCachesAndRefreshes(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	f := &fakeFetcher{value: []byte("v"), ttl: time.Hour, now: clock}
	c := New(f, WithClock(clock), WithRefreshFraction(0.5))
	ctx := context.Background()

	if _, err := c.Get(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "p"); err != nil { // within fresh window → cached
		t.Fatal(err)
	}
	if f.calls != 1 {
		t.Errorf("fetch called %d times within fresh window, want 1 (cache)", f.calls)
	}
	// Advance past the refresh threshold (>50% of a 1h lifetime).
	now = now.Add(40 * time.Minute)
	if _, err := c.Get(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if f.calls != 2 {
		t.Errorf("fetch called %d times after refresh threshold, want 2", f.calls)
	}
}

func TestSDKFailsSafeOnRevokedRefresh(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	f := &fakeFetcher{value: []byte("v"), ttl: time.Hour, now: clock}
	c := New(f, WithClock(clock), WithRefreshFraction(0.5))
	ctx := context.Background()
	if _, err := c.Get(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	// Credential revoked; advance past refresh so the next Get refreshes.
	f.failNow = true
	now = now.Add(40 * time.Minute)
	if _, err := c.Get(ctx, "p"); err == nil {
		t.Error("Get returned a value despite a revoked credential on refresh (not fail-safe)")
	}
}
