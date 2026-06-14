// Package secretsdk is the secrets SDK core (S19.2, F64): a client that fetches
// secrets and short-lived credentials, caches them, auto-refreshes before expiry,
// and fails safe — a revoked credential is rejected on the next refresh. This Go
// SDK is the reference; the Python/Node/Java SDKs follow the same template and the
// shared conformance behavior exercised here. Cached material is []byte and never
// logged (AN-8).
package secretsdk

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Fetcher retrieves a secret and its expiry from the serving secrets engine. It
// encapsulates auth-method/attestation login; a revoked credential surfaces as an
// error here.
type Fetcher interface {
	Fetch(ctx context.Context, path string) (value []byte, expiresAt time.Time, err error)
}

// Client caches and auto-refreshes secrets.
type Client struct {
	fetcher  Fetcher
	clock    func() time.Time
	fraction float64 // refresh once this fraction of lifetime has elapsed
	mu       sync.Mutex
	cache    map[string]entry
}

type entry struct {
	value     []byte
	issuedAt  time.Time
	expiresAt time.Time
}

// Option configures a Client.
type Option func(*Client)

// WithClock overrides the clock (tests).
func WithClock(f func() time.Time) Option { return func(c *Client) { c.clock = f } }

// WithRefreshFraction sets the lifetime fraction after which Get refreshes.
func WithRefreshFraction(f float64) Option { return func(c *Client) { c.fraction = f } }

// New constructs a Client.
func New(fetcher Fetcher, opts ...Option) *Client {
	c := &Client{fetcher: fetcher, clock: time.Now, fraction: 0.5, cache: map[string]entry{}}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Get returns a secret, serving from cache while fresh and refreshing once the
// refresh threshold is passed. A refresh failure (e.g. a revoked credential)
// evicts the cache entry and returns an error — fail-safe, never a stale secret.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	c.mu.Lock()
	e, ok := c.cache[path]
	c.mu.Unlock()
	now := c.clock()
	if ok && now.Before(c.refreshAt(e)) {
		return e.value, nil
	}
	value, expiresAt, err := c.fetcher.Fetch(ctx, path)
	if err != nil {
		c.mu.Lock()
		delete(c.cache, path)
		c.mu.Unlock()
		return nil, fmt.Errorf("secretsdk: refresh failed (fail-safe): %w", err)
	}
	c.mu.Lock()
	c.cache[path] = entry{value: value, issuedAt: now, expiresAt: expiresAt}
	c.mu.Unlock()
	return value, nil
}

func (c *Client) refreshAt(e entry) time.Time {
	life := e.expiresAt.Sub(e.issuedAt)
	if life <= 0 {
		return e.issuedAt // always refresh
	}
	return e.issuedAt.Add(time.Duration(float64(life) * c.fraction))
}
