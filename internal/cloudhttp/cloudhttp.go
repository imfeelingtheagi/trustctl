// Package cloudhttp is the thin shared HTTP round-trip used by trustctl's cloud
// provider families (KMS backends, DNS-01 providers) so the common request/response
// plumbing — bounded reads, non-2xx error normalisation, JSON decode, and a per-call
// timeout floor — lives in one place instead of being copy-pasted into each
// provider's package-local call()/do() (CODE-006).
//
// It deliberately does NOT own auth or URL construction: each provider still builds
// its own *http.Request (endpoint, path, query, and the Authorization header — a
// bearer token, SigV4 signature, or API key — which is provider-specific and must
// stay local so it is never logged, AN-8). cloudhttp owns only the parts that were
// genuinely identical across providers:
//
//   - send the request through an injectable Doer (so tests pass a double),
//   - apply a per-call timeout floor when the caller's context has no deadline,
//   - read the body under a fixed cap so a hostile/huge response cannot exhaust
//     memory,
//   - turn a non-2xx status into a normalised error carrying the status and a
//     bounded, token-free snippet of the body,
//   - decode a 2xx JSON body into out (when out != nil).
//
// No cryptographic operation happens here, so it imports no crypto/* (AN-3).
//
// Adoption (CODE-006): the bearer-token KMS backends internal/kms/gcpkms and
// internal/kms/azurekv route their JSON round-trip through cloudhttp.JSON. Two
// provider families are deliberately NOT yet migrated and tracked as a follow-up:
// internal/kms/awskms authenticates with AWS SigV4 (a different request-signing
// model than a static bearer header) and the eight internal/dns/* DNS-01 providers
// each carry provider-specific request/response shapes (some return non-JSON or wrap
// results in idiosyncratic envelopes); folding those in needs per-provider care to
// avoid behavioural drift, so they keep their local do()/call() for now and adopt
// this helper incrementally.
package cloudhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Doer is the minimal HTTP client seam: production passes http.DefaultClient (or a
// backend's configured client); tests pass a double. It matches the *HTTPDoer*
// interface each provider already defines, so a provider's existing doer satisfies
// it without change.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

const (
	// MaxBodyBytes caps a successful (decoded) response body. 1 MiB is ample for a
	// KMS sign result or a DNS record list and bounds memory against a hostile peer.
	MaxBodyBytes = 1 << 20
	// MaxErrorBytes caps the snippet of a non-2xx body included in the error.
	MaxErrorBytes = 4096
)

// StatusError is a normalised non-2xx response. Body is the (bounded, trimmed)
// response text; provider error bodies carry an API message and never echo the
// request's bearer token / key, so surfacing them does not leak credentials (AN-8).
// Callers may wrap it with provider context (e.g. "azure-key-vault: sign: %w").
type StatusError struct {
	StatusCode int
	Body       string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("status %d: %s", e.StatusCode, e.Body)
}

// JSON sends req through doer and decodes a 2xx JSON response into out (out may be
// nil to discard the body). A non-2xx response yields a *StatusError with a bounded
// body snippet. If timeout > 0 AND req's context has no deadline, the request is
// bounded by timeout so an interface-forced context.Background() cannot hang a
// worker on a wedged endpoint (the CODE-002 timeout floor, shared here per CODE-006).
func JSON(doer Doer, req *http.Request, out any, timeout time.Duration) error {
	if timeout > 0 {
		if _, hasDeadline := req.Context().Deadline(); !hasDeadline {
			ctx, cancel := context.WithTimeout(req.Context(), timeout)
			defer cancel()
			req = req.WithContext(ctx)
		}
	}

	resp, err := doer.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBytes))
		return &StatusError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, MaxBodyBytes)).Decode(out)
}
