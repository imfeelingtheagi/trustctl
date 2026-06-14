// Package secretshare provides one-time self-destructing secret-sharing links and
// secret-change approvals (S19.3, F60). A link is single-use — a second view
// returns nothing — and expiry-bound; single-use is enforced server-side. Secret
// *changes* go through the S12.3 approval primitive. All actions are audited
// (AN-2); shared material is []byte and never logged (AN-8).
package secretshare

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"trustctl.io/trustctl/internal/approval"
	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/crypto"
)

type link struct {
	secret    []byte
	expiresAt time.Time
	viewed    bool
}

// Sharer issues and redeems one-time secret links.
type Sharer struct {
	tenantID string
	audit    auditsink.Auditor
	clock    func() time.Time
	mu       sync.Mutex
	links    map[string]*link
}

// New constructs a Sharer.
func New(tenantID string, audit auditsink.Auditor, clock func() time.Time) *Sharer {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	if clock == nil {
		clock = time.Now
	}
	return &Sharer{tenantID: tenantID, audit: audit, clock: clock, links: map[string]*link{}}
}

// Create stores a secret behind a single-use token that expires after ttl.
func (s *Sharer) Create(ctx context.Context, secret []byte, ttl time.Duration) (string, error) {
	tb, err := crypto.RandomBytes(16)
	if err != nil {
		return "", err
	}
	token := hex.EncodeToString(tb)
	s.mu.Lock()
	s.links[token] = &link{secret: append([]byte(nil), secret...), expiresAt: s.clock().Add(ttl)}
	s.mu.Unlock()
	_ = s.audit.Audit(ctx, "secret.shared", s.tenantID, []byte(fmt.Sprintf(`{"token":%q}`, token)))
	return token, nil
}

// View returns the shared secret exactly once. A second view, or a view after
// expiry, returns an error and the link is destroyed.
func (s *Sharer) View(ctx context.Context, token string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[token]
	if !ok {
		return nil, fmt.Errorf("secretshare: link not found or already consumed")
	}
	if l.viewed || s.clock().After(l.expiresAt) {
		delete(s.links, token)
		return nil, fmt.Errorf("secretshare: link expired or already viewed")
	}
	l.viewed = true
	secret := l.secret
	delete(s.links, token) // self-destruct on first successful view
	_ = s.audit.Audit(ctx, "secret.share.viewed", s.tenantID, []byte(fmt.Sprintf(`{"token":%q}`, token)))
	return secret, nil
}

// changeIssuer adapts an apply func to approval.Issuer.
type changeIssuer struct {
	apply func(ctx context.Context, reqID, resource string) (string, error)
}

func (c changeIssuer) Issue(ctx context.Context, _ /*tenantID*/, reqID, resource string) (string, error) {
	return c.apply(ctx, reqID, resource)
}

// NewChangeApprovals returns an approval.Manager (S12.3) configured so an approved
// secret change is applied via apply — GitOps-style approval over secret
// mutations, reusing the Phase-2 approval primitive on the secrets surface.
func NewChangeApprovals(tenantID string, apply func(ctx context.Context, reqID, resource string) (string, error), audit auditsink.Auditor) (*approval.Manager, error) {
	return approval.New(approval.Config{
		TenantID: tenantID,
		Store:    approval.NewMemoryStore(),
		Issuer:   changeIssuer{apply: apply},
		Audit:    audit,
	})
}
