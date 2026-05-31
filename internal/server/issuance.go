package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/crypto/certinfo"
	"certctl.io/certctl/internal/orchestrator"
	"certctl.io/certctl/internal/store"
)

// leafTTL is the validity of a certificate issued by the assembled CA. It is
// comfortably within the issuing CA's own validity so the leaf never outlives it.
const leafTTL = 30 * 24 * time.Hour

// issueFunc mints a leaf certificate from a CSR (Server.IssueLeaf satisfies it).
type issueFunc func(ctx context.Context, csrDER []byte, ttl time.Duration) ([]byte, error)

// issuanceDispatcher is the real outbox handler (AN-6): for a requested→issued
// lifecycle transition it mints a leaf certificate from the assembled CA (whose
// key lives in the out-of-process signer, AN-4) and records it in the inventory
// as an event (AN-2). It is idempotent on the outbox message's key (AN-5), so a
// redelivery never mints a second certificate.
type issuanceDispatcher struct {
	issue issueFunc
	orch  *orchestrator.Orchestrator
	idem  *orchestrator.Idempotency
	store *store.Store
}

// Deliver implements orchestrator.Handler. It mints on a ca.issue trigger and
// acknowledges every other destination (e.g. connector.deploy) so an as-yet
// unrouted entry does not accumulate retries; routing those is a follow-up.
func (d *issuanceDispatcher) Deliver(ctx context.Context, m orchestrator.Message) error {
	if m.Destination == "ca.issue" {
		return d.handleIssue(ctx, m)
	}
	return nil
}

// issueTrigger is the part of the lifecycle transition payload issuance needs.
type issueTrigger struct {
	IdentityID string `json:"identity_id"`
	To         string `json:"to"`
}

func (d *issuanceDispatcher) handleIssue(ctx context.Context, m orchestrator.Message) error {
	var p issueTrigger
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("server: decode ca.issue payload: %w", err)
	}
	// Only a requested→issued transition triggers minting. Other ca.issue entries
	// (e.g. the IssuanceService's post-issuance observability record) are
	// acknowledged.
	if p.IdentityID == "" || p.To != string(orchestrator.StateIssued) {
		return nil
	}
	// Idempotent on the outbox key: a redelivery returns the recorded result
	// without minting again (AN-5 ↔ AN-6).
	_, err := d.idem.Do(ctx, m.TenantID, "issue:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		ident, err := d.store.GetIdentity(ctx, m.TenantID, p.IdentityID)
		if err != nil {
			return nil, fmt.Errorf("server: load identity %s: %w", p.IdentityID, err)
		}
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			return nil, err
		}
		defer key.Destroy()
		cn := ident.Name
		csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: []string{cn}}, key)
		if err != nil {
			return nil, err
		}
		leafPEM, err := d.issue(ctx, csrDER, leafTTL)
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(leafPEM)
		if blk == nil {
			return nil, errors.New("server: issued certificate is not PEM")
		}
		info, err := certinfo.Inspect(blk.Bytes)
		if err != nil {
			return nil, err
		}
		owner := ident.OwnerID
		nb, na := info.NotBefore, info.NotAfter
		if _, err := d.orch.RecordCertificate(ctx, m.TenantID, store.Certificate{
			OwnerID: &owner, Subject: info.Subject, SANs: sansOf(info),
			Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
			KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
			Source: "issued",
		}); err != nil {
			return nil, err
		}
		return []byte(info.SHA256Fingerprint), nil
	})
	return err
}

// sansOf collects the subject alternative names from a parsed certificate.
func sansOf(info certinfo.Info) []string {
	sans := make([]string, 0, len(info.DNSNames)+len(info.IPAddresses)+len(info.EmailAddresses)+len(info.URIs))
	sans = append(sans, info.DNSNames...)
	sans = append(sans, info.IPAddresses...)
	sans = append(sans, info.EmailAddresses...)
	sans = append(sans, info.URIs...)
	return sans
}
