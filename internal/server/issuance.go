package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/crypto/certinfo"
	"trustctl.io/trustctl/internal/orchestrator"
	"trustctl.io/trustctl/internal/store"
)

// leafTTL is the validity of a certificate issued by the assembled CA. It is
// comfortably within the issuing CA's own validity so the leaf never outlives it.
const leafTTL = 30 * 24 * time.Hour

// caNamespace is the fixed UUIDv5 namespace under which the served binary's
// stable CA handles are turned into the ca_id used by the revocation tables. It
// never changes, so a CA's ca_id is the same across restarts and the
// issued/revoked records for it line up over time.
var caNamespace = uuid.MustParse("8f6a0c1e-4d2b-5a3c-9e7f-1b2c3d4e5f60")

// IssuingCAID is the deterministic ca_id of the served binary's single issuing
// CA (keyed off the stable issuing-CA signer handle). It is the CA identifier
// recorded in ca_issued_certs / ca_crls for every leaf the served path mints,
// so the OCSP responder and CRL generator (and the served revocation handler)
// resolve the same CA. It is stable across restarts and shared by all tenants
// (the issuing CA is shared infrastructure; rows stay tenant-isolated by
// tenant_id under RLS).
func IssuingCAID() string {
	return uuid.NewSHA1(caNamespace, []byte(issuingCAHandle)).String()
}

// issueFunc mints a leaf certificate from a CSR (Server.IssueLeaf satisfies it).
type issueFunc func(ctx context.Context, csrDER []byte, ttl time.Duration) ([]byte, error)

// issuanceDispatcher is the real outbox handler (AN-6). For a requested→issued
// lifecycle transition it mints a leaf certificate from the assembled CA (whose
// key lives in the out-of-process signer, AN-4) and records it in the inventory
// as an event (AN-2); for an *→revoked transition it revokes that leaf so the
// certificate stops validating — the inventory status flips to revoked (via a
// projected certificate.revoked event, AN-2) and the serial is written to the
// revocation table (ca_issued_certs) that backs OCSP/CRL. It is idempotent on
// the outbox message's key (AN-5), so a redelivery never mints a second
// certificate nor double-revokes.
type issuanceDispatcher struct {
	issue issueFunc
	orch  *orchestrator.Orchestrator
	idem  *orchestrator.Idempotency
	store *store.Store
}

// Deliver implements orchestrator.Handler. It mints on a ca.issue trigger,
// revokes on a revocation.publish trigger, and acknowledges every other
// destination (e.g. connector.deploy) so an as-yet unrouted entry does not
// accumulate retries; routing those is a follow-up.
func (d *issuanceDispatcher) Deliver(ctx context.Context, m orchestrator.Message) error {
	switch m.Destination {
	case "ca.issue":
		return d.handleIssue(ctx, m)
	case "revocation.publish":
		return d.handleRevoke(ctx, m)
	default:
		return nil
	}
}

// transitionTrigger is the part of a lifecycle transition payload the issuance
// and revocation handlers need (the same JSON the orchestrator enqueues on the
// outbox entry).
type transitionTrigger struct {
	IdentityID string `json:"identity_id"`
	To         string `json:"to"`
	Reason     string `json:"reason"`
}

func (d *issuanceDispatcher) handleIssue(ctx context.Context, m orchestrator.Message) error {
	var p transitionTrigger
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
		// Bridge the minted serial into the revocation table (ca_issued_certs) so
		// the OCSP responder can answer good-vs-unknown and so a later revoke has a
		// row to flip (the link the inventory and the responder previously lacked).
		// Idempotent in the store (ON CONFLICT DO NOTHING).
		if err := d.store.RecordIssuedCert(ctx, m.TenantID, IssuingCAID(), info.SerialNumber, time.Now()); err != nil {
			return nil, err
		}
		return []byte(info.SHA256Fingerprint), nil
	})
	return err
}

// handleRevoke processes a revocation.publish outbox entry (the side effect of an
// *→revoked lifecycle transition): it actually invalidates the identity's issued
// certificate(s). For each active issued cert it (1) emits a certificate.revoked
// event so the inventory status is projected to revoked (AN-2), and (2) records
// the serial revoked in the revocation table (ca_issued_certs) that backs OCSP
// and the CRL. It is idempotent on the outbox key (AN-5): a redelivery returns
// the recorded result rather than revoking again, and the store keeps the first
// revocation time. All access is tenant-scoped under RLS (AN-1).
//
// Note: the served binary's CA key lives in the signer (AN-4), so signing live
// OCSP responses and CRLs (which need the CA private key in process) is the
// separate EXC-REVOKE-01 epic. This handler makes revocation real and recorded —
// the certificate stops validating and the revocation is on record for the
// responder/CRL — without holding a key in the control plane.
func (d *issuanceDispatcher) handleRevoke(ctx context.Context, m orchestrator.Message) error {
	var p transitionTrigger
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("server: decode revocation.publish payload: %w", err)
	}
	if p.IdentityID == "" || p.To != string(orchestrator.StateRevoked) {
		return nil
	}
	_, err := d.idem.Do(ctx, m.TenantID, "revoke:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		ident, err := d.store.GetIdentity(ctx, m.TenantID, p.IdentityID)
		if err != nil {
			return nil, fmt.Errorf("server: load identity %s: %w", p.IdentityID, err)
		}
		certs, err := d.store.ListActiveIssuedCertificatesForIdentity(ctx, m.TenantID, ident.OwnerID, ident.Name)
		if err != nil {
			return nil, fmt.Errorf("server: find issued certs for identity %s: %w", p.IdentityID, err)
		}
		reason := p.Reason
		if reason == "" {
			reason = "unspecified"
		}
		// reasonCode 0 == unspecified (RFC 5280); the human-readable reason is kept
		// on the inventory row. A richer reason->code mapping is future work.
		const reasonCode = 0
		now := time.Now()
		for _, c := range certs {
			// Flip the inventory status through a projected event (AN-2), so it
			// survives a read-model Rebuild() rather than being a lost direct write.
			if err := d.orch.RevokeCertificate(ctx, m.TenantID, c.Fingerprint, c.Serial, reason, now); err != nil {
				return nil, err
			}
			// Record the serial revoked in the responder's table so OCSP/CRL reflect
			// it. Skip an empty serial (a malformed/legacy row) rather than erroring.
			if c.Serial != "" {
				if err := d.store.RevokeIssuedCert(ctx, m.TenantID, IssuingCAID(), c.Serial, reasonCode, now); err != nil {
					return nil, err
				}
			}
		}
		return []byte(fmt.Sprintf("revoked:%d", len(certs))), nil
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
