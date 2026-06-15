package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// This file adds private/enterprise CA hierarchy support (F48) inside the AN-3
// crypto boundary: a CA can be a self-signed root or an intermediate signed by a
// parent, carries name-constraint / path-length / EKU policy, issues end-entity
// certificates enforcing those constraints, and can cross-sign another CA. Like
// Authority, the CA holds its signing key in-process as the reference path; in
// production the key is custodied by the signer/HSM (AN-4) behind this boundary.
// Callers outside the boundary use the crypto-free results and never name
// crypto/*.

// CASpec describes a CA to create: its subject, the DNS name constraints it
// permits, its remaining path length (sub-CA depth; <0 means unset), the extended
// key usages it permits on issued certificates, and its validity.
type CASpec struct {
	CommonName          string
	PermittedDNSDomains []string
	MaxPathLen          int
	EKUs                []string
	TTL                 time.Duration
}

// CA is a certificate authority in a hierarchy: its certificate, signing key,
// chain to the root, and policy. It signs intermediates and end-entity
// certificates and enforces its constraints.
type CA struct {
	cert     *x509.Certificate
	der      []byte
	key      *ecdsa.PrivateKey
	chainDER [][]byte // this cert first, then ancestors up to the root

	permittedDNS []string
	maxPathLen   int // remaining sub-CA depth; <0 means unset
	ekus         []x509.ExtKeyUsage
}

const (
	defaultRootTTL = 10 * 365 * 24 * time.Hour
	defaultCATTL   = 5 * 365 * 24 * time.Hour
)

// NewRoot creates a self-signed root CA.
func NewRoot(spec CASpec) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ttl := spec.TTL
	if ttl <= 0 {
		ttl = defaultRootTTL
	}
	der, cert, err := signCACert(spec.CommonName, spec.PermittedDNSDomains, spec.MaxPathLen, spec.EKUs, ttl, nil, nil, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert: cert, der: der, key: key, chainDER: [][]byte{der},
		permittedDNS: spec.PermittedDNSDomains, maxPathLen: spec.MaxPathLen, ekus: ekusFromStrings(spec.EKUs),
	}, nil
}

// CreateIntermediate signs an intermediate CA under c. It is rejected if c's path
// length is exhausted. The child's path length is one less than c's, and it
// inherits c's name constraints and EKU policy unless the spec narrows them.
func (c *CA) CreateIntermediate(spec CASpec) (*CA, error) {
	if c.maxPathLen == 0 {
		return nil, fmt.Errorf("ca: path-length constraint exhausted: %q may not issue sub-CAs", c.cert.Subject.CommonName)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	childPathLen := -1
	if c.maxPathLen > 0 {
		childPathLen = c.maxPathLen - 1
	}
	permitted := spec.PermittedDNSDomains
	if len(permitted) == 0 {
		permitted = c.permittedDNS
	}
	ekus := spec.EKUs
	if len(ekus) == 0 {
		ekus = ekuStrings(c.ekus)
	}
	ttl := spec.TTL
	if ttl <= 0 {
		ttl = defaultCATTL
	}
	der, cert, err := signCACert(spec.CommonName, permitted, childPathLen, ekus, ttl, c.cert, c.key, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert: cert, der: der, key: key, chainDER: append([][]byte{der}, c.chainDER...),
		permittedDNS: permitted, maxPathLen: childPathLen, ekus: ekusFromStrings(ekus),
	}, nil
}

// IssueLeaf validates a CSR and signs an end-entity certificate, enforcing the
// CA's name constraints (every SAN must be permitted) and EKU policy. The
// returned PEM is the leaf followed by this CA's chain to the root.
func (c *CA) IssueLeaf(csrDER []byte, ttl time.Duration) (Issued, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return Issued{}, fmt.Errorf("ca: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return Issued{}, fmt.Errorf("ca: csr signature: %w", err)
	}
	if len(c.permittedDNS) > 0 {
		for _, name := range csr.DNSNames {
			if !dnsPermitted(name, c.permittedDNS) {
				return Issued{}, fmt.Errorf("ca: SAN %q violates the CA name constraints %v", name, c.permittedDNS)
			}
		}
	}
	serial, err := randomSerial()
	if err != nil {
		return Issued{}, err
	}
	eku := c.ekus
	if len(eku) == 0 {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	now := time.Now()
	notAfter := now.Add(ttl)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return Issued{}, fmt.Errorf("ca: sign certificate: %w", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	out = append(out, c.ChainPEM()...)
	return Issued{CertificatePEM: out, Serial: serial.Text(16), NotAfter: notAfter}, nil
}

// CrossSign issues a cross-certificate for another CA's certificate: it carries
// that CA's subject and public key but is signed by this CA, so relying parties
// that trust this CA also trust the cross-signed one.
//
// A cross-certificate is a fully privileged CA certificate, so it must not be
// issued unconstrained (PKIGOV-004). It carries forward the target's path-length
// basic constraint and dNSName name constraints, and additionally clamps them to
// this signing CA's own lane: the cross-cert's permitted DNS domains are the
// intersection with this CA's name constraints, and its sub-CA depth is the more
// restrictive of the target's own pathLen and this CA's remaining depth. This
// prevents a cross-signature from widening the trust the relying party already
// extended to this CA (e.g. cross-signing a name-unconstrained or deeper CA must
// not let it issue names or depths this CA may not).
func (c *CA) CrossSign(otherCertDER []byte) ([]byte, error) {
	other, err := x509.ParseCertificate(otherCertDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse cross-sign target: %w", err)
	}
	if !other.IsCA {
		return nil, fmt.Errorf("ca: cross-sign target %q is not a CA certificate", other.Subject.CommonName)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	// Path length: cross-signing re-issues a peer CA at the same trust tier, so the
	// target's own depth is carried — but clamped to this signing CA's remaining
	// depth so the cross-cert can never grant MORE sub-CA depth than this CA itself
	// holds. The result is the more restrictive (smaller) of the two whenever both
	// are set; if the target is unset it is pinned to this CA's depth.
	pathLen, hasPathLen := crossPathLen(other)
	if c.maxPathLen >= 0 {
		if !hasPathLen || c.maxPathLen < pathLen {
			pathLen, hasPathLen = c.maxPathLen, true
		}
	}

	// Name constraints: carry the target's permitted dNSName set, then intersect
	// with this CA's own permitted set so the cross-cert can never permit a name
	// this CA itself may not.
	permitted := intersectDNS(other.PermittedDNSDomains, c.permittedDNS)

	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     other.Subject,
		NotBefore:                   other.NotBefore,
		NotAfter:                    other.NotAfter,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		PermittedDNSDomains:         permitted,
		PermittedDNSDomainsCritical: len(permitted) > 0,
	}
	if hasPathLen {
		tmpl.MaxPathLen = pathLen
		tmpl.MaxPathLenZero = pathLen == 0
	}
	crossDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, other.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("ca: cross-sign: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crossDER}), nil
}

// crossPathLen extracts the basic-constraints path-length from a parsed CA
// certificate, distinguishing "explicitly zero" from "unset". Go's x509 sets
// MaxPathLen=0 with MaxPathLenZero=true for an explicit zero, and leaves
// MaxPathLen=0/MaxPathLenZero=false (or MaxPathLen<0) when the constraint is
// absent.
func crossPathLen(cert *x509.Certificate) (int, bool) {
	if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
		return cert.MaxPathLen, true
	}
	return 0, false
}

// intersectDNS returns the dNSName name-constraint set the cross-cert may permit:
// the target's permitted set restricted to what the signing CA itself permits. If
// the signing CA is unconstrained, the target's set carries forward unchanged. If
// the target is unconstrained, it is narrowed to the signing CA's set.
func intersectDNS(target, signer []string) []string {
	if len(signer) == 0 {
		return append([]string(nil), target...)
	}
	if len(target) == 0 {
		return append([]string(nil), signer...)
	}
	var out []string
	for _, t := range target {
		if dnsPermitted(strings.TrimPrefix(t, "."), signer) || containsFold(signer, t) {
			out = append(out, t)
		}
	}
	return out
}

// containsFold reports whether set contains v, ignoring a leading constraint dot.
func containsFold(set []string, v string) bool {
	v = strings.TrimPrefix(v, ".")
	for _, s := range set {
		if strings.TrimPrefix(s, ".") == v {
			return true
		}
	}
	return false
}

// CertificatePEM returns this CA's certificate in PEM form.
func (c *CA) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// CertificateDER returns this CA's certificate in DER form.
func (c *CA) CertificateDER() []byte { return c.der }

// ChainPEM returns this CA's certificate followed by its ancestors, PEM-encoded.
func (c *CA) ChainPEM() []byte {
	var out []byte
	for _, der := range c.chainDER {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

// CommonName is the CA's subject common name.
func (c *CA) CommonName() string { return c.cert.Subject.CommonName }

// Serial is the CA certificate's serial number in hex.
func (c *CA) Serial() string { return c.cert.SerialNumber.Text(16) }

// NotAfter is the CA certificate's expiry.
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter }

// MaxPathLen is the CA's remaining sub-CA depth (<0 means unset).
func (c *CA) MaxPathLen() int { return c.maxPathLen }

// PermittedDNSDomains returns the CA's permitted DNS name constraints.
func (c *CA) PermittedDNSDomains() []string { return c.permittedDNS }

// signCACert builds and signs a CA certificate. When parent/parentKey are nil it
// is self-signed (a root); otherwise it is signed by the parent (an intermediate
// or cross-cert).
func signCACert(commonName string, permitted []string, maxPathLen int, ekus []string, ttl time.Duration, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, pub *ecdsa.PublicKey, selfKey *ecdsa.PrivateKey) ([]byte, *x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: commonName},
		NotBefore:                   now.Add(-time.Minute),
		NotAfter:                    now.Add(ttl),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		PermittedDNSDomains:         permitted,
		PermittedDNSDomainsCritical: len(permitted) > 0,
	}
	if maxPathLen >= 0 {
		tmpl.MaxPathLen = maxPathLen
		tmpl.MaxPathLenZero = maxPathLen == 0
	}
	if e := ekusFromStrings(ekus); len(e) > 0 {
		tmpl.ExtKeyUsage = e
	}
	signer, signerKey := parent, parentKey
	if signer == nil { // self-signed root
		signer, signerKey = tmpl, selfKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, pub, signerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return der, cert, nil
}

// dnsPermitted reports whether name is within one of the permitted DNS domains
// (exact match or a subdomain), per RFC 5280 name constraints.
func dnsPermitted(name string, permitted []string) bool {
	for _, p := range permitted {
		p = strings.TrimPrefix(p, ".")
		if name == p || strings.HasSuffix(name, "."+p) {
			return true
		}
	}
	return false
}

func ekusFromStrings(names []string) []x509.ExtKeyUsage {
	var out []x509.ExtKeyUsage
	for _, n := range names {
		switch n {
		case "serverAuth":
			out = append(out, x509.ExtKeyUsageServerAuth)
		case "clientAuth":
			out = append(out, x509.ExtKeyUsageClientAuth)
		case "codeSigning":
			out = append(out, x509.ExtKeyUsageCodeSigning)
		case "emailProtection":
			out = append(out, x509.ExtKeyUsageEmailProtection)
		case "any":
			out = append(out, x509.ExtKeyUsageAny)
		}
	}
	return out
}

func ekuStrings(ekus []x509.ExtKeyUsage) []string {
	var out []string
	for _, e := range ekus {
		switch e {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "emailProtection")
		case x509.ExtKeyUsageAny:
			out = append(out, "any")
		}
	}
	return out
}
