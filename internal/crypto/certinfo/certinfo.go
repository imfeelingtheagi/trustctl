// Package certinfo extracts inventory metadata from an X.509 certificate inside
// the AN-3 crypto boundary (a subpackage of internal/crypto, so it alone may
// import crypto/x509). Callers outside the boundary consume only the crypto-free
// Info struct, so the certificate-inventory layer never imports crypto/*.
package certinfo

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Info is the inventory metadata of a certificate.
type Info struct {
	Subject           string
	Issuer            string
	SerialNumber      string // hex
	DNSNames          []string
	IPAddresses       []string
	EmailAddresses    []string
	URIs              []string
	NotBefore         time.Time
	NotAfter          time.Time
	SHA256Fingerprint string // hex of the DER
	KeyAlgorithm      string
	PublicKeyBits     int // key size in bits (RSA modulus, EC curve, 256 for Ed25519); 0 if unknown
	IsCA              bool

	// RFC 5280 profile fields surfaced for served-leaf conformance checks
	// (PKIGOV-001). Empty/absent extensions yield empty slices.
	SubjectKeyID          string   // hex of the Subject Key Identifier
	AuthorityKeyID        string   // hex of the Authority Key Identifier
	CRLDistributionPoints []string // CDP URLs
	OCSPServers           []string // AIA OCSP responder URLs
	IssuingCertificateURL []string // AIA CA-issuers URLs
	PolicyOIDs            []string // certificatePolicies, dotted form
}

// Inspect parses a certificate (PEM or DER) and returns its inventory metadata.
func Inspect(raw []byte) (Info, error) {
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return Info{}, fmt.Errorf("certinfo: PEM block is %q, not CERTIFICATE", block.Type)
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Info{}, fmt.Errorf("certinfo: parse certificate: %w", err)
	}
	if cert.SerialNumber == nil {
		return Info{}, errors.New("certinfo: certificate has no serial number")
	}

	sum := sha256.Sum256(cert.Raw)
	info := Info{
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		SerialNumber:      cert.SerialNumber.Text(16),
		DNSNames:          cert.DNSNames,
		EmailAddresses:    cert.EmailAddresses,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		SHA256Fingerprint: hex.EncodeToString(sum[:]),
		KeyAlgorithm:      cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:     publicKeyBits(cert.PublicKey),
		IsCA:              cert.IsCA,
	}
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	for _, u := range cert.URIs {
		info.URIs = append(info.URIs, u.String())
	}
	// RFC 5280 profile fields (PKIGOV-001): the served-leaf conformance check reads
	// these to assert CDP/AIA/SKI/policies are present and well-formed.
	if len(cert.SubjectKeyId) > 0 {
		info.SubjectKeyID = hex.EncodeToString(cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) > 0 {
		info.AuthorityKeyID = hex.EncodeToString(cert.AuthorityKeyId)
	}
	info.CRLDistributionPoints = append(info.CRLDistributionPoints, cert.CRLDistributionPoints...)
	info.OCSPServers = append(info.OCSPServers, cert.OCSPServer...)
	info.IssuingCertificateURL = append(info.IssuingCertificateURL, cert.IssuingCertificateURL...)
	info.PolicyOIDs = policyStrings(cert)
	return info, nil
}

// policyStrings returns the certificatePolicies OIDs in dotted form, reading the
// Go 1.22+ parsed cert.Policies ([]x509.OID) and falling back to the deprecated
// cert.PolicyIdentifiers, de-duplicated. (x509.CreateCertificate writes the
// extension from either field; ParseCertificate populates Policies, and only
// populates PolicyIdentifiers for OIDs representable as asn1.ObjectIdentifier.)
func policyStrings(cert *x509.Certificate) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, oid := range cert.Policies {
		add(oid.String())
	}
	for _, oid := range cert.PolicyIdentifiers {
		add(oid.String())
	}
	return out
}

// publicKeyBits returns the key size in bits: the RSA modulus length, the EC
// curve size, 256 for Ed25519, or 0 for an unrecognized key. It is the signal
// the crypto-inventory (F52) uses to flag undersized keys.
func publicKeyBits(pub any) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// Thumbprint returns the certificate's Windows thumbprint: the uppercase
// hex-encoded SHA-1 digest of the certificate's DER encoding — the value the
// Windows certificate store and `netsh http ... certhash=` use to identify a
// certificate. SHA-1 is used here as an identifier, not a signature.
func Thumbprint(raw []byte) (string, error) {
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return "", fmt.Errorf("certinfo: PEM block is %q, not CERTIFICATE", block.Type)
		}
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("certinfo: parse certificate: %w", err)
	}
	sum := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}
