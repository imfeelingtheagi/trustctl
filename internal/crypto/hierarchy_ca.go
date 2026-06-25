package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"time"
)

const (
	defaultHierarchyRootTTL = 10 * 365 * 24 * time.Hour
	defaultHierarchyCATTL   = 5 * 365 * 24 * time.Hour
)

// HierarchyCAProfile is the crypto-boundary representation of a served private
// CA certificate. The signer passed to the functions below may be an isolated
// signing-service RemoteSigner, so the CA private key never enters the control
// plane.
type HierarchyCAProfile struct {
	CommonName          string
	PermittedDNSDomains []string
	MaxPathLen          int
	EKUs                []string
	TTL                 time.Duration
}

// IssuedHierarchyCA is the public result of CA certificate creation. It contains
// the certificate only; private key material remains inside the supplied signer.
type IssuedHierarchyCA struct {
	CertificateDER      []byte
	CertificatePEM      []byte
	Serial              string
	NotAfter            time.Time
	MaxPathLen          int
	PermittedDNSDomains []string
	EKUs                []string
}

// SelfSignedHierarchyCA creates a self-signed CA certificate using signer. The
// private key is signer-held; only the digest to sign crosses the signer boundary.
func SelfSignedHierarchyCA(signer DigestSigner, profile HierarchyCAProfile) (IssuedHierarchyCA, error) {
	if profile.TTL <= 0 {
		profile.TTL = defaultHierarchyRootTTL
	}
	return signHierarchyCA(signer, signer.Public(), nil, profile)
}

// SignIntermediateHierarchyCA creates an intermediate CA certificate: childPublic
// is the public key of the signer-held child key, and parentSigner signs the
// certificate under parentCertDER.
func SignIntermediateHierarchyCA(parentCertDER []byte, parentSigner DigestSigner, childPublic PublicKey, profile HierarchyCAProfile) (IssuedHierarchyCA, error) {
	parent, err := x509.ParseCertificate(parentCertDER)
	if err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: parse parent CA: %w", err)
	}
	parentHasPathLen := parent.MaxPathLen > 0 || parent.MaxPathLenZero
	if parentHasPathLen && parent.MaxPathLen == 0 {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: parent CA path-length constraint is exhausted")
	}
	if len(profile.PermittedDNSDomains) == 0 {
		profile.PermittedDNSDomains = append([]string(nil), parent.PermittedDNSDomains...)
	}
	if len(profile.EKUs) == 0 {
		profile.EKUs = extKeyUsageStrings(parent.ExtKeyUsage)
	}
	if parentHasPathLen {
		childPathLen := parent.MaxPathLen - 1
		if profile.MaxPathLen >= 0 && profile.MaxPathLen < childPathLen {
			childPathLen = profile.MaxPathLen
		}
		profile.MaxPathLen = childPathLen
	}
	if profile.TTL <= 0 {
		profile.TTL = defaultHierarchyCATTL
	}
	if notAfter := time.Now().Add(profile.TTL); notAfter.After(parent.NotAfter) {
		profile.TTL = time.Until(parent.NotAfter)
	}
	return signHierarchyCA(parentSigner, childPublic, parent, profile)
}

func signHierarchyCA(signer DigestSigner, subjectPublic PublicKey, issuer *x509.Certificate, profile HierarchyCAProfile) (IssuedHierarchyCA, error) {
	if profile.CommonName == "" {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: CA common name is required")
	}
	if profile.TTL <= 0 {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: CA TTL must be positive")
	}
	adapter, err := newX509Signer(signer)
	if err != nil {
		return IssuedHierarchyCA{}, err
	}
	pub, err := parsePKIXPublicKey(subjectPublic)
	if err != nil {
		return IssuedHierarchyCA{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return IssuedHierarchyCA{}, err
	}
	ski, err := subjectKeyID(pub)
	if err != nil {
		return IssuedHierarchyCA{}, err
	}
	knownEKUs, customEKUs, err := caExtKeyUsage(profile.EKUs)
	if err != nil {
		return IssuedHierarchyCA{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: profile.CommonName},
		NotBefore:                   now.Add(-time.Minute),
		NotAfter:                    now.Add(profile.TTL),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		SubjectKeyId:                ski,
		PermittedDNSDomains:         profile.PermittedDNSDomains,
		PermittedDNSDomainsCritical: len(profile.PermittedDNSDomains) > 0,
		ExtKeyUsage:                 knownEKUs,
		UnknownExtKeyUsage:          customEKUs,
	}
	if profile.MaxPathLen >= 0 {
		tmpl.MaxPathLen = profile.MaxPathLen
		tmpl.MaxPathLenZero = profile.MaxPathLen == 0
	}
	selfSigned := issuer == nil
	if selfSigned {
		issuer = tmpl
		tmpl.AuthorityKeyId = ski
	} else if len(issuer.SubjectKeyId) > 0 {
		tmpl.AuthorityKeyId = issuer.SubjectKeyId
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, adapter)
	if err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: sign CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return IssuedHierarchyCA{}, err
	}
	verifyIssuer := issuer
	if selfSigned {
		verifyIssuer = cert
	}
	if err := cert.CheckSignatureFrom(verifyIssuer); err != nil {
		return IssuedHierarchyCA{}, fmt.Errorf("crypto: issued CA failed verification: %w", err)
	}
	return IssuedHierarchyCA{
		CertificateDER:      der,
		CertificatePEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Serial:              cert.SerialNumber.Text(16),
		NotAfter:            cert.NotAfter,
		MaxPathLen:          profile.MaxPathLen,
		PermittedDNSDomains: append([]string(nil), profile.PermittedDNSDomains...),
		EKUs:                append([]string(nil), profile.EKUs...),
	}, nil
}

func parsePKIXPublicKey(pub PublicKey) (any, error) {
	if len(pub.DER) == 0 {
		return nil, fmt.Errorf("crypto: public key is empty")
	}
	parsed, err := x509.ParsePKIXPublicKey(pub.DER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse public key: %w", err)
	}
	return parsed, nil
}

func extKeyUsageStrings(usages []x509.ExtKeyUsage) []string {
	out := make([]string, 0, len(usages))
	for _, u := range usages {
		switch u {
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

func caExtKeyUsage(names []string) ([]x509.ExtKeyUsage, []asn1.ObjectIdentifier, error) {
	if len(names) == 0 {
		return nil, nil, nil
	}
	var known []x509.ExtKeyUsage
	var custom []asn1.ObjectIdentifier
	for _, name := range names {
		if usage, ok := knownExtKeyUsage(name); ok {
			known = append(known, usage)
			continue
		}
		oid, err := parseDottedOID(name)
		if err != nil {
			return nil, nil, fmt.Errorf("unsupported CA extended key usage %q", name)
		}
		custom = append(custom, oid)
	}
	return known, custom, nil
}
