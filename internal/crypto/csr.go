package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
)

// CertificateRequestTemplate is a backend-agnostic PKCS#10 CSR template so
// callers never touch crypto/x509 directly (AN-3).
type CertificateRequestTemplate struct {
	CommonName string
	DNSNames   []string
}

// CreateCertificateRequest builds and signs a CSR using signer. The private key
// is used only through the DigestSigner interface, so signer may be remote
// (for example the isolated signing service reached over UDS).
func CreateCertificateRequest(tmpl CertificateRequestTemplate, signer DigestSigner) ([]byte, error) {
	adapter, err := newX509Signer(signer)
	if err != nil {
		return nil, err
	}
	req := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: tmpl.CommonName},
		DNSNames: tmpl.DNSNames,
	}
	return x509.CreateCertificateRequest(rand.Reader, req, adapter)
}

// VerifyCertificateRequest parses a CSR and checks its self-signature.
func VerifyCertificateRequest(der []byte) error {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return err
	}
	return csr.CheckSignature()
}

// x509Signer adapts a DigestSigner to the standard library's crypto.Signer so a
// (possibly remote) key can drive x509.CreateCertificateRequest. It lives inside
// the AN-3 boundary precisely so callers don't need crypto/x509.
type x509Signer struct {
	inner DigestSigner
	pub   crypto.PublicKey
	isRSA bool
}

func newX509Signer(inner DigestSigner) (*x509Signer, error) {
	pub, err := x509.ParsePKIXPublicKey(inner.Public().DER)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	_, isRSA := pub.(*rsa.PublicKey)
	return &x509Signer{inner: inner, pub: pub, isRSA: isRSA}, nil
}

func (a *x509Signer) Public() crypto.PublicKey { return a.pub }

func (a *x509Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	h, err := hashFromCrypto(opts.HashFunc())
	if err != nil {
		return nil, err
	}
	sopts := SignOptions{Hash: h}
	if a.isRSA {
		if _, ok := opts.(*rsa.PSSOptions); ok {
			sopts.RSAPadding = RSAPSS
		} else {
			sopts.RSAPadding = RSAPKCS1v15
		}
	}
	return a.inner.SignDigest(digest, sopts)
}

func hashFromCrypto(h crypto.Hash) (Hash, error) {
	switch h {
	case crypto.SHA256:
		return SHA256, nil
	case crypto.SHA384:
		return SHA384, nil
	case crypto.SHA512:
		return SHA512, nil
	default:
		return "", fmt.Errorf("unsupported hash %v", h)
	}
}
