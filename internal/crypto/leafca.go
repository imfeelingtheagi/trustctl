package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// SelfSignedCACert creates a self-signed CA certificate whose signing key is the
// given DigestSigner. In production that signer is a key held inside the
// out-of-process signing service (AN-4): the raw private key never leaves the
// signer; only digests cross the boundary. The certificate is returned as DER.
func SelfSignedCACert(signer DigestSigner, commonName string, ttl time.Duration) ([]byte, error) {
	adapter, err := newX509Signer(signer)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, adapter.Public(), adapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: self-sign CA: %w", err)
	}
	return der, nil
}

// SignLeafFromCSR validates a CSR and signs an end-entity certificate with the CA
// key (a DigestSigner). It then VERIFIES the issued certificate against the CA
// before returning it: a signer that returns a signature which does not verify
// causes issuance to fail closed rather than emit an unverifiable certificate.
func SignLeafFromCSR(caCertDER []byte, caSigner DigestSigner, csrDER []byte, ttl time.Duration) ([]byte, error) {
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CA cert: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("crypto: CSR signature: %w", err)
	}
	adapter, err := newX509Signer(caSigner)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, csr.PublicKey, adapter)
	if err != nil {
		return nil, fmt.Errorf("crypto: sign leaf: %w", err)
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse issued leaf: %w", err)
	}
	if err := issued.CheckSignatureFrom(caCert); err != nil {
		return nil, fmt.Errorf("crypto: issued leaf failed verification (signer misbehaved): %w", err)
	}
	return der, nil
}

// VerifyLeafSignedByCA reports whether leafDER was signed by the CA in caDER. It
// is the boundary helper callers use to confirm an issued certificate chains to
// its CA without importing crypto/x509 themselves (AN-3).
func VerifyLeafSignedByCA(leafDER, caDER []byte) error {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return fmt.Errorf("crypto: parse leaf: %w", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return fmt.Errorf("crypto: parse CA: %w", err)
	}
	return leaf.CheckSignatureFrom(ca)
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("crypto: serial: %w", err)
	}
	return serial, nil
}
