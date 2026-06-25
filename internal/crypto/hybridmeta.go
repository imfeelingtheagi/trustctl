package crypto

import (
	"encoding/asn1"
	"fmt"

	"crypto/x509/pkix"
)

const (
	// HybridMLDSA44ECDSAP256Algorithm is the profile/inventory algorithm label
	// for the compile-time hybrid transition profile: ML-DSA-44 plus ECDSA P-256.
	// It is selected by ordinary profile data passed into the crypto boundary; no
	// runtime provider registry, plugin engine, or policy-driven crypto suite
	// registration is involved.
	HybridMLDSA44ECDSAP256Algorithm = "Hybrid-ML-DSA-44-ECDSA-P256"

	// HybridLeafExtensionOID identifies the trstctl hybrid transition extension.
	// The extension carries the draft composite public-key bytes
	// (ML-DSA public key || ECDSA public key) plus the ML-DSA proof of possession.
	HybridLeafExtensionOID = "1.3.6.1.4.1.59551.2.2"
)

var (
	oidHybridLeafExtension             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59551, 2, 2}
	oidCompositeMLDSA44ECDSAP256SHA256 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 40}
)

type hybridLeafMetadata struct {
	CompositeAlgorithm asn1.ObjectIdentifier
	MLDSAAlgorithm     string
	TraditionalAlg     string
	MLDSAPublicKey     []byte
	TraditionalPubKey  []byte
	CompositePublicKey []byte
	ProofSignature     []byte
}

// HybridKeyAlgorithmFromExtensions reports the profile/inventory key algorithm
// implied by the hybrid transition extension, if present. It intentionally only
// classifies the requested algorithm; proof verification lives in internal/crypto/pqc
// at issuance time, where the ML-DSA verifier is available without creating an
// import cycle.
func HybridKeyAlgorithmFromExtensions(exts []CertificateExtension) (algorithm string, found bool, err error) {
	for _, ext := range exts {
		oid, err := parseOID(ext.OID)
		if err != nil {
			return "", false, fmt.Errorf("crypto: hybrid extension OID %q: %w", ext.OID, err)
		}
		if !oid.Equal(oidHybridLeafExtension) {
			continue
		}
		var meta hybridLeafMetadata
		rest, err := asn1.Unmarshal(ext.Value, &meta)
		if err != nil {
			return "", true, fmt.Errorf("crypto: parse hybrid extension: %w", err)
		}
		if len(rest) != 0 {
			return "", true, fmt.Errorf("crypto: hybrid extension has trailing data")
		}
		if meta.CompositeAlgorithm.Equal(oidCompositeMLDSA44ECDSAP256SHA256) &&
			meta.MLDSAAlgorithm == string(MLDSA44) &&
			meta.TraditionalAlg == string(ECDSAP256) {
			return HybridMLDSA44ECDSAP256Algorithm, true, nil
		}
		return "", true, fmt.Errorf("crypto: unsupported hybrid components %s + %s under %s", meta.MLDSAAlgorithm, meta.TraditionalAlg, meta.CompositeAlgorithm.String())
	}
	return "", false, nil
}

func certificateExtensionsFromPKIX(exts []pkix.Extension) []CertificateExtension {
	out := make([]CertificateExtension, 0, len(exts))
	for _, ext := range exts {
		out = append(out, CertificateExtension{
			OID:      ext.Id.String(),
			Critical: ext.Critical,
			Value:    append([]byte(nil), ext.Value...),
		})
	}
	return out
}
