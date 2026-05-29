package jose

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// This file adds the JOSE primitives the built-in ACME server (RFC 8555) needs:
// verifying a client's flattened-JSON JWS against its (RSA) account key and
// computing the RFC 7638 key thumbprint. It stays in the crypto boundary so the
// ACME server never handles crypto/* itself.

// ACMEProtected is the protected header of an ACME JWS.
type ACMEProtected struct {
	Alg   string          `json:"alg"`
	Kid   string          `json:"kid,omitempty"`
	JWK   json.RawMessage `json:"jwk,omitempty"`
	Nonce string          `json:"nonce,omitempty"`
	URL   string          `json:"url"`
}

// ACMEMessage is a parsed flattened-JSON ACME JWS.
type ACMEMessage struct {
	Protected ACMEProtected
	Payload   []byte // base64url-decoded payload ("" for POST-as-GET)

	protectedB64 string
	payloadB64   string
	signatureB64 string
}

// ParseACMEJWS parses a flattened-JSON ACME JWS body without verifying it.
func ParseACMEJWS(body []byte) (*ACMEMessage, error) {
	var raw struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("jose: parse acme jws: %w", err)
	}
	phJSON, err := b64.DecodeString(raw.Protected)
	if err != nil {
		return nil, fmt.Errorf("jose: acme protected header: %w", err)
	}
	var ph ACMEProtected
	if err := json.Unmarshal(phJSON, &ph); err != nil {
		return nil, fmt.Errorf("jose: acme protected header: %w", err)
	}
	var payload []byte
	if raw.Payload != "" {
		if payload, err = b64.DecodeString(raw.Payload); err != nil {
			return nil, fmt.Errorf("jose: acme payload: %w", err)
		}
	}
	return &ACMEMessage{
		Protected: ph, Payload: payload,
		protectedB64: raw.Protected, payloadB64: raw.Payload, signatureB64: raw.Signature,
	}, nil
}

// ACMEKey is an ACME account public key (RSA), used to verify a client's JWS and
// to derive the key authorization for challenges.
type ACMEKey struct {
	pub  *rsa.PublicKey
	n, e string // base64url, for the RFC 7638 thumbprint
}

// ACMEKeyFromJWK builds an account key from a JWK (the jwk member of a
// new-account request's protected header). Only RSA keys are supported.
func ACMEKeyFromJWK(jwk json.RawMessage) (*ACMEKey, error) {
	var k struct {
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	if err := json.Unmarshal(jwk, &k); err != nil {
		return nil, fmt.Errorf("jose: parse jwk: %w", err)
	}
	if k.Kty != "RSA" {
		return nil, fmt.Errorf("jose: unsupported ACME account key type %q (want RSA)", k.Kty)
	}
	nb, err := b64.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("jose: jwk modulus: %w", err)
	}
	eb, err := b64.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("jose: jwk exponent: %w", err)
	}
	return &ACMEKey{
		pub: &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())},
		n:   k.N, e: k.E,
	}, nil
}

// Verify checks the JWS signature against key (RS256 only).
func (m *ACMEMessage) Verify(key *ACMEKey) error {
	if key == nil {
		return errors.New("jose: no account key")
	}
	if m.Protected.Alg != "RS256" {
		return fmt.Errorf("jose: unsupported ACME JWS alg %q (want RS256)", m.Protected.Alg)
	}
	return verifyRS256(key.pub, m.protectedB64+"."+m.payloadB64, m.signatureB64)
}

// Thumbprint returns the RFC 7638 JWK thumbprint (base64url SHA-256), used as the
// stable account identifier and in challenge key authorizations.
func (k *ACMEKey) Thumbprint() string {
	canonical := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.e, k.n)
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:])
}
