package crypto

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"trustctl.io/trustctl/internal/crypto/secret"
)

// LockedSigner holds its private key as PKCS#8 DER inside a locked secret buffer
// (mlock + MADV_DONTDUMP + zeroized on Destroy, per AN-8). The key is parsed
// into a transient standard-library value only for the moment of each
// signature, so the unprotected form of the key lives in memory for
// milliseconds at most. It implements DigestSigner.
type LockedSigner struct {
	algorithm Algorithm
	public    PublicKey
	der       *secret.Buffer
}

// GenerateLockedKey generates a new key and stores its private material in a
// locked secret buffer.
func GenerateLockedKey(algorithm Algorithm) (*LockedSigner, error) {
	key, err := generateStdlibKey(algorithm)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	buf, err := secret.NewFrom(der)
	secret.Wipe(der) // wipe the transient, unlocked copy
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		buf.Destroy()
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return &LockedSigner{
		algorithm: algorithm,
		public:    PublicKey{Algorithm: algorithm, DER: pubDER},
		der:       buf,
	}, nil
}

// Algorithm reports the key's algorithm.
func (l *LockedSigner) Algorithm() Algorithm { return l.algorithm }

// Public returns the public key.
func (l *LockedSigner) Public() PublicKey { return l.public }

// SignDigest parses the locked private key, signs digest, and lets the parsed
// key go out of scope immediately.
func (l *LockedSigner) SignDigest(digest []byte, opts SignOptions) ([]byte, error) {
	der := l.der.Bytes()
	if der == nil {
		return nil, errors.New("crypto: locked key has been destroyed")
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("crypto: parsed key %T is not a signer", key)
	}
	return signDigest(signer, digest, opts)
}

// Destroy zeroizes and releases the locked key. It is idempotent.
func (l *LockedSigner) Destroy() { l.der.Destroy() }
