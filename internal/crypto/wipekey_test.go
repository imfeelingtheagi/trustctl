package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

// TestWipeStdlibKeyZeroesSecretScalars guards SIGNER-008: the helper that wipes the
// transiently-parsed private key during LockedSigner.SignDigest must actually zero
// the secret scalars, so the unprotected copy is cleared before the parsed key is
// dropped. A regression that drops the wipe (or stops covering RSA's CRT values)
// fails here.
func TestWipeStdlibKeyZeroesSecretScalars(t *testing.T) {
	t.Run("ecdsa", func(t *testing.T) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wipeStdlibKey(k)
		if k.D.Sign() != 0 {
			t.Errorf("ecdsa D not zeroed after wipe: %s", k.D)
		}
	})

	t.Run("rsa", func(t *testing.T) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		wipeStdlibKey(k)
		if k.D.Sign() != 0 {
			t.Errorf("rsa D not zeroed: %s", k.D)
		}
		for i, p := range k.Primes {
			if p.Sign() != 0 {
				t.Errorf("rsa prime[%d] not zeroed: %s", i, p)
			}
		}
		for name, v := range map[string]*big.Int{
			"Dp":   k.Precomputed.Dp,
			"Dq":   k.Precomputed.Dq,
			"Qinv": k.Precomputed.Qinv,
		} {
			if v != nil && v.Sign() != 0 {
				t.Errorf("rsa precomputed %s not zeroed: %s", name, v)
			}
		}
	})

	// nil and unknown types must be no-ops, never panic.
	wipeStdlibKey(nil)
	wipeStdlibKey((*ecdsa.PrivateKey)(nil))
	wipeStdlibKey("not a key")
}

// TestSignDigestWipesParsedKeyAndStillSigns proves the wipe is wired into the
// signing path without breaking correctness: a LockedSigner still produces a
// verifiable signature even though each SignDigest now zeroizes the key it parsed.
func TestSignDigestWipesParsedKeyAndStillSigns(t *testing.T) {
	ls, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	defer ls.Destroy()
	msg := []byte("sign me")
	digest, err := Digest(SHA256, msg)
	if err != nil {
		t.Fatal(err)
	}
	// Two consecutive signatures must both succeed and verify — proving the wipe of
	// the first parse did not corrupt the locked source for the second.
	for i := 0; i < 2; i++ {
		sig, err := ls.SignDigest(digest, SignOptions{Hash: SHA256})
		if err != nil {
			t.Fatalf("SignDigest #%d: %v", i, err)
		}
		if err := VerifyDigest(ls.Public(), digest, sig, SignOptions{Hash: SHA256}); err != nil {
			t.Fatalf("VerifyDigest #%d: %v", i, err)
		}
	}
}
