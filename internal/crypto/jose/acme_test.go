package jose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// signFlattenedJWS builds an ACME-style flattened JWS the way x/crypto/acme does:
// RS256 over base64url(protected)+"."+base64url(payload), with the RSA public key
// embedded as a jwk.
func signFlattenedJWS(t *testing.T, key *rsa.PrivateKey, nonce, url string, payload []byte) []byte {
	t.Helper()
	jwk := jwkJSON(key.Public().(*rsa.PublicKey))
	ph, _ := json.Marshal(map[string]any{"alg": "RS256", "jwk": json.RawMessage(jwk), "nonce": nonce, "url": url})
	phB64 := base64.RawURLEncoding.EncodeToString(ph)
	plB64 := base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(phB64 + "." + plB64))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{
		"protected": phB64, "payload": plB64,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})
	return body
}

func jwkJSON(pub *rsa.PublicKey) []byte {
	eb := big2bytes(pub.E)
	return []byte(`{"e":"` + base64.RawURLEncoding.EncodeToString(eb) +
		`","kty":"RSA","n":"` + base64.RawURLEncoding.EncodeToString(pub.N.Bytes()) + `"}`)
}

func big2bytes(e int) []byte {
	var b []byte
	for e > 0 {
		b = append([]byte{byte(e & 0xff)}, b...)
		e >>= 8
	}
	return b
}

// FuzzParseACMEJWS is the parser fuzz target: ParseACMEJWS must never panic on
// arbitrary client input.
func FuzzParseACMEJWS(f *testing.F) {
	f.Add([]byte(`{"protected":"","payload":"","signature":""}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"protected":"!!!","payload":"x","signature":"y"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseACMEJWS(data)
	})
}

func TestACMEJWSVerifyAndThumbprint(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	body := signFlattenedJWS(t, key, "nonce-1", "https://ca/acme/new-account", []byte(`{"termsOfServiceAgreed":true}`))

	msg, err := ParseACMEJWS(body)
	if err != nil {
		t.Fatalf("ParseACMEJWS: %v", err)
	}
	if msg.Protected.Nonce != "nonce-1" || msg.Protected.URL != "https://ca/acme/new-account" {
		t.Errorf("protected header = %+v", msg.Protected)
	}

	ak, err := ACMEKeyFromJWK(msg.Protected.JWK)
	if err != nil {
		t.Fatalf("ACMEKeyFromJWK: %v", err)
	}
	if err := msg.Verify(ak); err != nil {
		t.Errorf("Verify of a valid JWS failed: %v", err)
	}
	if ak.Thumbprint() == "" {
		t.Error("empty thumbprint")
	}

	// A tampered payload must not verify.
	bad := signFlattenedJWS(t, key, "nonce-1", "https://ca/acme/new-account", []byte(`{"termsOfServiceAgreed":true}`))
	tampered := append([]byte{}, bad...)
	tampered[len(tampered)/2] ^= 0xff
	if m, err := ParseACMEJWS(tampered); err == nil {
		if err := m.Verify(ak); err == nil {
			t.Error("Verify accepted a tampered JWS")
		}
	}

	// A different key must not verify the original message.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherKey, _ := ACMEKeyFromJWK(jwkJSON(&other.PublicKey))
	if err := msg.Verify(otherKey); err == nil {
		t.Error("Verify accepted a signature from a different key")
	}
}
