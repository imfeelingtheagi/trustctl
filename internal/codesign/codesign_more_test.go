package codesign

import (
	"context"
	"testing"

	"trustctl.io/trustctl/internal/crypto"
)

func TestCodesignNewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("empty TenantID accepted")
	}
	if _, err := New(Config{TenantID: "t1"}); err == nil {
		t.Error("missing KeyResolver accepted")
	}
}

func TestCodesignSignErrors(t *testing.T) {
	key, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer key.Destroy()
	svc, _ := New(Config{TenantID: "t1", Keys: keyMap{m: map[string]crypto.DigestSigner{"k": key}}})
	ctx := context.Background()
	if _, err := svc.Sign(ctx, SignRequest{Principal: "a", KeyID: "k", Digest: nil}); err == nil {
		t.Error("empty digest accepted")
	}
	if _, err := svc.Sign(ctx, SignRequest{Principal: "a", KeyID: "missing", Digest: crypto.SHA256Sum([]byte("x"))}); err == nil {
		t.Error("unknown key accepted")
	}
}

func TestCodesignKeylessValidation(t *testing.T) {
	svc, _ := New(Config{TenantID: "t1", Keys: keyMap{m: map[string]crypto.DigestSigner{}}})
	eph, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer eph.Destroy()
	ctx := context.Background()
	if _, err := svc.SignKeyless(ctx, KeylessRequest{Ephemeral: eph, FulcioSAN: "san", Digest: nil}); err == nil {
		t.Error("empty digest accepted")
	}
	if _, err := svc.SignKeyless(ctx, KeylessRequest{Ephemeral: eph, Digest: crypto.SHA256Sum([]byte("x"))}); err == nil {
		t.Error("missing Fulcio SAN accepted")
	}
}
