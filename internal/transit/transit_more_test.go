package transit

import (
	"context"
	"testing"
)

func TestTransitErrorPaths(t *testing.T) {
	ctx := context.Background()
	k := New("t1", nil)
	if err := k.CreateKey(ctx, "a", KindAEAD); err != nil {
		t.Fatal(err)
	}
	if err := k.CreateKey(ctx, "a", KindAEAD); err == nil {
		t.Error("duplicate key creation accepted")
	}
	if err := k.CreateKey(ctx, "x", "bogus"); err == nil {
		t.Error("unknown key kind accepted")
	}
	if _, err := k.Encrypt(ctx, "missing", []byte("x"), nil); err == nil {
		t.Error("encrypt with unknown key accepted")
	}
	if _, err := k.Decrypt(ctx, "a", "not-a-ciphertext", nil); err == nil {
		t.Error("malformed ciphertext accepted")
	}
	if _, err := k.Decrypt(ctx, "a", "trv:99:AAAA", nil); err == nil {
		t.Error("unknown key version accepted")
	}
	if _, err := k.Rotate(ctx, "missing"); err == nil {
		t.Error("rotate of unknown key accepted")
	}
	if _, err := k.HMAC(ctx, "a", []byte("d")); err == nil {
		t.Error("HMAC on an AEAD key accepted")
	}
	if _, _, err := k.Sign(ctx, "a", []byte("d")); err == nil {
		t.Error("Sign on an AEAD key accepted")
	}
}
