package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/pkcs11"
)

type servedPKCS11Session struct {
	mu   sync.Mutex
	keys map[string]*servedPKCS11Key
	seq  int
}

type servedPKCS11Key struct {
	signer   *crypto.LockedSigner
	revoked  bool
	zeroized bool
}

func newServedPKCS11Session() *servedPKCS11Session {
	return &servedPKCS11Session{keys: map[string]*servedPKCS11Key{}}
}

func (s *servedPKCS11Session) GenerateKey(alg crypto.Algorithm) (string, []byte, error) {
	signer, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	handle := "pkcs11://slot/0/object/" + hex.EncodeToString([]byte{byte(s.seq)})
	s.keys[handle] = &servedPKCS11Key{signer: signer}
	return handle, signer.Public().DER, nil
}

func (s *servedPKCS11Session) SignDigest(handle string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	s.mu.Lock()
	key := s.keys[handle]
	s.mu.Unlock()
	if key == nil {
		return nil, fmt.Errorf("pkcs11: unknown object handle %q", handle)
	}
	if key.revoked {
		return nil, fmt.Errorf("pkcs11: key %q is revoked", handle)
	}
	if key.zeroized {
		return nil, fmt.Errorf("pkcs11: key %q is zeroized", handle)
	}
	return key.signer.SignDigest(digest, opts)
}

func (s *servedPKCS11Session) RevokeKey(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.keys[handle]
	if key == nil {
		return fmt.Errorf("pkcs11: unknown object handle %q", handle)
	}
	if key.zeroized {
		return fmt.Errorf("pkcs11: key %q is zeroized", handle)
	}
	key.revoked = true
	return nil
}

func (s *servedPKCS11Session) ZeroizeKey(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.keys[handle]
	if key == nil {
		return fmt.Errorf("pkcs11: unknown object handle %q", handle)
	}
	key.zeroized = true
	key.signer.Destroy()
	delete(s.keys, handle)
	return nil
}

func (s *servedPKCS11Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range s.keys {
		key.signer.Destroy()
	}
	s.keys = map[string]*servedPKCS11Key{}
	return nil
}

type servedPKCS11ManagedKeys struct {
	lc crypto.RemoteKeyLifecycle

	mu   sync.Mutex
	keys map[string]crypto.KeyRef
}

func newServedPKCS11ManagedKeys(lc crypto.RemoteKeyLifecycle) *servedPKCS11ManagedKeys {
	return &servedPKCS11ManagedKeys{lc: lc, keys: map[string]crypto.KeyRef{}}
}

func (s *servedPKCS11ManagedKeys) Generate(ctx context.Context, tenantID string, alg crypto.Algorithm, _ string) (api.ManagedKey, error) {
	signer, ref, err := s.lc.GenerateManagedKey(ctx, alg)
	if err != nil {
		return api.ManagedKey{}, err
	}
	s.mu.Lock()
	s.keys[tenantID+"\x00"+ref.ID] = ref
	s.mu.Unlock()
	return api.ManagedKey{KeyID: ref.ID, Algorithm: ref.Algorithm, Version: 1, State: "active", PublicDER: signer.Public().DER}, nil
}

func (s *servedPKCS11ManagedKeys) Rotate(ctx context.Context, tenantID, keyID, _, _ string) (api.ManagedKey, error) {
	ref, err := s.ref(tenantID, keyID)
	if err != nil {
		return api.ManagedKey{}, err
	}
	signer, next, err := s.lc.RotateKey(ctx, ref)
	if err != nil {
		return api.ManagedKey{}, err
	}
	s.mu.Lock()
	delete(s.keys, tenantID+"\x00"+keyID)
	s.keys[tenantID+"\x00"+next.ID] = next
	s.mu.Unlock()
	return api.ManagedKey{KeyID: next.ID, Algorithm: next.Algorithm, Version: 2, State: "active", PublicDER: signer.Public().DER}, nil
}

func (s *servedPKCS11ManagedKeys) Revoke(ctx context.Context, tenantID, keyID, _, _ string) (api.ManagedKey, error) {
	ref, err := s.ref(tenantID, keyID)
	if err != nil {
		return api.ManagedKey{}, err
	}
	if err := s.lc.RevokeKey(ctx, ref); err != nil {
		return api.ManagedKey{}, err
	}
	return api.ManagedKey{KeyID: ref.ID, Algorithm: ref.Algorithm, Version: 2, State: "revoked"}, nil
}

func (s *servedPKCS11ManagedKeys) Zeroize(ctx context.Context, tenantID, keyID, _, _ string) (api.ManagedKey, error) {
	ref, err := s.ref(tenantID, keyID)
	if err != nil {
		return api.ManagedKey{}, err
	}
	if err := s.lc.ZeroizeKey(ctx, ref); err != nil {
		return api.ManagedKey{}, err
	}
	return api.ManagedKey{KeyID: ref.ID, Algorithm: ref.Algorithm, Version: 2, State: "zeroized"}, nil
}

func (s *servedPKCS11ManagedKeys) ref(tenantID, keyID string) (crypto.KeyRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, ok := s.keys[tenantID+"\x00"+keyID]
	if !ok {
		return crypto.KeyRef{}, api.ErrManagedKeyUnknown
	}
	return ref, nil
}

// TestServedPKCS11ManagedKeyLifecycleCAPKEY01 proves CAP-KEY-01 through the
// running control-plane surface: a PKCS#11/HSM backend is wired through the managed
// key factory and the served API drives generate, rotate, revoke, and zeroize using
// only opaque HSM object handles and public metadata.
func TestServedPKCS11ManagedKeyLifecycleCAPKEY01(t *testing.T) {
	session := newServedPKCS11Session()
	t.Cleanup(func() { _ = session.Close() })
	backend := pkcs11.New(session)
	var lifecycle crypto.RemoteKeyLifecycle = backend

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ManagedKeyFactory = func(md ManagedKeyServiceDeps) (api.ManagedKeyService, error) {
			if md.Log == nil || md.Idempotency == nil {
				t.Fatal("managed-key PKCS#11 factory did not receive event log and idempotency spine")
			}
			return newServedPKCS11ManagedKeys(lifecycle), nil
		}
	})
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "hsm-operator", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/managed-keys", token, "pkcs11-key-generate", map[string]string{
		"algorithm": string(crypto.RSA2048),
	})
	if code != http.StatusCreated {
		t.Fatalf("PKCS#11 managed-key generate = %d, want 201; body=%s", code, body)
	}
	generated := decodeManagedKey(t, body)
	if generated.KeyID == "" || generated.Algorithm != crypto.RSA2048 || generated.State != "active" || len(generated.PublicDER) == 0 {
		t.Fatalf("bad PKCS#11 generated key response: %+v", generated)
	}
	if !strings.HasPrefix(generated.KeyID, "pkcs11://") {
		t.Fatalf("PKCS#11 managed key id = %q, want opaque pkcs11 handle", generated.KeyID)
	}

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/managed-keys/rotate", token, "pkcs11-key-rotate", map[string]string{
		"key_id": generated.KeyID,
	})
	if code != http.StatusOK {
		t.Fatalf("PKCS#11 managed-key rotate = %d, want 200; body=%s", code, body)
	}
	rotated := decodeManagedKey(t, body)
	if rotated.KeyID == "" || rotated.KeyID == generated.KeyID || rotated.State != "active" || len(rotated.PublicDER) == 0 {
		t.Fatalf("bad PKCS#11 rotated key response: %+v", rotated)
	}

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/managed-keys/revoke", token, "pkcs11-key-revoke", map[string]string{
		"key_id": rotated.KeyID,
	})
	if code != http.StatusOK {
		t.Fatalf("PKCS#11 managed-key revoke = %d, want 200; body=%s", code, body)
	}
	revoked := decodeManagedKey(t, body)
	if revoked.State != "revoked" {
		t.Fatalf("PKCS#11 revoked state = %q, want revoked", revoked.State)
	}

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/managed-keys/zeroize", token, "pkcs11-key-zeroize", map[string]string{
		"key_id": rotated.KeyID,
	})
	if code != http.StatusOK {
		t.Fatalf("PKCS#11 managed-key zeroize = %d, want 200; body=%s", code, body)
	}
	zeroized := decodeManagedKey(t, body)
	if zeroized.State != "zeroized" {
		t.Fatalf("PKCS#11 zeroized state = %q, want zeroized", zeroized.State)
	}
}

func decodeManagedKey(t *testing.T, body []byte) api.ManagedKey {
	t.Helper()
	var key api.ManagedKey
	if err := json.Unmarshal(body, &key); err != nil {
		t.Fatalf("decode managed key: %v body=%s", err, body)
	}
	return key
}
