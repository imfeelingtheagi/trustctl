package signing

import (
	"context"
	"encoding/hex"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trustctl.io/trustctl/internal/crypto"
	signerpb "trustctl.io/trustctl/internal/signing/proto"
)

// heldKey is a key the signer holds: its locked private material plus the
// signer-enforceable usage constraints declared at creation (SIGNER-002/003).
type heldKey struct {
	signer      *crypto.LockedSigner
	constraints keyConstraints
}

// Server implements signerpb.SignerServiceServer. Private keys are held as
// LockedSigner values (AN-8: PKCS#8 DER in mlock'd, non-dumpable, zeroizable
// memory) in an in-memory store keyed by opaque handle. Private-key bytes never
// cross the gRPC boundary. Each key carries its usage constraints, which the
// signer enforces on every Sign (AN-7-bulkheaded at the transport).
type Server struct {
	signerpb.UnimplementedSignerServiceServer

	mu      sync.Mutex
	keys    map[string]*heldKey
	serving bool
	store   *KeyStore // optional sealed persistence; nil = in-memory only

	// signGate, when non-nil, is called inside Sign while it holds its in-flight
	// bulkhead slot. It is a test-only seam (set via export_test.go) used to make
	// the served saturation test deterministic; it is nil in production and has
	// zero effect there.
	signGate func()
}

// NewServer returns a ready in-memory signing server (keys do not survive a
// restart).
func NewServer() *Server {
	return &Server{keys: make(map[string]*heldKey), serving: true}
}

// NewPersistentServer returns a signing server backed by a sealed key store: it
// loads any persisted keys on construction (so a restart preserves the issuing CA
// rather than silently rotating it, R3.2) and seals new keys as they are
// generated. Usage constraints are sealed with the key and restored too, so a
// CA-class key stays purpose-bound across a restart.
func NewPersistentServer(store *KeyStore) (*Server, error) {
	keys, err := store.Load()
	if err != nil {
		return nil, err
	}
	return &Server{keys: keys, serving: true, store: store}, nil
}

// GenerateKey creates a new key inside the signer and returns its handle and
// public key. Any usage constraints on the request (allowed_purposes /
// allowed_hashes, SIGNER-002/003) are bound to the key and enforced on every
// subsequent Sign.
func (s *Server) GenerateKey(_ context.Context, req *signerpb.GenerateKeyRequest) (*signerpb.GenerateKeyResponse, error) {
	alg, err := algorithmFromProto(req.GetAlgorithm())
	if err != nil {
		return nil, err
	}
	constraints, err := constraintsFromGenerate(req)
	if err != nil {
		return nil, err
	}
	ls, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate key: %v", err)
	}
	id := req.GetRequestedId()
	if id == "" {
		raw, err := crypto.RandomBytes(16)
		if err != nil {
			ls.Destroy()
			return nil, status.Errorf(codes.Internal, "generate handle: %v", err)
		}
		id = hex.EncodeToString(raw)
	}

	held := &heldKey{signer: ls, constraints: constraints}

	s.mu.Lock()
	if _, exists := s.keys[id]; exists {
		s.mu.Unlock()
		ls.Destroy()
		return nil, status.Error(codes.AlreadyExists, "key handle already exists")
	}
	s.keys[id] = held
	s.mu.Unlock()

	// Persist the new key sealed at rest (R3.2) so it survives a signer restart.
	// The usage constraints are sealed with the key (and bound to the handle as
	// AAD), so a CA-class key stays purpose-bound across a restart. On failure,
	// roll back the in-memory insert so state stays consistent.
	if s.store != nil {
		if err := s.store.Save(id, ls, constraints); err != nil {
			s.mu.Lock()
			delete(s.keys, id)
			s.mu.Unlock()
			ls.Destroy()
			return nil, status.Errorf(codes.Internal, "persist key: %v", err)
		}
	}

	return &signerpb.GenerateKeyResponse{
		Handle:    &signerpb.KeyHandle{Id: id},
		Algorithm: algorithmToProto(alg),
		PublicKey: ls.Public().DER,
	}, nil
}

// GetPublicKey returns the public key for a handle.
func (s *Server) GetPublicKey(_ context.Context, req *signerpb.GetPublicKeyRequest) (*signerpb.GetPublicKeyResponse, error) {
	held, err := s.lookup(req.GetHandle())
	if err != nil {
		return nil, err
	}
	return &signerpb.GetPublicKeyResponse{
		Algorithm: algorithmToProto(held.signer.Algorithm()),
		PublicKey: held.signer.Public().DER,
	}, nil
}

// Sign signs a pre-computed digest with the keyed handle. If the key was created
// with usage constraints (SIGNER-002/003), the request's asserted purpose and
// hash must satisfy them or the signature is refused with FAILED_PRECONDITION —
// so socket access alone cannot coerce a key into signing outside its mandate.
func (s *Server) Sign(_ context.Context, req *signerpb.SignRequest) (*signerpb.SignResponse, error) {
	if err := validateSignRequest(req); err != nil {
		return nil, err
	}
	held, err := s.lookup(req.GetHandle())
	if err != nil {
		return nil, err
	}
	if err := held.constraints.check(req); err != nil {
		return nil, err
	}
	if s.signGate != nil {
		s.signGate() // test-only: hold the in-flight slot (nil in production)
	}
	hash, _, _ := hashFromProto(req.GetHash()) // validated above
	sig, err := held.signer.SignDigest(req.GetDigest(), crypto.SignOptions{
		Hash:       hash,
		RSAPadding: paddingFromProto(req.GetRsaPadding()),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign: %v", err)
	}
	return &signerpb.SignResponse{Signature: sig}, nil
}

// DestroyKey zeroizes and forgets a handle. It is idempotent.
func (s *Server) DestroyKey(_ context.Context, req *signerpb.DestroyKeyRequest) (*signerpb.DestroyKeyResponse, error) {
	h := req.GetHandle()
	if h == nil || h.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing key handle")
	}
	s.mu.Lock()
	held, ok := s.keys[h.GetId()]
	if ok {
		delete(s.keys, h.GetId())
	}
	s.mu.Unlock()
	if ok {
		held.signer.Destroy()
		if s.store != nil {
			if err := s.store.Remove(h.GetId()); err != nil {
				return nil, status.Errorf(codes.Internal, "remove persisted key: %v", err)
			}
		}
	}
	return &signerpb.DestroyKeyResponse{}, nil
}

// Health reports whether the server is serving or draining.
func (s *Server) Health(_ context.Context, _ *signerpb.HealthRequest) (*signerpb.HealthResponse, error) {
	s.mu.Lock()
	serving := s.serving
	s.mu.Unlock()
	st := signerpb.HealthResponse_STATUS_SERVING
	if !serving {
		st = signerpb.HealthResponse_STATUS_DRAINING
	}
	return &signerpb.HealthResponse{Status: st}, nil
}

// Shutdown marks the server draining and zeroizes every key it holds.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serving = false
	for id, held := range s.keys {
		held.signer.Destroy()
		delete(s.keys, id)
	}
}

func (s *Server) lookup(h *signerpb.KeyHandle) (*heldKey, error) {
	if h == nil || h.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing key handle")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	held, ok := s.keys[h.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "unknown key handle")
	}
	return held, nil
}
