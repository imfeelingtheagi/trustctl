package signing

import (
	"context"
	"encoding/hex"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"certctl.io/certctl/internal/crypto"
	signerpb "certctl.io/certctl/internal/signing/proto"
)

// Server implements signerpb.SignerServiceServer. Private keys are held as
// LockedSigner values (AN-8: PKCS#8 DER in mlock'd, non-dumpable, zeroizable
// memory) in an in-memory store keyed by opaque handle. Private-key bytes never
// cross the gRPC boundary.
type Server struct {
	signerpb.UnimplementedSignerServiceServer

	mu      sync.Mutex
	keys    map[string]*crypto.LockedSigner
	serving bool
}

// NewServer returns a ready signing server.
func NewServer() *Server {
	return &Server{keys: make(map[string]*crypto.LockedSigner), serving: true}
}

// GenerateKey creates a new key inside the signer and returns its handle and
// public key.
func (s *Server) GenerateKey(_ context.Context, req *signerpb.GenerateKeyRequest) (*signerpb.GenerateKeyResponse, error) {
	alg, err := algorithmFromProto(req.GetAlgorithm())
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

	s.mu.Lock()
	if _, exists := s.keys[id]; exists {
		s.mu.Unlock()
		ls.Destroy()
		return nil, status.Error(codes.AlreadyExists, "key handle already exists")
	}
	s.keys[id] = ls
	s.mu.Unlock()

	return &signerpb.GenerateKeyResponse{
		Handle:    &signerpb.KeyHandle{Id: id},
		Algorithm: algorithmToProto(alg),
		PublicKey: ls.Public().DER,
	}, nil
}

// GetPublicKey returns the public key for a handle.
func (s *Server) GetPublicKey(_ context.Context, req *signerpb.GetPublicKeyRequest) (*signerpb.GetPublicKeyResponse, error) {
	ls, err := s.lookup(req.GetHandle())
	if err != nil {
		return nil, err
	}
	return &signerpb.GetPublicKeyResponse{
		Algorithm: algorithmToProto(ls.Algorithm()),
		PublicKey: ls.Public().DER,
	}, nil
}

// Sign signs a pre-computed digest with the keyed handle.
func (s *Server) Sign(_ context.Context, req *signerpb.SignRequest) (*signerpb.SignResponse, error) {
	if err := validateSignRequest(req); err != nil {
		return nil, err
	}
	ls, err := s.lookup(req.GetHandle())
	if err != nil {
		return nil, err
	}
	hash, _, _ := hashFromProto(req.GetHash()) // validated above
	sig, err := ls.SignDigest(req.GetDigest(), crypto.SignOptions{
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
	ls, ok := s.keys[h.GetId()]
	if ok {
		delete(s.keys, h.GetId())
	}
	s.mu.Unlock()
	if ok {
		ls.Destroy()
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
	for id, ls := range s.keys {
		ls.Destroy()
		delete(s.keys, id)
	}
}

func (s *Server) lookup(h *signerpb.KeyHandle) (*crypto.LockedSigner, error) {
	if h == nil || h.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing key handle")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ls, ok := s.keys[h.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "unknown key handle")
	}
	return ls, nil
}
