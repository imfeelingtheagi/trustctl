package signing_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/pqc"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// TestSignerBinarySignsPQCOverUDS is the PQC-01 served-path acceptance test:
// post-quantum keys must be generated inside the isolated signer process and
// used through the UDS Sign RPC. The signer RPC accepts pre-computed digests, so
// the PQC verifier checks the exact digest bytes that crossed the AN-4 boundary.
func TestSignerBinarySignsPQCOverUDS(t *testing.T) {
	bin := buildSigner(t)
	dir, err := os.MkdirTemp("", "pqc")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "s.sock")

	ctx := context.Background()
	client, stop, err := signing.StartChild(ctx, bin, socket, devSignerArgs()...)
	if err != nil {
		t.Fatalf("StartChild: %v", err)
	}
	defer stop()
	defer func() { _ = client.Close() }()

	digest, err := crypto.Digest(crypto.SHA256, []byte("PQC-01 served signer known vector"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		algorithm crypto.Algorithm
		proto     signerpb.Algorithm
		verify    func(crypto.PublicKey, []byte, []byte) error
	}{
		{
			name:      "ml-dsa-44",
			algorithm: crypto.MLDSA44,
			proto:     signerpb.Algorithm_ALGORITHM_ML_DSA_44,
			verify:    pqc.Verify,
		},
		{
			name:      "slh-dsa-sha2-128f",
			algorithm: crypto.SLHDSA128f,
			proto:     signerpb.Algorithm_ALGORITHM_SLH_DSA_SHA2_128F,
			verify:    crypto.VerifySLHDSA,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := client.RawGenerateKeyForTest(ctx, tt.proto)
			if err != nil {
				t.Fatalf("RawGenerateKeyForTest(%s): %v", tt.algorithm, err)
			}
			if got := raw.GetAlgorithm(); got != tt.proto {
				t.Fatalf("raw algorithm = %v, want %v", got, tt.proto)
			}

			signer, err := client.SignerForHandle(ctx, raw.GetHandle().GetId())
			if err != nil {
				t.Fatalf("SignerForHandle(%s): %v", tt.algorithm, err)
			}
			if got := signer.Algorithm(); got != tt.algorithm {
				t.Fatalf("remote signer algorithm = %s, want %s", got, tt.algorithm)
			}

			sig, err := signer.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256})
			if err != nil {
				t.Fatalf("SignDigest(%s): %v", tt.algorithm, err)
			}
			if err := tt.verify(signer.Public(), digest, sig); err != nil {
				t.Fatalf("verify %s signature from signer process: %v", tt.algorithm, err)
			}
		})
	}
}
