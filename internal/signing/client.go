package signing

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"certctl.io/certctl/internal/crypto"
	signerpb "certctl.io/certctl/internal/signing/proto"
)

// Client is a control-plane client of the signing service over a Unix domain
// socket. UDS is a local channel, so transport security is the socket's
// filesystem permissions plus SO_PEERCRED peer authentication (see peer.go),
// not TLS.
type Client struct {
	conn *grpc.ClientConn
	svc  signerpb.SignerServiceClient
}

// Dial connects to the signing service listening at socketPath.
func Dial(socketPath string) (*Client, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial signer: %w", err)
	}
	return &Client{conn: conn, svc: signerpb.NewSignerServiceClient(conn)}, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }

// Healthy reports whether the signer answers Health with SERVING.
func (c *Client) Healthy(ctx context.Context) bool {
	resp, err := c.svc.Health(ctx, &signerpb.HealthRequest{})
	return err == nil && resp.GetStatus() == signerpb.HealthResponse_STATUS_SERVING
}

// GenerateKey asks the signer to create a key and returns a RemoteSigner that
// signs through it. The private key never leaves the signer.
func (c *Client) GenerateKey(ctx context.Context, algorithm crypto.Algorithm) (*RemoteSigner, error) {
	resp, err := c.svc.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm: algorithmToProto(algorithm),
	})
	if err != nil {
		return nil, err
	}
	return &RemoteSigner{
		client:    c,
		handle:    resp.GetHandle(),
		algorithm: algorithm,
		public:    crypto.PublicKey{Algorithm: algorithm, DER: resp.GetPublicKey()},
	}, nil
}

// RemoteSigner is a crypto.DigestSigner backed by a key held inside the signer.
type RemoteSigner struct {
	client    *Client
	handle    *signerpb.KeyHandle
	algorithm crypto.Algorithm
	public    crypto.PublicKey
}

// Public returns the key's public key.
func (r *RemoteSigner) Public() crypto.PublicKey { return r.public }

// Algorithm reports the key's algorithm.
func (r *RemoteSigner) Algorithm() crypto.Algorithm { return r.algorithm }

// SignDigest signs digest by calling the signer's Sign RPC over the UDS.
func (r *RemoteSigner) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := r.client.svc.Sign(ctx, &signerpb.SignRequest{
		Handle:     r.handle,
		Digest:     digest,
		Hash:       hashToProto(opts.Hash),
		RsaPadding: paddingToProto(opts.RSAPadding),
	})
	if err != nil {
		return nil, err
	}
	return resp.GetSignature(), nil
}

// Destroy asks the signer to zeroize and forget the key.
func (r *RemoteSigner) Destroy(ctx context.Context) error {
	_, err := r.client.svc.DestroyKey(ctx, &signerpb.DestroyKeyRequest{Handle: r.handle})
	return err
}
