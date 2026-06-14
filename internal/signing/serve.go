package signing

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"google.golang.org/grpc"

	signerpb "trustctl.io/trustctl/internal/signing/proto"
)

// maxMessageBytes bounds gRPC request/response size; the signer signs digests,
// not bulk data.
const maxMessageBytes = 1 << 20 // 1 MiB

// maxConcurrentStreams caps concurrent HTTP/2 streams at the gRPC transport as a
// first AN-7 bound (gRPC's default is effectively unbounded). The application
// layer adds a tighter semaphore over the expensive RPCs (see bulkhead.go). It
// is set above defaultMaxInflight so cheap RPCs (Health/GetPublicKey/DestroyKey)
// still get through while expensive ones are shedding load.
const maxConcurrentStreams = 256

// ServeOptions tunes the serving path. The zero value uses safe defaults.
type ServeOptions struct {
	// MaxInflight bounds concurrent expensive (key-using) RPCs; excess is
	// rejected with RESOURCE_EXHAUSTED (AN-7, SIGNER-001). <=0 means
	// defaultMaxInflight.
	MaxInflight int
}

// Serve runs an in-memory signing service on a Unix domain socket at socketPath
// (keys do not survive a restart). For persistent CA-key custody, build a
// persistent server and use ServeServer.
func Serve(ctx context.Context, socketPath string) error {
	return ServeServer(ctx, socketPath, NewServer())
}

// ServeServer runs the given signing server on a Unix domain socket at
// socketPath until ctx is cancelled, then drains in-flight requests and zeroizes
// all keys. The socket lives in a 0700 directory as a 0600 socket, and
// connections are restricted to the signer's own uid (SO_PEERCRED on Linux). A
// persistent server (NewPersistentServer) gives the issuing CA key custody that
// survives a restart (R3.2).
func ServeServer(ctx context.Context, socketPath string, svc *Server) error {
	return ServeServerWithOptions(ctx, socketPath, svc, ServeOptions{})
}

// ServeServerWithOptions is ServeServer with explicit AN-7 tuning.
func ServeServerWithOptions(ctx context.Context, socketPath string, svc *Server, opts ServeOptions) error {
	ln, err := listenUDS(socketPath)
	if err != nil {
		return err
	}

	// AN-7 backpressure: bound concurrent expensive RPCs and reject the excess
	// fast with RESOURCE_EXHAUSTED, so a flood of Sign/GenerateKey calls cannot
	// exhaust the signer (SIGNER-001). MaxConcurrentStreams caps HTTP/2 streams
	// at the transport; the unary interceptor enforces the in-flight semaphore
	// and a per-RPC deadline at the application layer.
	inflight := opts.MaxInflight
	if inflight <= 0 {
		inflight = defaultMaxInflight
	}
	lim := newLimiter(inflight)
	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxMessageBytes),
		grpc.MaxSendMsgSize(maxMessageBytes),
		grpc.MaxConcurrentStreams(maxConcurrentStreams),
		grpc.UnaryInterceptor(bulkheadInterceptor(lim)),
	)
	signerpb.RegisterSignerServiceServer(srv, svc)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		srv.GracefulStop() // wait for in-flight RPCs to finish...
		svc.Shutdown()     // ...then zeroize keys (no handler is running now)
		<-errc             // Serve returns nil after GracefulStop
		return nil
	case err := <-errc:
		svc.Shutdown()
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	}
}

// listenUDS creates the socket directory (0700), removes any stale socket,
// listens, tightens the socket to 0600, and wraps the listener with peer-uid
// authentication.
func listenUDS(socketPath string) (net.Listener, error) {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod socket dir: %w", err)
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen unix: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return newPeerAuthListener(ln, os.Geteuid()), nil
}
