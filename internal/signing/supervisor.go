package signing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// StartChild launches the signer binary as a child process listening on
// socketPath (single-node mode), waits until it is healthy, and returns a
// connected Client plus a stop function. This is the control-plane side of the
// AN-4 process boundary: the signer runs as its own process, reached only over
// the UDS.
func StartChild(ctx context.Context, binaryPath, socketPath string) (*Client, func(), error) {
	cmd := exec.Command(binaryPath, "--socket", socketPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start signer: %w", err)
	}

	client, err := dialReady(ctx, socketPath, 10*time.Second)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, nil, err
	}

	stop := func() {
		_ = client.Close()
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _, _ = cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
	return client, stop, nil
}

// dialReady connects and retries Health until the signer is serving or the
// timeout passes.
func dialReady(ctx context.Context, socketPath string, timeout time.Duration) (*Client, error) {
	client, err := Dial(socketPath)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		hctx, cancel := context.WithTimeout(ctx, time.Second)
		ok := client.Healthy(hctx)
		cancel()
		if ok {
			return client, nil
		}
		if time.Now().After(deadline) {
			_ = client.Close()
			return nil, fmt.Errorf("signer not ready within %s", timeout)
		}
		select {
		case <-ctx.Done():
			_ = client.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
