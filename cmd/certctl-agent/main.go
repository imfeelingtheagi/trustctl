// Command certctl-agent is the in-network agent.
//
// The agent registers with the control plane (bootstrap token; attestation is a
// later addition), communicates over mTLS with a short-lived, auto-rotating
// client certificate, and performs all key operations locally so that private
// keys never leave the host. Discovery, deployment, SSH trust, and drift
// reconciliation build on this core in later sprints.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"certctl.io/certctl/internal/agent"
	"certctl.io/certctl/internal/agent/transport"
	"certctl.io/certctl/internal/buildinfo"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	enrollURL := flag.String("enroll-url", "", "control-plane enrollment base URL")
	token := flag.String("bootstrap-token", "", "one-time bootstrap token")
	caBundle := flag.String("ca-bundle", "", "path to the control-plane CA certificate (PEM)")
	serverAddr := flag.String("server", "", "control-plane gRPC address")
	serverName := flag.String("server-name", "", "expected control-plane server name (defaults to --name)")
	commonName := flag.String("name", "", "this agent's identity (client-cert common name)")
	keyPath := flag.String("key", "agent.key", "path to persist the agent private key")
	certPath := flag.String("cert", "agent.crt", "path to persist the agent certificate")
	rotateEvery := flag.Duration("rotate-every", 12*time.Hour, "how often to rotate the client certificate")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("certctl-agent"))
		return
	}
	if *enrollURL == "" || *caBundle == "" || *serverAddr == "" || *commonName == "" {
		fmt.Fprintln(os.Stderr, "certctl-agent: --enroll-url, --ca-bundle, --server, and --name are required")
		os.Exit(2)
	}

	if err := run(agentOptions{
		enrollURL: *enrollURL, token: *token, caBundle: *caBundle,
		serverAddr: *serverAddr, serverName: *serverName, commonName: *commonName,
		keyPath: *keyPath, certPath: *certPath, rotateEvery: *rotateEvery,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "certctl-agent:", err)
		os.Exit(1)
	}
}

type agentOptions struct {
	enrollURL, token, caBundle, serverAddr, serverName, commonName, keyPath, certPath string
	rotateEvery                                                                       time.Duration
}

func run(o agentOptions) error {
	caPEM, err := os.ReadFile(o.caBundle)
	if err != nil {
		return fmt.Errorf("read CA bundle: %w", err)
	}
	serverName := o.serverName
	if serverName == "" {
		serverName = o.commonName
	}

	a := agent.New(agent.Config{
		CommonName:     o.commonName,
		BootstrapToken: o.token,
		KeyPath:        o.keyPath,
		CertPath:       o.certPath,
		ServerName:     serverName,
		ServerCAPEM:    caPEM,
		RefreshBefore:  o.rotateEvery,
	}, agent.NewHTTPEnroller(o.enrollURL, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := a.Bootstrap(ctx); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	creds, err := a.Credentials()
	if err != nil {
		return err
	}
	conn, err := transport.Dial(o.serverAddr, creds)
	if err != nil {
		return fmt.Errorf("connect to control plane: %w", err)
	}
	defer conn.Close()
	fmt.Printf("certctl-agent: connected to %s as %s (cert serial %s, expires %s)\n",
		o.serverAddr, o.commonName, a.CertificateSerial(), a.CertificateNotAfter().Format(time.RFC3339))

	ticker := time.NewTicker(o.rotateEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("certctl-agent: shutting down")
			return nil
		case <-ticker.C:
			if err := a.Rotate(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "certctl-agent: rotation failed:", err)
				continue
			}
			fmt.Printf("certctl-agent: rotated client certificate (serial %s)\n", a.CertificateSerial())
		}
	}
}
