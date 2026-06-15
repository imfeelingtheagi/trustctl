// Command trustctl-agent is the in-network agent.
//
// The agent registers with the control plane (bootstrap token; attestation is a
// later addition), communicates over mTLS with a short-lived, auto-rotating
// client certificate, and performs all key operations locally so that private
// keys never leave the host. On Windows it can run under the Service Control
// Manager (--service); see service_windows.go. Discovery, deployment, SSH
// trust, and drift reconciliation build on this core in later sprints.
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"trustctl.io/trustctl/internal/agent"
	"trustctl.io/trustctl/internal/agent/transport"
	"trustctl.io/trustctl/internal/buildinfo"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	service := flag.String("service", "", "Windows service control: install | uninstall | run")
	enrollURL := flag.String("enroll-url", "", "control-plane enrollment base URL")
	token := flag.String("bootstrap-token", "", "one-time bootstrap token")
	caBundle := flag.String("ca-bundle", "", "path to the control-plane CA certificate (PEM)")
	serverAddr := flag.String("server", "", "control-plane gRPC address")
	serverName := flag.String("server-name", "", "expected control-plane server name (defaults to --name)")
	commonName := flag.String("name", "", "this agent's identity (client-cert common name)")
	keyPath := flag.String("key", "agent.key", "path to persist the agent private key")
	certPath := flag.String("cert", "agent.crt", "path to persist the agent certificate")
	rotateEvery := flag.Duration("rotate-every", 12*time.Hour, "how often to rotate the client certificate")
	k8sMode := flag.Bool("k8s", false, "run as a Kubernetes DaemonSet: publish the identity into a Secret and bridge cert-manager")
	k8sSecret := flag.String("k8s-secret", "", "Kubernetes Secret to publish the identity into (namespace/name)")
	cmIssuer := flag.String("cert-manager-issuer", "", "cert-manager issuerRef name to bridge (enables the external issuer)")
	cmGroup := flag.String("cert-manager-group", "trustctl.io", "cert-manager issuerRef group")
	bridgeSignerURL := flag.String("bridge-signer-url", "", "control-plane issuance URL the cert-manager bridge forwards CSRs to")
	reconcileEvery := flag.Duration("reconcile-every", 30*time.Second, "how often the cert-manager bridge reconciles")
	// Privileged SSH-trust rewrite (SIGNER-004) — DEFAULT OFF. A one-shot op that
	// adds the SSH CA to this host's TrustedUserCAKeys (additive; never removes
	// existing trust), validated with `sshd -t`, reloaded, and auto-rolled-back on
	// failure. Gated behind --ssh-trust-confirm because weakening sshd trust is a
	// lockout-class mutation (CLAUDE.md §8).
	sshTrustAddCA := flag.Bool("ssh-trust-add-ca", false, "ADD the SSH CA to this host's trust (default off; additive, with rollback). Requires --ssh-trust-confirm")
	sshTrustConfirm := flag.Bool("ssh-trust-confirm", false, "explicit confirmation required to rewrite SSH CA trust")
	sshTrustCAKey := flag.String("ssh-trust-ca-key", "", "path to the SSH CA public key (OpenSSH authorized-key line) to trust")
	sshTrustTenant := flag.String("ssh-trust-tenant", "", "tenant the SSH-trust change is audited under (AN-1)")
	sshTrustConfig := flag.String("ssh-trust-sshd-config", "/etc/ssh/sshd_config", "path to sshd_config")
	sshTrustKeysFile := flag.String("ssh-trust-keys-file", "/etc/ssh/trusted_user_ca_keys", "path to TrustedUserCAKeys")
	sshTrustReloadCmd := flag.String("ssh-trust-reload-cmd", "", "command to reload sshd after a validated config change (e.g. \"systemctl reload sshd\"); required for --ssh-trust-add-ca")
	sshTrustValidateCmd := flag.String("ssh-trust-validate-cmd", "sshd -t", "command that validates sshd config before reload")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("trustctl-agent"))
		return
	}

	// Privileged SSH-trust rewrite (SIGNER-004): a self-contained, default-off,
	// explicitly-confirmed one-shot op that does NOT need the enroll/connection
	// settings, so it runs (and exits) before the steady-state agent loop. With the
	// flag off this is a no-op and the agent proceeds normally.
	sshCtx, sshStop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	if handled, err := runSSHTrustAddCA(sshCtx, sshTrustOptions{
		addCA: *sshTrustAddCA, confirm: *sshTrustConfirm, caKeyPath: *sshTrustCAKey,
		tenantID: *sshTrustTenant, sshdConfig: *sshTrustConfig, trustedKeys: *sshTrustKeysFile,
		reloadCmd: *sshTrustReloadCmd, validateCmd: *sshTrustValidateCmd,
	}); handled {
		sshStop()
		if err != nil {
			fmt.Fprintln(os.Stderr, "trustctl-agent:", err)
			os.Exit(1)
		}
		return
	}
	sshStop()

	o := agentOptions{
		enrollURL: *enrollURL, token: *token, caBundle: *caBundle,
		serverAddr: *serverAddr, serverName: *serverName, commonName: *commonName,
		keyPath: *keyPath, certPath: *certPath, rotateEvery: *rotateEvery,
	}

	// Uninstalling a service needs no connection settings; everything else does.
	if *service != "uninstall" {
		if o.enrollURL == "" || o.caBundle == "" || o.serverAddr == "" || o.commonName == "" {
			fmt.Fprintln(os.Stderr, "trustctl-agent: --enroll-url, --ca-bundle, --server, and --name are required")
			os.Exit(2)
		}
	}

	if *service != "" {
		if err := handleService(*service, o); err != nil {
			fmt.Fprintln(os.Stderr, "trustctl-agent:", err)
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	run := runAgent
	if *k8sMode {
		kopts := k8sOptions{
			secret: *k8sSecret, issuer: *cmIssuer, group: *cmGroup,
			signerURL: *bridgeSignerURL, reconcileEvery: *reconcileEvery,
		}
		run = func(ctx context.Context, o agentOptions) error { return runKubernetes(ctx, o, kopts) }
	}
	if err := run(ctx, o); err != nil {
		fmt.Fprintln(os.Stderr, "trustctl-agent:", err)
		os.Exit(1)
	}
}

type agentOptions struct {
	enrollURL, token, caBundle, serverAddr, serverName, commonName, keyPath, certPath string
	rotateEvery                                                                       time.Duration
}

// runAgent bootstraps the agent, connects to the control plane over mTLS, and
// rotates its client certificate on a timer until ctx is cancelled. It is the
// shared loop for both interactive use and the Windows service.
func runAgent(ctx context.Context, o agentOptions) error {
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
	defer func() { _ = conn.Close() }()
	fmt.Printf("trustctl-agent: connected to %s as %s (cert serial %s, expires %s)\n",
		o.serverAddr, o.commonName, a.CertificateSerial(), a.CertificateNotAfter().Format(time.RFC3339))

	ticker := time.NewTicker(o.rotateEvery)
	defer ticker.Stop()
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for {
		select {
		case <-ctx.Done():
			fmt.Println("trustctl-agent: shutting down")
			return nil
		case <-ticker.C:
			// Rotate with jittered exponential backoff on failure (RESIL-006): a
			// control-plane outage during the refresh window must not be a single
			// missed attempt that then waits a full rotate-every interval — the agent
			// retries promptly with backoff until it succeeds, the deadline (the next
			// regular tick) passes, or shutdown. The jitter spreads a fleet's
			// reconnects so a recovering control plane is not stampeded (no thundering
			// herd). The existing certificate stays valid until expiry and the identity
			// survives restart, so a sub-window outage is harmless.
			rotateWithBackoff(ctx, a, o.rotateEvery, rng)
		}
	}
}

// rotateBackoffBase / Max bound the agent's retry schedule on a failed rotation
// (RESIL-006). The delay grows exponentially from the base, is capped at Max, and
// has full jitter applied, so retries are prompt but spread across a fleet.
const (
	rotateBackoffBase = 1 * time.Second
	rotateBackoffMax  = 60 * time.Second
)

// rotateWithBackoff attempts a.Rotate, and on failure keeps retrying with full-
// jitter exponential backoff until it succeeds, the budget elapses (so the next
// regular rotation tick takes over), or ctx is cancelled (RESIL-006). The budget is
// the regular rotation interval, so a persistent outage falls back to the normal
// cadence rather than spinning forever on a tight loop.
func rotateWithBackoff(ctx context.Context, a *agent.Agent, budget time.Duration, rng *rand.Rand) {
	deadline := time.Now().Add(budget)
	for attempt := 0; ; attempt++ {
		if err := a.Rotate(ctx); err == nil {
			fmt.Printf("trustctl-agent: rotated client certificate (serial %s)\n", a.CertificateSerial())
			return
		} else {
			fmt.Fprintln(os.Stderr, "trustctl-agent: rotation failed:", err)
		}
		delay := rotateBackoff(attempt, rng)
		if time.Now().Add(delay).After(deadline) {
			// The next regular tick is sooner than the next backoff retry — let the
			// ticker drive the next attempt instead of overshooting the cadence.
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// rotateBackoff returns the delay before retry attempt n (0-based): an exponential
// backoff base*2^n capped at Max, with full jitter (a uniform value in (0, capped]).
// Full jitter is the AWS-recommended schedule for de-correlating a fleet's retries.
// It never returns a non-positive duration, so a recovering agent cannot spin.
func rotateBackoff(attempt int, rng *rand.Rand) time.Duration {
	d := rotateBackoffBase
	for i := 0; i < attempt && d < rotateBackoffMax; i++ {
		d *= 2
	}
	if d > rotateBackoffMax {
		d = rotateBackoffMax
	}
	// Full jitter in (0, d]: a uniform pick, clamped to at least 1ns so it is strictly
	// positive and the loop always makes progress.
	jittered := time.Duration(rng.Int63n(int64(d))) + 1
	return jittered
}
