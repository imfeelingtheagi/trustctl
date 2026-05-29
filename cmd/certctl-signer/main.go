// Command certctl-signer is the isolated signing service (AN-4).
//
// It is a separate, sacred process: it serves the SignerService over gRPC on a
// Unix domain socket, performs all private-key operations behind that boundary,
// and has no HTTP server, no SQL driver, and no third-party logging. In
// single-node mode the control plane launches it as a child process (see
// internal/signing.StartChild). The design is in docs/design/signing-service.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"certctl.io/certctl/internal/buildinfo"
	"certctl.io/certctl/internal/signing"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	socket := flag.String("socket", "", "path to the Unix domain socket to listen on")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("certctl-signer"))
		return
	}
	if *socket == "" {
		fmt.Fprintln(os.Stderr, "certctl-signer: --socket is required")
		os.Exit(2)
	}

	// Process-level memory protection before any key touches memory (AN-8).
	if err := signing.Harden(); err != nil {
		fmt.Fprintf(os.Stderr, "certctl-signer: harden: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := signing.Serve(ctx, *socket); err != nil {
		fmt.Fprintf(os.Stderr, "certctl-signer: %v\n", err)
		os.Exit(1)
	}
}
