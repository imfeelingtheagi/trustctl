// Command trustctl-cli is the trustctl command-line interface — a scriptable
// client at parity with the REST API (F11). Configuration comes from flags or
// the TRUSTCTL_SERVER / TRUSTCTL_TOKEN / TRUSTCTL_TENANT environment variables, so
// it drops cleanly into CI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"trustctl.io/trustctl/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	env := cli.Env{
		Server:         os.Getenv("TRUSTCTL_SERVER"),
		Token:          os.Getenv("TRUSTCTL_TOKEN"),
		Tenant:         os.Getenv("TRUSTCTL_TENANT"),
		IdempotencyKey: os.Getenv("TRUSTCTL_IDEMPOTENCY_KEY"),
	}
	os.Exit(cli.Run(ctx, os.Args[1:], env, os.Stdin, os.Stdout, os.Stderr))
}
