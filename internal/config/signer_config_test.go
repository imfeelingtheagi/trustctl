package config_test

import (
	"testing"

	"trustctl.io/trustctl/internal/config"
)

// TestSignerDefaultsToChild: the signer is a supervised child by default, with a
// sealed key store and a persisted CA cert so a restart preserves the CA (R3.2).
func TestSignerDefaultsToChild(t *testing.T) {
	c := config.Default()
	if c.Signer.Mode != config.SignerChild {
		t.Errorf("signer.mode default = %q, want %q", c.Signer.Mode, config.SignerChild)
	}
	if c.Signer.KeyStoreDir == "" {
		t.Error("signer.key_store_dir should have a default (sealed key persistence)")
	}
	if c.CA.CertFile == "" {
		t.Error("ca.cert_file should have a default (persisted issuing-CA cert)")
	}
}

// TestSignerExternalRequiresSocket: an external signer needs a socket; a bogus
// mode fails fast.
func TestSignerExternalRequiresSocket(t *testing.T) {
	base := map[string]string{
		"TRUSTCTL_POSTGRES_MODE": "external",
		"TRUSTCTL_POSTGRES_DSN":  "postgres://u:p@h:5432/db?sslmode=require",
		"TRUSTCTL_NATS_MODE":     "external",
		"TRUSTCTL_NATS_URL":      "nats://h:4222",
	}

	if _, err := config.Load(envFunc(base, map[string]string{"TRUSTCTL_SIGNER_MODE": "external"})); err == nil {
		t.Error("external signer without a socket should fail validation")
	}
	if _, err := config.Load(envFunc(base, map[string]string{
		"TRUSTCTL_SIGNER_MODE":   "external",
		"TRUSTCTL_SIGNER_SOCKET": "/run/trustctl/signer.sock",
	})); err != nil {
		t.Errorf("external signer with a socket should validate: %v", err)
	}
	if _, err := config.Load(envFunc(base, map[string]string{"TRUSTCTL_SIGNER_MODE": "bogus"})); err == nil {
		t.Error("an invalid signer.mode should fail validation")
	}
}
