package server

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestFullBackupEncryptsSensitiveArtifacts(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "signer-auth-secret.bin")
	secretBytes := []byte("signer-auth-token-material")
	if err := os.WriteFile(src, secretBytes, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	defer secret.Wipe(key)
	keyID, err := backup.BackupArtifactKeyID(key)
	if err != nil {
		t.Fatalf("BackupArtifactKeyID: %v", err)
	}
	enc := &fullBackupEncryption{key: key, keyID: keyID}

	artifact, err := fileArtifact(
		"signer-auth-secret",
		"signer-auth-secret",
		src,
		filepath.Join(dir, "backup", "files", "signer-auth-secret.bin"),
		true,
		false,
		true,
		true,
		filepath.Join(dir, "backup"),
		enc,
	)
	if err != nil {
		t.Fatalf("fileArtifact: %v", err)
	}
	if artifact.Encryption == nil {
		t.Fatal("sensitive artifact was captured without encryption metadata")
	}
	stored, err := os.ReadFile(filepath.Join(dir, "backup", filepath.FromSlash(artifact.Path)))
	if err != nil {
		t.Fatalf("read encrypted artifact: %v", err)
	}
	if bytes.Contains(stored, secretBytes) {
		t.Fatal("encrypted backup artifact still contains signer auth material in plaintext")
	}
	if artifact.PlaintextSHA256 == "" || artifact.PlaintextBytes == 0 {
		t.Fatal("encrypted artifact manifest must keep plaintext digest metadata for restore verification")
	}
}

func TestFullRestoreDecryptsEncryptedArtifact(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "audit-signing-key.pem")
	want := []byte("audit-signing-private-key")
	if err := os.WriteFile(src, want, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	key := []byte("abcdef0123456789abcdef0123456789")
	defer secret.Wipe(key)
	keyID, err := backup.BackupArtifactKeyID(key)
	if err != nil {
		t.Fatalf("BackupArtifactKeyID: %v", err)
	}
	enc := &fullBackupEncryption{key: key, keyID: keyID}
	backupDir := filepath.Join(dir, "backup")

	artifact, err := fileArtifact(
		"audit-signing-key",
		"audit-signing-key",
		src,
		filepath.Join(backupDir, "files", "audit-signing-key.pem"),
		true,
		false,
		true,
		true,
		backupDir,
		enc,
	)
	if err != nil {
		t.Fatalf("fileArtifact: %v", err)
	}
	manifest := backup.NewFullManifest([]backup.Artifact{artifact})
	restored := filepath.Join(dir, "restore", "audit-signing-key.pem")
	if err := restoreFileArtifact(manifest, "audit-signing-key", backupDir, "files/audit-signing-key.pem", restored, key); err != nil {
		t.Fatalf("restoreFileArtifact: %v", err)
	}
	got, err := os.ReadFile(restored)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("restored artifact = %q, want %q", got, want)
	}
}
