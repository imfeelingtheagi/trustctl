package embedded_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/protocols/est"
)

type allowAll struct{}

func (allowAll) Authenticate(*http.Request) bool { return true }

type signingEnroller struct {
	caCertDER []byte
	caSigner  *crypto.LockedSigner
}

func (e signingEnroller) Enroll(_ context.Context, csrDER []byte, _, _, _ string) ([]byte, error) {
	return crypto.SignLeafFromCSR(e.caCertDER, e.caSigner, csrDER, time.Hour)
}

// TestEmbeddedESTClientEnrolls compiles the C EST client with cc and runs it end-to-end
// against the real EST server, proving a constrained-device enrollment works.
func TestEmbeddedESTClientEnrolls(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("cc not available; the embedded EST client is built on the CI backstop")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl CLI not available; required by the embedded client")
	}

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "est_client")
	build := exec.Command("cc", "-O2", "-o", bin, filepath.Join("csrc", "est_client.c"))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cc build failed: %v\n%s", err, out)
	}

	caSigner, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer caSigner.Destroy()
	caCertDER, err := crypto.SelfSignedCACert(caSigner, "EST C-client Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := est.New(est.Config{
		Enroller:   signingEnroller{caCertDER: caCertDER, caSigner: caSigner},
		Auth:       allowAll{},
		CAChainDER: [][]byte{caCertDER},
		ProfileName: "device",
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	enrollDir := filepath.Join(tmp, "enroll")
	if err := os.MkdirAll(enrollDir, 0o755); err != nil {
		t.Fatal(err)
	}
	run := exec.Command(bin, ts.URL, enrollDir)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("embedded EST client failed: %v\n%s", err, out)
	}

	cert, err := os.ReadFile(filepath.Join(enrollDir, "cert.pem"))
	if err != nil || !bytes.Contains(cert, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("client did not produce a certificate (err=%v)", err)
	}
}
