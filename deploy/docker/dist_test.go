package docker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readArtifact reads a distribution file relative to this package directory and
// fails the test if it is missing.
func readArtifact(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func mustContainAll(t *testing.T, name, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("%s: expected to contain %q", name, w)
		}
	}
}

func mustContainAny(t *testing.T, name, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if strings.Contains(body, w) {
			return
		}
	}
	t.Errorf("%s: expected to contain one of %v", name, wants)
}

// TestDockerfileIsMinimalAndReproducible encodes the image half of the
// acceptance: a small (distroless/scratch) image built reproducibly (no CGO,
// trimmed paths, pinned build id), running unprivileged, and carrying both the
// control plane and the isolated signer (AN-4).
func TestDockerfileIsMinimalAndReproducible(t *testing.T) {
	df := readArtifact(t, "Dockerfile")

	mustContainAny(t, "Dockerfile base image", df, "distroless", "scratch")
	mustContainAll(t, "Dockerfile reproducible build flags", df,
		"CGO_ENABLED=0", "-trimpath", "-buildid=", "-buildvcs=false")
	// Both binaries ship: the control plane and the sacred signer process (AN-4).
	mustContainAll(t, "Dockerfile binaries", df, "./cmd/certctl", "./cmd/certctl-signer")
	// Unprivileged runtime.
	mustContainAny(t, "Dockerfile non-root user", df, "nonroot", "USER 65532")
	mustContainAll(t, "Dockerfile entrypoint", df, "ENTRYPOINT")
}

// TestComposeBringsUpEvaluableStack encodes the Compose half of the acceptance:
// `docker compose up` brings up the control plane against Postgres and NATS, and
// the control plane is wired to them as an EXTERNAL datastore configuration
// (which is exactly the external-datastore path the acceptance asks to be
// tested).
func TestComposeBringsUpEvaluableStack(t *testing.T) {
	c := readArtifact(t, "docker-compose.yml")

	mustContainAll(t, "compose services", c, "postgres", "nats", "certctl")
	// JetStream must be enabled for the event spine (AN-2).
	mustContainAny(t, "compose nats jetstream", c, "-js", "--jetstream", "jetstream")
	// The control plane points at the external datastores by environment.
	mustContainAll(t, "compose external datastore wiring", c,
		"CERTCTL_POSTGRES_MODE", "external",
		"CERTCTL_POSTGRES_DSN", "CERTCTL_NATS_MODE", "CERTCTL_NATS_URL")
	// Ordered, health-gated startup.
	mustContainAll(t, "compose health/ordering", c, "healthcheck", "depends_on")
}

// TestReleaseWorkflowSignsAndAttests encodes "images are cosign-signed and ship
// an SBOM", published to GHCR with a Docker Hub mirror, built reproducibly, and
// gated under 20 MB.
func TestReleaseWorkflowSignsAndAttests(t *testing.T) {
	wf := readArtifact(t, filepath.Join("..", "..", ".github", "workflows", "release.yml"))

	mustContainAll(t, "release cosign signing", wf, "cosign")
	mustContainAny(t, "release CycloneDX SBOM", wf, "cyclonedx", "CycloneDX", "sbom", "SBOM")
	mustContainAll(t, "release GHCR primary", wf, "ghcr.io")
	mustContainAny(t, "release Docker Hub mirror", wf, "docker.io", "DOCKERHUB", "docker-hub", "Docker Hub")
	// Keyless (OIDC) signing needs an id-token.
	mustContainAll(t, "release keyless OIDC permission", wf, "id-token")
	// Reproducible build inputs.
	mustContainAny(t, "release reproducibility", wf, "SOURCE_DATE_EPOCH", "rewrite-timestamp", "reproducib")
	// The <20 MB size budget is enforced in the pipeline.
	mustContainAny(t, "release image size gate", wf, "20971520", "20000000", "20 MB", "20MB", "MAX_IMAGE")
}

// TestDockerignoreKeepsContextSmall encodes that the build context excludes the
// heavy, non-deterministic directories so the build stays small and
// reproducible.
func TestDockerignoreKeepsContextSmall(t *testing.T) {
	di := readArtifact(t, filepath.Join("..", "..", ".dockerignore"))
	mustContainAll(t, ".dockerignore", di, "node_modules", ".git", "bin")
}
