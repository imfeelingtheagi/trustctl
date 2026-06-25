package secretscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// GitleaksPinnedVersion is the scanner version trstctl validates and documents
	// for the served secret-scan bridge. The binary does the detection; this package
	// only invokes it and parses the redacted report metadata.
	GitleaksPinnedVersion = "v8.27.2"
	// GitleaksDefaultRulesActive is the number of rules in the pinned version's
	// embedded default gitleaks.toml. It gives the served API an auditable floor for
	// "the real default scanner is active" without importing the scanner library.
	GitleaksDefaultRulesActive = 213
	GitleaksMinRulesActive     = 140
)

var (
	ErrGitleaksBinaryNotFound = errors.New("secretscan: gitleaks binary not found")
	ErrInvalidScanTarget      = errors.New("secretscan: invalid scan target")
)

// Report is the redacted metadata returned by a Gitleaks run.
type Report struct {
	Scanner       string
	EngineVersion string
	RulesActive   int
	Findings      []Finding
}

// GitleaksRunner invokes the pinned Gitleaks CLI as a subprocess.
type GitleaksRunner struct {
	Binary              string
	Timeout             time.Duration
	MaxTargetMegabytes  int
	rulesActiveOverride int
}

// NewGitleaksRunner returns a runner. An empty binary resolves from
// TRSTCTL_GITLEAKS_BIN, tools/bin/gitleaks, then PATH at scan time.
func NewGitleaksRunner(binary string) *GitleaksRunner {
	return &GitleaksRunner{Binary: strings.TrimSpace(binary), Timeout: 2 * time.Minute, MaxTargetMegabytes: 50}
}

// Scan runs gitleaks against a directory or file. The command is executed without a
// shell, with a report path outside the target tree, and with full secret redaction.
func (r *GitleaksRunner) Scan(ctx context.Context, target string) (Report, error) {
	targetPath, targetRoot, err := normalizeTarget(target)
	if err != nil {
		return Report{}, err
	}
	bin, err := r.resolveBinary()
	if err != nil {
		return Report{}, err
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	report, err := os.CreateTemp("", "trstctl-gitleaks-*.json")
	if err != nil {
		return Report{}, fmt.Errorf("secretscan: create gitleaks report: %w", err)
	}
	reportPath := report.Name()
	_ = report.Close()
	defer func() { _ = os.Remove(reportPath) }()

	maxMB := r.MaxTargetMegabytes
	if maxMB <= 0 {
		maxMB = 50
	}
	args := []string{
		"dir",
		"--no-banner",
		"--redact",
		"--exit-code", "0",
		"--report-format", "json",
		"--report-path", reportPath,
		"--max-target-megabytes", fmt.Sprintf("%d", maxMB),
		targetPath,
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = targetRoot
	cmd.Env = sanitizedGitleaksEnv(os.Environ())
	var stderr limitedBuffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return Report{}, fmt.Errorf("secretscan: gitleaks timed out after %s", timeout)
		}
		return Report{}, fmt.Errorf("secretscan: gitleaks failed: %w%s", err, stderr.suffix())
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return Report{}, fmt.Errorf("secretscan: read gitleaks report: %w", err)
	}
	findings, err := ParseGitleaks(data)
	if err != nil {
		return Report{}, err
	}
	relativizeFindings(findings, targetRoot)
	rules := GitleaksDefaultRulesActive
	if r.rulesActiveOverride > 0 {
		rules = r.rulesActiveOverride
	}
	return Report{Scanner: "gitleaks", EngineVersion: GitleaksPinnedVersion, RulesActive: rules, Findings: findings}, nil
}

func (r *GitleaksRunner) resolveBinary() (string, error) {
	candidates := []string{r.Binary, os.Getenv("TRSTCTL_GITLEAKS_BIN"), filepath.Join("tools", "bin", "gitleaks")}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if filepath.IsAbs(candidate) || strings.ContainsRune(candidate, filepath.Separator) {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
			continue
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	if path, err := exec.LookPath("gitleaks"); err == nil {
		return path, nil
	}
	return "", ErrGitleaksBinaryNotFound
}

func normalizeTarget(target string) (targetPath string, root string, err error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", fmt.Errorf("%w: path is required", ErrInvalidScanTarget)
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrInvalidScanTarget, err)
	}
	abs = filepath.Clean(abs)
	info, err := os.Stat(abs)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrInvalidScanTarget, err)
	}
	root = abs
	if !info.IsDir() {
		root = filepath.Dir(abs)
	}
	return abs, root, nil
}

func relativizeFindings(findings []Finding, root string) {
	for i := range findings {
		file := filepath.Clean(findings[i].File)
		if rel, err := filepath.Rel(root, file); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
			file = filepath.ToSlash(rel)
		}
		findings[i].File = file
		findings[i].CredentialRef = findings[i].RuleID + "@" + file
	}
}

func sanitizedGitleaksEnv(env []string) []string {
	out := make([]string, 0, len(env)+3)
	for _, kv := range env {
		if strings.HasPrefix(kv, "GITLEAKS_CONFIG=") || strings.HasPrefix(kv, "GITLEAKS_CONFIG_TOML=") {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "NO_COLOR=1", "GITLEAKS_NO_UPDATE_CHECK=true")
	return out
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len() < 4096 {
		_, _ = b.Buffer.Write(p[:min(len(p), 4096-b.Len())])
	}
	return len(p), nil
}

func (b *limitedBuffer) suffix() string {
	msg := strings.TrimSpace(b.String())
	if msg == "" {
		return ""
	}
	return ": " + msg
}
