package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/perf"
)

func TestPerfGateExitsNonzeroForInjectedRuntimeBreaches(t *testing.T) {
	obsPath := filepath.Join(t.TempDir(), "breached-observations.json")
	if err := os.WriteFile(obsPath, []byte(`{
  "api.issuance": {"queue_saturation": 0.81},
  "api.inventory": {"error_budget_percent": 0.11},
  "spine.projection_replay": {"projection_lag_events": 51}
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "run", ".", "--samples", "4", "--pretty=false", "--observations", obsPath)
	cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(t.TempDir(), "gocache"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("perfgate passed with injected runtime breaches:\n%s", out)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("perfgate error = %T %v, want exit error; output:\n%s", err, err, out)
	}
	if exitErr.ExitCode() == 0 {
		t.Fatalf("perfgate exit code = 0 with injected runtime breaches:\n%s", out)
	}
	for _, want := range [][]byte{
		[]byte("perf gate failed"),
		[]byte("queue saturation"),
		[]byte("error budget"),
		[]byte("projection lag"),
	} {
		if !bytes.Contains(out, want) {
			t.Fatalf("perfgate output missing %q:\n%s", want, out)
		}
	}
}

func TestPerfGateRunsLiveProfile(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "live.json")
	cmd := exec.Command("go", "run", ".", "--profile", "live", "--samples", "16", "--pretty=false", "--out", outPath)
	cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(t.TempDir(), "gocache"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("perfgate live failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read live output: %v", err)
	}
	var report perf.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode live output: %v\n%s", err, data)
	}
	if report.Profile != "live" || !report.ServedStack || report.MeasurementArtifact != perf.LiveMeasurementArtifact {
		t.Fatalf("bad live profile metadata: %+v", report)
	}
	if got, want := len(report.Results), len(perf.HotPaths())*2; got != want {
		t.Fatalf("live result count = %d, want %d", got, want)
	}
}
