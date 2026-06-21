package docs

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/perf"
)

func TestPerformanceSLOMatrixHasExecutableEvidence(t *testing.T) {
	doc := read(t, "performance.md")
	artifact := readPerfArtifact(t)
	results := map[string]perf.Result{}
	for _, result := range artifact.Results {
		results[result.HotPath] = result
		if !result.Met {
			t.Errorf("perf artifact marks %s as not met: %+v", result.HotPath, result)
		}
	}
	if !artifact.Summary.OK {
		t.Fatalf("perf artifact summary is not ok: %+v", artifact.Summary)
	}
	for _, slo := range perf.HotPaths() {
		for _, want := range []string{slo.ID, slo.HotPath, slo.Benchmark, slo.Owner, slo.CapacityRef} {
			if !strings.Contains(doc, want) {
				t.Errorf("performance.md missing %q for %s", want, slo.ID)
			}
		}
		result, ok := results[slo.HotPath]
		if !ok {
			t.Errorf("perf artifact missing hot path %s", slo.HotPath)
			continue
		}
		if result.SLOID != slo.ID {
			t.Errorf("%s artifact SLO id = %s, want %s", slo.HotPath, result.SLOID, slo.ID)
		}
		if result.Benchmark != slo.Benchmark {
			t.Errorf("%s artifact benchmark = %s, want %s", slo.HotPath, result.Benchmark, slo.Benchmark)
		}
		if result.P50MS > slo.P50MS || result.P95MS > slo.P95MS || result.P99MS > slo.P99MS {
			t.Errorf("%s latency p50/p95/p99 = %.3f/%.3f/%.3f exceeds %.3f/%.3f/%.3f",
				slo.HotPath, result.P50MS, result.P95MS, result.P99MS, slo.P50MS, slo.P95MS, slo.P99MS)
		}
		if result.ThroughputPerSecond < slo.MinThroughputPerSecond {
			t.Errorf("%s throughput = %.2f, want >= %.2f", slo.HotPath, result.ThroughputPerSecond, slo.MinThroughputPerSecond)
		}
	}
}

func TestPerformanceCapacityModelIsTiedToPerfArtifact(t *testing.T) {
	doc := read(t, "performance-capacity.md")
	if !strings.Contains(doc, perf.MeasurementArtifact) {
		t.Fatalf("performance-capacity.md must cite %s", perf.MeasurementArtifact)
	}
	artifact := readPerfArtifact(t)
	artifactTiers := map[string]bool{}
	for _, tier := range artifact.CapacityTiers {
		artifactTiers[tier] = true
	}
	for _, tier := range perf.CapacityTiers() {
		for _, want := range []string{tier.ID, tier.Name, formatInt(tier.ManagedCredentials), fmt.Sprintf("$%.4f", tier.EstimatedCostPerCredential)} {
			if !strings.Contains(doc, want) {
				t.Errorf("performance-capacity.md missing %q for %s", want, tier.ID)
			}
		}
		if !artifactTiers[tier.ID] {
			t.Errorf("perf artifact missing capacity tier %s", tier.ID)
		}
	}
}

func TestPerfSmokeScriptAndCIArtifactGateAreCommitted(t *testing.T) {
	script, err := os.ReadFile("../scripts/perf/run-local.sh")
	if err != nil {
		t.Fatalf("read perf script: %v", err)
	}
	for _, want := range []string{"--profile", "--out", "./scripts/perf/cmd/perfgate"} {
		if !strings.Contains(string(script), want) {
			t.Errorf("scripts/perf/run-local.sh missing %q", want)
		}
	}
	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{"Perf smoke SLO gate", "scripts/perf/run-local.sh --profile smoke", "perf-smoke-slo"} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml missing perf gate evidence %q", want)
		}
	}
}

func readPerfArtifact(t *testing.T) perf.Report {
	t.Helper()
	var report perf.Report
	data := read(t, "../"+perf.MeasurementArtifact)
	if err := json.Unmarshal([]byte(data), &report); err != nil {
		t.Fatalf("parse %s: %v", perf.MeasurementArtifact, err)
	}
	return report
}

func formatInt(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	head := len(s) % 3
	if head == 0 {
		head = 3
	}
	out = append(out, s[:head]...)
	for i := head; i < len(s); i += 3 {
		out = append(out, ',')
		out = append(out, s[i:i+3]...)
	}
	return string(out)
}
