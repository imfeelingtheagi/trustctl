package perf

import (
	"strings"
	"testing"
)

func BenchmarkIssuance(b *testing.B) {
	benchmarkOperation(b, "api.issuance")
}

func BenchmarkInventory(b *testing.B) {
	benchmarkOperation(b, "api.inventory")
}

func BenchmarkGraphRiskQuery(b *testing.B) {
	benchmarkOperation(b, "api.graph_risk")
}

func BenchmarkSecrets(b *testing.B) {
	benchmarkOperation(b, "api.secrets")
}

func BenchmarkProtocolEnrollment(b *testing.B) {
	benchmarkOperation(b, "protocol.enrollment")
}

func BenchmarkOCSPCRL(b *testing.B) {
	benchmarkOperation(b, "revocation.ocsp_crl")
}

func BenchmarkSignerRPC(b *testing.B) {
	benchmarkOperation(b, "signer.rpc")
}

func BenchmarkProjectionReplay(b *testing.B) {
	benchmarkOperation(b, "spine.projection_replay")
}

func TestPerfSmokeGateCoversEveryHotPath(t *testing.T) {
	report, err := RunSmoke("smoke", 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != len(HotPaths()) {
		t.Fatalf("smoke results = %d, want %d", len(report.Results), len(HotPaths()))
	}
	for _, result := range report.Results {
		if !result.Met {
			t.Fatalf("%s failed smoke SLO: %+v", result.HotPath, result)
		}
	}
}

func TestPerfSmokeGateFailsInjectedRuntimeBreaches(t *testing.T) {
	report, err := RunSmokeWithObservations("smoke", 8, map[string]Observation{
		"api.issuance":            {QueueSaturation: 0.81},
		"api.inventory":           {ErrorBudgetPercent: 0.11},
		"spine.projection_replay": {ProjectionLagEvents: 51},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.OK {
		t.Fatalf("smoke report unexpectedly passed with injected queue/error/lag breaches: %+v", report.Summary)
	}
	want := map[string]string{
		"api.issuance":            "queue saturation",
		"api.inventory":           "error budget",
		"spine.projection_replay": "projection lag",
	}
	for _, result := range report.Results {
		substr, ok := want[result.HotPath]
		if !ok {
			continue
		}
		if result.Met {
			t.Fatalf("%s met SLO despite injected %q breach: %+v", result.HotPath, substr, result)
		}
		if !containsFailure(result.Failures, substr) {
			t.Fatalf("%s failures = %v, want %q", result.HotPath, result.Failures, substr)
		}
		delete(want, result.HotPath)
	}
	if len(want) != 0 {
		t.Fatalf("missing injected breach results for %v", want)
	}
}

func TestPerfSmokeGateRejectsUnknownObservationHotPath(t *testing.T) {
	_, err := RunSmokeWithObservations("smoke", 1, map[string]Observation{
		"not.a.hot.path": {QueueSaturation: 1},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown hot path") {
		t.Fatalf("RunSmokeWithObservations error = %v, want unknown hot path", err)
	}
}

func TestPerfLiveLoadHarnessCoversEveryHotPathAndPhase(t *testing.T) {
	report, err := RunLiveLoad("live", 16)
	if err != nil {
		t.Fatal(err)
	}
	if report.Profile != "live" {
		t.Fatalf("profile = %q, want live", report.Profile)
	}
	if report.MeasurementArtifact != LiveMeasurementArtifact {
		t.Fatalf("measurement artifact = %q, want %q", report.MeasurementArtifact, LiveMeasurementArtifact)
	}
	if !report.ServedStack {
		t.Fatal("live report did not mark the served stack as booted")
	}
	if report.StackProfile == "" {
		t.Fatal("live report has no stack profile")
	}
	if len(report.LoadPhases) != 2 {
		t.Fatalf("live phases = %d, want realistic and peak", len(report.LoadPhases))
	}
	if got, want := len(report.Results), len(HotPaths())*len(report.LoadPhases); got != want {
		t.Fatalf("live results = %d, want %d", got, want)
	}

	seen := map[string]bool{}
	for _, result := range report.Results {
		if !result.ServedStack {
			t.Fatalf("%s/%s did not mark served_stack", result.HotPath, result.Phase)
		}
		if result.StackProfile != report.StackProfile {
			t.Fatalf("%s/%s stack profile = %q, want %q", result.HotPath, result.Phase, result.StackProfile, report.StackProfile)
		}
		if result.Phase != "realistic" && result.Phase != "peak" {
			t.Fatalf("%s phase = %q, want realistic or peak", result.HotPath, result.Phase)
		}
		if result.P50MS <= 0 || result.P95MS <= 0 || result.P99MS <= 0 || result.MaxMS <= 0 {
			t.Fatalf("%s/%s missing latency percentiles/max: %+v", result.HotPath, result.Phase, result)
		}
		if result.MaxMS < result.P99MS {
			t.Fatalf("%s/%s max %.4fms < p99 %.4fms", result.HotPath, result.Phase, result.MaxMS, result.P99MS)
		}
		if result.ThroughputPerSecond <= 0 || result.TargetRatePerSecond <= 0 {
			t.Fatalf("%s/%s missing throughput/target rate: %+v", result.HotPath, result.Phase, result)
		}
		if result.Errors != 0 {
			t.Fatalf("%s/%s recorded %d errors: %+v", result.HotPath, result.Phase, result.Errors, result.Failures)
		}
		if result.ResourceMetrics == nil || result.ResourceMetrics.Goroutines <= 0 || result.ResourceMetrics.CPUCount <= 0 {
			t.Fatalf("%s/%s missing resource metrics: %+v", result.HotPath, result.Phase, result.ResourceMetrics)
		}
		seen[result.HotPath+"/"+result.Phase] = true
	}
	for _, slo := range HotPaths() {
		for _, phase := range []string{"realistic", "peak"} {
			key := slo.HotPath + "/" + phase
			if !seen[key] {
				t.Fatalf("missing live result for %s", key)
			}
		}
	}
	if report.Summary.Measurements != len(report.Results) || report.Summary.HotPaths != len(HotPaths()) {
		t.Fatalf("bad live summary: %+v", report.Summary)
	}
}

func TestPerfLiveLoadGateFailsInjectedRuntimeBreaches(t *testing.T) {
	report, err := RunLiveLoadWithObservations("live", 16, map[string]Observation{
		"api.issuance": {QueueSaturation: 0.81},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.OK {
		t.Fatalf("live report unexpectedly passed with injected queue breach: %+v", report.Summary)
	}
	found := false
	for _, result := range report.Results {
		if result.HotPath != "api.issuance" {
			continue
		}
		found = true
		if result.Met {
			t.Fatalf("api.issuance/%s met SLO despite injected queue breach: %+v", result.Phase, result)
		}
		if !containsFailure(result.Failures, "queue saturation") {
			t.Fatalf("api.issuance/%s failures = %v, want queue saturation", result.Phase, result.Failures)
		}
	}
	if !found {
		t.Fatal("missing api.issuance live result")
	}
}

func containsFailure(failures []string, substr string) bool {
	for _, failure := range failures {
		if strings.Contains(failure, substr) {
			return true
		}
	}
	return false
}

func benchmarkOperation(b *testing.B, hotPath string) {
	ops, cleanup, err := operations()
	if err != nil {
		b.Fatal(err)
	}
	defer cleanup()
	op, ok := ops[hotPath]
	if !ok {
		b.Fatalf("no perf operation for %s", hotPath)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := op(); err != nil {
			b.Fatal(err)
		}
	}
}
