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
