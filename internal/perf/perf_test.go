package perf

import "testing"

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
