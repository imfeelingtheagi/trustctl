package perf

// HotPathSLO is one row in the committed performance contract. It is intentionally
// code-owned so docs, the local perf gate, and CI all consume the same denominator.
type HotPathSLO struct {
	ID                     string  `json:"id"`
	HotPath                string  `json:"hot_path"`
	Surface                string  `json:"surface"`
	Owner                  string  `json:"owner"`
	Benchmark              string  `json:"benchmark"`
	P50MS                  float64 `json:"p50_ms"`
	P95MS                  float64 `json:"p95_ms"`
	P99MS                  float64 `json:"p99_ms"`
	MinThroughputPerSecond float64 `json:"min_throughput_per_second"`
	ErrorBudgetPercent     float64 `json:"error_budget_percent"`
	MaxQueueSaturation     float64 `json:"max_queue_saturation"`
	MaxProjectionLagEvents int     `json:"max_projection_lag_events"`
	CapacityRef            string  `json:"capacity_ref"`
}

// CapacityTier is one buyer-facing right-sizing row. Numbers are deliberately
// conservative and tied to the local smoke artifact rather than a vendor-specific
// cloud SKU; operators can replace unit costs without changing the product SLOs.
type CapacityTier struct {
	ID                         string  `json:"id"`
	Name                       string  `json:"name"`
	Tenants                    int     `json:"tenants"`
	ManagedCredentials         int     `json:"managed_credentials"`
	EventsPerDay               int     `json:"events_per_day"`
	PostgresGiB30Day           float64 `json:"postgres_gib_30_day"`
	JetStreamGiB30Day          float64 `json:"jetstream_gib_30_day"`
	ControlPlaneCPU            string  `json:"control_plane_cpu"`
	ControlPlaneMemoryGiB      int     `json:"control_plane_memory_gib"`
	SignerCPU                  string  `json:"signer_cpu"`
	SignerMemoryGiB            int     `json:"signer_memory_gib"`
	EstimatedMonthlyCostUSD    int     `json:"estimated_monthly_cost_usd"`
	EstimatedCostPerCredential float64 `json:"estimated_cost_per_credential_usd"`
	Notes                      string  `json:"notes"`
}

const MeasurementArtifact = "scripts/perf/artifacts/smoke-baseline.json"

var hotPathSLOs = []HotPathSLO{
	{
		ID: "PERF-SLO-001", HotPath: "api.issuance", Surface: "POST /api/v1/identities + served signer issuance",
		Owner: "CORRECT/API", Benchmark: "BenchmarkIssuance", P50MS: 50, P95MS: 150, P99MS: 300,
		MinThroughputPerSecond: 25, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 25,
		CapacityRef: "CAP-SMALL",
	},
	{
		ID: "PERF-SLO-002", HotPath: "api.inventory", Surface: "GET /api/v1/certificates + inventory pagination",
		Owner: "API/STORE", Benchmark: "BenchmarkInventory", P50MS: 25, P95MS: 75, P99MS: 150,
		MinThroughputPerSecond: 100, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 25,
		CapacityRef: "CAP-SMALL",
	},
	{
		ID: "PERF-SLO-003", HotPath: "api.graph_risk", Surface: "GET /api/v1/graph/* + /api/v1/risk/*",
		Owner: "GRAPH/RISK", Benchmark: "BenchmarkGraphRiskQuery", P50MS: 75, P95MS: 250, P99MS: 500,
		MinThroughputPerSecond: 20, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 25,
		CapacityRef: "CAP-MEDIUM",
	},
	{
		ID: "PERF-SLO-004", HotPath: "api.secrets", Surface: "GET/PUT /api/v1/secrets/*",
		Owner: "SECRETS/CRYPTO", Benchmark: "BenchmarkSecrets", P50MS: 50, P95MS: 150, P99MS: 300,
		MinThroughputPerSecond: 50, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 25,
		CapacityRef: "CAP-SMALL",
	},
	{
		ID: "PERF-SLO-005", HotPath: "protocol.enrollment", Surface: "ACME/EST/SCEP/CMP/SPIFFE/SSH enrollment parsers",
		Owner: "PROTOCOLS", Benchmark: "BenchmarkProtocolEnrollment", P50MS: 50, P95MS: 150, P99MS: 300,
		MinThroughputPerSecond: 40, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 25,
		CapacityRef: "CAP-MEDIUM",
	},
	{
		ID: "PERF-SLO-006", HotPath: "revocation.ocsp_crl", Surface: "POST /ocsp/{tenant} + GET /crl/{tenant}",
		Owner: "REVOCATION", Benchmark: "BenchmarkOCSPCRL", P50MS: 25, P95MS: 75, P99MS: 150,
		MinThroughputPerSecond: 100, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 25,
		CapacityRef: "CAP-SMALL",
	},
	{
		ID: "PERF-SLO-007", HotPath: "signer.rpc", Surface: "trustctl-signer gRPC Sign/GenerateKey request path",
		Owner: "SIGNING", Benchmark: "BenchmarkSignerRPC", P50MS: 25, P95MS: 75, P99MS: 150,
		MinThroughputPerSecond: 100, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.70, MaxProjectionLagEvents: 0,
		CapacityRef: "CAP-SMALL",
	},
	{
		ID: "PERF-SLO-008", HotPath: "spine.projection_replay", Surface: "event replay + projection decode/apply loop",
		Owner: "SPINE/PROJECTIONS", Benchmark: "BenchmarkProjectionReplay", P50MS: 100, P95MS: 300, P99MS: 750,
		MinThroughputPerSecond: 500, ErrorBudgetPercent: 0.10, MaxQueueSaturation: 0.80, MaxProjectionLagEvents: 50,
		CapacityRef: "CAP-LARGE",
	},
}

var capacityTiers = []CapacityTier{
	{
		ID: "CAP-SMALL", Name: "single-node regulated evaluation", Tenants: 5, ManagedCredentials: 25000, EventsPerDay: 250000,
		PostgresGiB30Day: 20, JetStreamGiB30Day: 35, ControlPlaneCPU: "2 vCPU", ControlPlaneMemoryGiB: 4,
		SignerCPU: "1 vCPU", SignerMemoryGiB: 1, EstimatedMonthlyCostUSD: 450, EstimatedCostPerCredential: 0.018,
		Notes: "Bundled PostgreSQL/NATS for evaluation; move to external datastores before production multi-tenant use.",
	},
	{
		ID: "CAP-MEDIUM", Name: "external datastore production", Tenants: 50, ManagedCredentials: 250000, EventsPerDay: 2500000,
		PostgresGiB30Day: 180, JetStreamGiB30Day: 320, ControlPlaneCPU: "6 vCPU", ControlPlaneMemoryGiB: 12,
		SignerCPU: "2 vCPU", SignerMemoryGiB: 2, EstimatedMonthlyCostUSD: 4200, EstimatedCostPerCredential: 0.0168,
		Notes: "External PostgreSQL and JetStream, two control-plane replicas, isolated signer process.",
	},
	{
		ID: "CAP-LARGE", Name: "multi-replica enterprise", Tenants: 250, ManagedCredentials: 1000000, EventsPerDay: 10000000,
		PostgresGiB30Day: 700, JetStreamGiB30Day: 1200, ControlPlaneCPU: "16 vCPU", ControlPlaneMemoryGiB: 32,
		SignerCPU: "6 vCPU", SignerMemoryGiB: 8, EstimatedMonthlyCostUSD: 14500, EstimatedCostPerCredential: 0.0145,
		Notes: "External HA PostgreSQL, external JetStream cluster, isolated signer capacity scaled separately.",
	},
}

func HotPaths() []HotPathSLO {
	out := make([]HotPathSLO, len(hotPathSLOs))
	copy(out, hotPathSLOs)
	return out
}

func CapacityTiers() []CapacityTier {
	out := make([]CapacityTier, len(capacityTiers))
	copy(out, capacityTiers)
	return out
}
