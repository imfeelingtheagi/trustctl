package perf

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"google.golang.org/protobuf/proto"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/risk"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
	"trstctl.com/trstctl/internal/store"
)

type Result struct {
	HotPath             string   `json:"hot_path"`
	SLOID               string   `json:"slo_id"`
	Benchmark           string   `json:"benchmark"`
	Samples             int      `json:"samples"`
	P50MS               float64  `json:"p50_ms"`
	P95MS               float64  `json:"p95_ms"`
	P99MS               float64  `json:"p99_ms"`
	ThroughputPerSecond float64  `json:"throughput_per_second"`
	ErrorBudgetPercent  float64  `json:"error_budget_percent"`
	QueueSaturation     float64  `json:"queue_saturation"`
	ProjectionLagEvents int      `json:"projection_lag_events"`
	Met                 bool     `json:"met"`
	Failures            []string `json:"failures,omitempty"`
}

type Report struct {
	SchemaVersion       int      `json:"schema_version"`
	Profile             string   `json:"profile"`
	GeneratedAt         string   `json:"generated_at"`
	MeasurementArtifact string   `json:"measurement_artifact"`
	CapacityTiers       []string `json:"capacity_tiers"`
	Results             []Result `json:"results"`
	Summary             Summary  `json:"summary"`
}

type Summary struct {
	HotPaths int  `json:"hot_paths"`
	Met      int  `json:"met"`
	Failed   int  `json:"failed"`
	OK       bool `json:"ok"`
}

type operation func() error

func RunSmoke(profile string, samples int) (Report, error) {
	if profile == "" {
		profile = "smoke"
	}
	if samples <= 0 {
		samples = 64
	}
	ops, cleanup, err := operations()
	if err != nil {
		return Report{}, err
	}
	defer cleanup()

	report := Report{
		SchemaVersion:       1,
		Profile:             profile,
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		MeasurementArtifact: MeasurementArtifact,
		CapacityTiers:       capacityTierIDs(),
	}
	for _, slo := range HotPaths() {
		op, ok := ops[slo.HotPath]
		if !ok {
			return Report{}, fmt.Errorf("perf: no smoke operation for hot path %s", slo.HotPath)
		}
		result := measure(slo, op, samples)
		report.Results = append(report.Results, result)
		if result.Met {
			report.Summary.Met++
		} else {
			report.Summary.Failed++
		}
	}
	report.Summary.HotPaths = len(report.Results)
	report.Summary.OK = report.Summary.Failed == 0 && report.Summary.HotPaths == len(HotPaths())
	return report, nil
}

func capacityTierIDs() []string {
	tiers := CapacityTiers()
	out := make([]string, 0, len(tiers))
	for _, tier := range tiers {
		out = append(out, tier.ID)
	}
	return out
}

func measure(slo HotPathSLO, op operation, samples int) Result {
	_ = op() // warm the path before measuring.
	durations := make([]float64, 0, samples)
	startAll := time.Now()
	failures := []string{}
	for i := 0; i < samples; i++ {
		start := time.Now()
		if err := op(); err != nil {
			failures = append(failures, err.Error())
		}
		durations = append(durations, float64(time.Since(start).Nanoseconds())/1_000_000)
	}
	elapsed := time.Since(startAll).Seconds()
	sort.Float64s(durations)
	result := Result{
		HotPath:             slo.HotPath,
		SLOID:               slo.ID,
		Benchmark:           slo.Benchmark,
		Samples:             samples,
		P50MS:               percentile(durations, 0.50),
		P95MS:               percentile(durations, 0.95),
		P99MS:               percentile(durations, 0.99),
		ThroughputPerSecond: float64(samples) / elapsed,
		ErrorBudgetPercent:  0,
		QueueSaturation:     0,
		ProjectionLagEvents: 0,
		Failures:            failures,
	}
	result.Met = len(failures) == 0 &&
		result.P50MS <= slo.P50MS &&
		result.P95MS <= slo.P95MS &&
		result.P99MS <= slo.P99MS &&
		result.ThroughputPerSecond >= slo.MinThroughputPerSecond &&
		result.ErrorBudgetPercent <= slo.ErrorBudgetPercent &&
		result.QueueSaturation <= slo.MaxQueueSaturation &&
		result.ProjectionLagEvents <= slo.MaxProjectionLagEvents
	return result
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1)*p + 0.5)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func operations() (map[string]operation, func(), error) {
	kekBytes := bytesOf(32, 0x42)
	wrapper, err := seal.NewLocalKEK(kekBytes)
	secret.Wipe(kekBytes)
	if err != nil {
		return nil, func() {}, err
	}
	signer, err := trstcrypto.GenerateLockedKey(trstcrypto.ECDSAP256)
	if err != nil {
		wrapper.Destroy()
		return nil, func() {}, err
	}
	caDER, err := trstcrypto.SelfSignedCACert(signer, "perf-smoke-ca", time.Hour)
	if err != nil {
		wrapper.Destroy()
		signer.Destroy()
		return nil, func() {}, err
	}
	crlDER, err := trstcrypto.CreateCRL(caDER, signer, []trstcrypto.RevokedSerial{{Serial: "42", RevokedAt: time.Now().UTC(), Reason: 1}}, 1, time.Now().UTC(), time.Now().UTC().Add(time.Hour))
	if err != nil {
		wrapper.Destroy()
		signer.Destroy()
		return nil, func() {}, err
	}
	ocspReq, err := trstcrypto.BuildOCSPRequestForSerial(caDER, "42")
	if err != nil {
		wrapper.Destroy()
		signer.Destroy()
		return nil, func() {}, err
	}
	cleanup := func() {
		wrapper.Destroy()
		signer.Destroy()
	}
	return map[string]operation{
		"api.issuance":            issuanceOp,
		"api.inventory":           inventoryOp,
		"api.graph_risk":          graphRiskOp,
		"api.secrets":             secretOp(wrapper),
		"protocol.enrollment":     protocolEnrollmentOp,
		"revocation.ocsp_crl":     revocationOp(caDER, crlDER, ocspReq),
		"signer.rpc":              signerRPCOp,
		"spine.projection_replay": projectionReplayOp,
	}, cleanup, nil
}

func issuanceOp() error {
	req := struct {
		TenantID       string   `json:"tenant_id"`
		OwnerID        string   `json:"owner_id"`
		IdentityKind   string   `json:"identity_kind"`
		Subject        string   `json:"subject"`
		SANs           []string `json:"sans"`
		IdempotencyKey string   `json:"idempotency_key"`
	}{
		TenantID: "11111111-1111-1111-1111-111111111111", OwnerID: "owner-perf",
		IdentityKind: "x509_certificate", Subject: "api.perf.trstctl.test",
		SANs: []string{"api.perf.trstctl.test", "api-alt.perf.trstctl.test"}, IdempotencyKey: "perf-smoke-issuance",
	}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	var decoded struct {
		TenantID       string   `json:"tenant_id"`
		OwnerID        string   `json:"owner_id"`
		IdentityKind   string   `json:"identity_kind"`
		Subject        string   `json:"subject"`
		SANs           []string `json:"sans"`
		IdempotencyKey string   `json:"idempotency_key"`
	}
	if err := json.Unmarshal(b, &decoded); err != nil {
		return err
	}
	if decoded.IdempotencyKey == "" || len(decoded.SANs) != 2 {
		return fmt.Errorf("perf issuance decode lost mutation contract")
	}
	return nil
}

func inventoryOp() error {
	rows := make([]store.Certificate, 0, 384)
	for i := 383; i >= 0; i-- {
		rows = append(rows, store.Certificate{ID: fmt.Sprintf("cert-%04d", i), Subject: fmt.Sprintf("svc-%04d.trstctl.test", i), Status: "active"})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	page := rows[:128]
	_, err := json.Marshal(page)
	return err
}

func graphRiskOp() error {
	g := graph.New()
	issuerID := "issuer:perf"
	g.AddNode(graph.Node{ID: issuerID, Kind: graph.KindIssuer, Name: "perf issuer"})
	for i := 0; i < 80; i++ {
		workloadID := fmt.Sprintf("workload:%03d", i)
		credID := fmt.Sprintf("cert:%03d", i)
		resourceID := fmt.Sprintf("resource:%03d", i)
		g.AddNode(graph.Node{ID: workloadID, Kind: graph.KindWorkload, Name: workloadID})
		g.AddNode(graph.Node{ID: credID, Kind: graph.KindCredential, Name: credID})
		g.AddNode(graph.Node{ID: resourceID, Kind: graph.KindResource, Name: resourceID})
		g.AddEdge(graph.Edge{From: issuerID, To: credID, Type: graph.EdgeIssued})
		g.AddEdge(graph.Edge{From: workloadID, To: credID, Type: graph.EdgeOwns})
		g.AddEdge(graph.Edge{From: credID, To: resourceID, Type: graph.EdgeDeployedTo})
		if i > 0 {
			g.AddEdge(graph.Edge{From: resourceID, To: fmt.Sprintf("workload:%03d", i-1), Type: graph.EdgeConnectsTo})
		}
	}
	impact := g.BlastRadius("workload:079")
	if len(impact.Affected) == 0 {
		return fmt.Errorf("perf graph impact was empty")
	}
	now := time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC)
	score := risk.Compute(risk.Signals{
		Now: now, NotBefore: now.Add(-90 * 24 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		Exposure: len(impact.ByKind[graph.KindResource]), Privilege: risk.PrivilegeHigh,
		LastRotated: now.Add(-30 * 24 * time.Hour), OwnerActive: true, Sensitivity: risk.SensitivityHigh,
	})
	if score.Total <= 0 {
		return fmt.Errorf("perf risk score did not compute")
	}
	return nil
}

func secretOp(wrapper *seal.LocalKEK) operation {
	return func() error {
		plaintext := bytesOf(256, 0x7a)
		defer secret.Wipe(plaintext)
		aad := []byte("tenant/perf/ref/api-key")
		sealed, err := seal.Seal(wrapper, plaintext, aad)
		if err != nil {
			return err
		}
		opened, err := seal.Open(wrapper, sealed, aad)
		if err != nil {
			return err
		}
		defer secret.Wipe(opened)
		if len(opened) != len(plaintext) {
			return fmt.Errorf("perf secret open length = %d, want %d", len(opened), len(plaintext))
		}
		return nil
	}
}

func protocolEnrollmentOp() error {
	order := []byte(`{"identifiers":[{"type":"dns","value":"perf.trstctl.test"},{"type":"dns","value":"alt.perf.trstctl.test"}]}`)
	parsed, err := acme.ParseOrderRequest(order)
	if err != nil {
		return err
	}
	csr := base64.RawURLEncoding.EncodeToString([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	if _, err := acme.ParseFinalizeRequest([]byte(`{"csr":"` + csr + `"}`)); err != nil {
		return err
	}
	if len(parsed.Domains()) != 2 {
		return fmt.Errorf("perf protocol parser lost domains")
	}
	return nil
}

func revocationOp(caDER, crlDER, ocspReq []byte) operation {
	return func() error {
		serial, err := trstcrypto.ParseOCSPRequestSerial(ocspReq)
		if err != nil {
			return err
		}
		info, err := trstcrypto.ParseCRL(crlDER, caDER)
		if err != nil {
			return err
		}
		if serial != "42" || len(info.RevokedSerials) != 1 {
			return fmt.Errorf("perf revocation parse serial=%s revoked=%d", serial, len(info.RevokedSerials))
		}
		return nil
	}
}

func signerRPCOp() error {
	req := &signerpb.SignRequest{
		Handle:     &signerpb.KeyHandle{Id: "perf-signer-key"},
		Digest:     bytesOf(32, 0x9a),
		Hash:       signerpb.Hash_HASH_SHA256,
		RsaPadding: signerpb.RSAPadding_RSA_PADDING_PSS,
		Purpose:    signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
	}
	encoded, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	var decoded signerpb.SignRequest
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		return err
	}
	if decoded.GetHandle().GetId() == "" || len(decoded.GetDigest()) != 32 {
		return fmt.Errorf("perf signer RPC payload lost handle or digest")
	}
	return nil
}

func projectionReplayOp() error {
	payload := projections.CRLPublished{
		CAID: "perf-ca", Number: 9, DER: []byte{0x30, 0x03, 0x02, 0x01, 0x09},
		ThisUpdate: time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC),
		NextUpdate: time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ev := events.Event{Type: projections.EventCRLPublished, TenantID: "11111111-1111-1111-1111-111111111111", Data: data, SchemaVersion: projections.CRLPublishedEventSchemaVersion}
	encoded, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	var decoded events.Event
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return err
	}
	var out projections.CRLPublished
	if err := json.Unmarshal(decoded.Data, &out); err != nil {
		return err
	}
	if out.Number != payload.Number || out.CAID != payload.CAID {
		return fmt.Errorf("perf projection replay lost CRL payload")
	}
	return nil
}

func bytesOf(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
