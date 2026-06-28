package perf

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

const liveStackProfile = "eval-loopback-served-hot-paths"

func RunLiveLoad(profile string, samples int) (Report, error) {
	return RunLiveLoadWithObservations(profile, samples, nil)
}

func RunLiveLoadWithObservations(profile string, samples int, observations map[string]Observation) (Report, error) {
	if profile == "" {
		profile = "live"
	}
	if samples <= 0 {
		samples = 32
	}
	if err := validateObservations(observations); err != nil {
		return Report{}, err
	}
	ops, transports, cleanup, err := liveServedOperations()
	if err != nil {
		return Report{}, err
	}
	defer cleanup()

	phases := liveLoadPhases(samples)
	report := Report{
		SchemaVersion:       1,
		Profile:             profile,
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		MeasurementArtifact: LiveMeasurementArtifact,
		CapacityTiers:       capacityTierIDs(),
		ServedStack:         true,
		StackProfile:        liveStackProfile,
		LoadPhases:          phases,
		ResourceMetrics:     captureResourceMetrics(0),
	}
	for _, phase := range phases {
		report.Summary.Phases = append(report.Summary.Phases, phase.Name)
		for _, slo := range HotPaths() {
			op, ok := ops[slo.HotPath]
			if !ok {
				return Report{}, fmt.Errorf("perf: no live operation for hot path %s", slo.HotPath)
			}
			result := measure(slo, op, phase.Samples, observations[slo.HotPath])
			result.Phase = phase.Name
			result.TargetRatePerSecond = slo.MinThroughputPerSecond * phase.RateMultiplier
			result.ServedStack = true
			result.StackProfile = liveStackProfile
			result.Transport = transports[slo.HotPath]
			result.ResourceMetrics = captureResourceMetrics(result.ProjectionLagEvents)
			report.Results = append(report.Results, result)
			if result.Met {
				report.Summary.Met++
			} else {
				report.Summary.Failed++
			}
		}
	}
	report.Summary.HotPaths = len(HotPaths())
	report.Summary.Measurements = len(report.Results)
	report.Summary.OK = report.Summary.Failed == 0 && report.Summary.Measurements == len(HotPaths())*len(phases)
	return report, nil
}

func liveLoadPhases(samples int) []LoadPhase {
	return []LoadPhase{
		{Name: "realistic", Samples: samples, TargetRateMultiplier: 1.25, RateMultiplier: 1.25},
		{Name: "peak", Samples: samples * 2, TargetRateMultiplier: 2.50, RateMultiplier: 2.50},
	}
}

func liveServedOperations() (map[string]operation, map[string]string, func(), error) {
	productOps, productCleanup, err := operations()
	if err != nil {
		return nil, nil, func() {}, err
	}
	signerOp, signerTransport, signerCleanup, err := liveSignerRPCOp()
	if err != nil {
		productCleanup()
		return nil, nil, func() {}, err
	}
	productOps["signer.rpc"] = signerOp

	mux := http.NewServeMux()
	mux.HandleFunc("/perf/live/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		hotPath, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/perf/live/"))
		if err != nil {
			http.Error(w, "bad hot path", http.StatusBadRequest)
			return
		}
		op, ok := productOps[hotPath]
		if !ok {
			http.Error(w, "unknown hot path", http.StatusNotFound)
			return
		}
		if err := op(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	servedOps := make(map[string]operation, len(productOps))
	transports := make(map[string]string, len(productOps))
	for _, slo := range HotPaths() {
		hotPath := slo.HotPath
		transports[hotPath] = "http-handler"
		if hotPath == "signer.rpc" {
			transports[hotPath] = "http-handler+" + signerTransport
		}
		endpoint := "/perf/live/" + url.PathEscape(hotPath)
		servedOps[hotPath] = func() error {
			req, err := http.NewRequest(http.MethodPost, endpoint, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Idempotency-Key", "perf-live-"+hotPath)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				return fmt.Errorf("perf live %s returned %d: %s", hotPath, rec.Code, strings.TrimSpace(rec.Body.String()))
			}
			return nil
		}
	}

	cleanup := func() {
		signerCleanup()
		productCleanup()
	}
	return servedOps, transports, cleanup, nil
}

func liveSignerRPCOp() (operation, string, func(), error) {
	lis := bufconn.Listen(1 << 20)
	svc := signing.NewServer()
	grpcServer := grpc.NewServer()
	signerpb.RegisterSignerServiceServer(grpcServer, svc)
	served := make(chan error, 1)
	go func() {
		served <- grpcServer.Serve(lis)
	}()
	conn, err := grpc.NewClient("passthrough:///perf-live-signer",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
	)
	if err != nil {
		grpcServer.Stop()
		svc.Shutdown()
		_ = lis.Close()
		return nil, "", func() {}, fmt.Errorf("perf live signer: create bufconn client: %w", err)
	}
	client := signerpb.NewSignerServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gen, err := client.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm:       signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		RequestedId:     "perf-live-signer",
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_GENERIC},
	})
	if err != nil {
		_ = conn.Close()
		grpcServer.Stop()
		svc.Shutdown()
		_ = lis.Close()
		return nil, "", func() {}, fmt.Errorf("perf live signer: generate key over gRPC: %w", err)
	}
	digest, err := trstcrypto.Digest(trstcrypto.SHA256, []byte("trstctl perf live signer rpc"))
	if err != nil {
		_ = conn.Close()
		grpcServer.Stop()
		svc.Shutdown()
		_ = lis.Close()
		return nil, "", func() {}, fmt.Errorf("perf live signer: digest: %w", err)
	}
	op := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := client.Sign(ctx, &signerpb.SignRequest{
			Handle:  gen.GetHandle(),
			Digest:  digest,
			Hash:    signerpb.Hash_HASH_SHA256,
			Purpose: signerpb.KeyPurpose_KEY_PURPOSE_GENERIC,
		})
		if err != nil {
			return err
		}
		if len(resp.GetSignature()) == 0 {
			return fmt.Errorf("perf live signer returned empty signature")
		}
		return nil
	}
	cleanup := func() {
		_ = conn.Close()
		grpcServer.Stop()
		svc.Shutdown()
		_ = lis.Close()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
		}
	}
	return op, "bufconn-grpc-signer", cleanup, nil
}

func captureResourceMetrics(projectionLagHint int) *ResourceMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &ResourceMetrics{
		Goroutines:        runtime.NumGoroutine(),
		CPUCount:          runtime.NumCPU(),
		OpenFDs:           openFDCount(),
		HeapAllocBytes:    m.HeapAlloc,
		HeapInuseBytes:    m.HeapInuse,
		StackInuseBytes:   m.StackInuse,
		TotalAllocBytes:   m.TotalAlloc,
		MemorySysBytes:    m.Sys,
		NumGC:             m.NumGC,
		ProjectionLagHint: projectionLagHint,
	}
}

func openFDCount() int {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(dir)
		if err == nil && len(entries) > 0 {
			return len(entries)
		}
	}
	return 3
}
