package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const maxServedDiscoveryTargets = 10000

type networkDiscoveryConfig struct {
	Targets []string `json:"targets"`
	CIDRs   []string `json:"cidrs"`
	CIDR    string   `json:"cidr"`
	Ports   []int    `json:"ports"`
}

type manualDiscoveryConfig struct {
	Findings []manualDiscoveryFinding `json:"findings"`
}

type manualDiscoveryFinding struct {
	Kind        string          `json:"kind"`
	Ref         string          `json:"ref"`
	Provenance  string          `json:"provenance"`
	Fingerprint string          `json:"fingerprint"`
	RiskScore   int             `json:"risk_score"`
	Metadata    json.RawMessage `json:"metadata"`
}

func (d *issuanceDispatcher) handleDiscoveryRun(ctx context.Context, m orchestrator.Message) error {
	if d.orch == nil || d.store == nil || d.idem == nil {
		return errors.New("server: discovery dispatcher is not configured")
	}
	var p projections.DiscoveryRunQueued
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("server: decode discovery.run payload: %w", err)
	}
	if p.ID == "" || p.SourceID == "" {
		return nil
	}
	_, err := d.idem.Do(ctx, m.TenantID, "discovery:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		run, err := d.store.GetDiscoveryRun(ctx, m.TenantID, p.ID)
		if err != nil {
			return nil, err
		}
		if discoveryRunTerminal(run.Status) {
			return []byte(run.Status), nil
		}
		if run.Status == "queued" {
			if err := d.orch.StartDiscoveryRun(ctx, m.TenantID, p.ID); err != nil {
				return nil, err
			}
		}
		src, err := d.store.GetDiscoverySource(ctx, m.TenantID, p.SourceID)
		if err != nil {
			return nil, err
		}
		rep, status, msg, err := d.executeDiscoveryRun(ctx, m.TenantID, src, p)
		if err != nil {
			return nil, err
		}
		if err := d.orch.CompleteDiscoveryRun(ctx, m.TenantID, store.DiscoveryRun{
			ID: p.ID, Status: status, Targets: rep.Targets, Discovered: rep.Discovered,
			Failed: rep.Failed, Rejected: rep.Rejected, Error: msg,
		}); err != nil {
			return nil, err
		}
		return []byte(status), nil
	})
	return err
}

func (d *issuanceDispatcher) executeDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	if src.Kind == "network" {
		return d.executeNetworkDiscoveryRun(ctx, tenantID, src, run)
	}
	rep, err := d.recordManualDiscoveryFindings(ctx, tenantID, src, run.ID)
	if err != nil {
		return rep, "", "", err
	}
	if rep.Targets > 0 {
		return rep, "succeeded", "", nil
	}
	return netscan.Report{}, "failed", "no server-side connector is configured for discovery source kind " + src.Kind, nil
}

func (d *issuanceDispatcher) executeNetworkDiscoveryRun(ctx context.Context, tenantID string, src store.DiscoverySource, run projections.DiscoveryRunQueued) (netscan.Report, string, string, error) {
	targets, err := networkDiscoveryTargets(src.Config)
	if err != nil {
		return netscan.Report{}, "failed", err.Error(), nil
	}
	if run.DryRun {
		return netscan.Report{Targets: len(targets)}, "succeeded", "", nil
	}
	sink := discoveryRunSink{orch: d.orch, tenantID: tenantID, runID: run.ID, sourceID: src.ID}
	scanner := netscan.New(sink, netscan.WithWorkers(8), netscan.WithQueue(128), netscan.WithBackoff(10*time.Millisecond))
	defer scanner.Close()
	rep := scanner.Scan(ctx, targets)
	status := "succeeded"
	msg := ""
	if rep.Failed > 0 || rep.Rejected > 0 {
		if rep.Discovered > 0 {
			status = "partial"
			msg = "some discovery probes failed"
		} else {
			status = "failed"
			msg = "all discovery probes failed"
		}
	}
	return rep, status, msg, nil
}

func networkDiscoveryTargets(raw json.RawMessage) ([]string, error) {
	var cfg networkDiscoveryConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode network discovery config: %w", err)
	}
	targets := make([]string, 0, len(cfg.Targets))
	for _, target := range cfg.Targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(target); err != nil {
			return nil, fmt.Errorf("network discovery target %q must be host:port", target)
		}
		targets = append(targets, target)
	}
	cidrs := append([]string(nil), cfg.CIDRs...)
	if cfg.CIDR != "" {
		cidrs = append(cidrs, cfg.CIDR)
	}
	for _, cidr := range cidrs {
		expanded, err := netscan.ExpandRange(cidr, cfg.Ports)
		if err != nil {
			return nil, err
		}
		targets = append(targets, expanded...)
	}
	if len(targets) == 0 {
		return nil, errors.New("network discovery source requires targets or cidrs+ports")
	}
	if len(targets) > maxServedDiscoveryTargets {
		return nil, fmt.Errorf("network discovery source has %d targets; maximum is %d", len(targets), maxServedDiscoveryTargets)
	}
	return targets, nil
}

func (d *issuanceDispatcher) recordManualDiscoveryFindings(ctx context.Context, tenantID string, src store.DiscoverySource, runID string) (netscan.Report, error) {
	var cfg manualDiscoveryConfig
	if err := json.Unmarshal(src.Config, &cfg); err != nil {
		return netscan.Report{}, fmt.Errorf("decode discovery findings config: %w", err)
	}
	rep := netscan.Report{Targets: len(cfg.Findings)}
	for _, f := range cfg.Findings {
		f.Kind = strings.TrimSpace(f.Kind)
		f.Ref = strings.TrimSpace(f.Ref)
		if f.Kind == "" || f.Ref == "" {
			rep.Failed++
			continue
		}
		if f.Provenance == "" {
			f.Provenance = src.Kind + ":" + f.Ref
		}
		if len(f.Metadata) == 0 {
			f.Metadata = json.RawMessage(`{}`)
		}
		if _, err := d.orch.RecordDiscoveryFinding(ctx, tenantID, store.DiscoveryFinding{
			RunID: runID, SourceID: src.ID, Kind: f.Kind, Ref: f.Ref, Provenance: f.Provenance,
			Fingerprint: f.Fingerprint, RiskScore: f.RiskScore, Metadata: f.Metadata,
		}); err != nil {
			return rep, err
		}
		rep.Discovered++
	}
	return rep, nil
}

func discoveryRunTerminal(status string) bool {
	return status == "succeeded" || status == "partial" || status == "failed"
}

type discoveryRunSink struct {
	orch     *orchestrator.Orchestrator
	tenantID string
	runID    string
	sourceID string
}

func (s discoveryRunSink) Record(ctx context.Context, f netscan.Found) error {
	meta, err := json.Marshal(map[string]any{
		"subject":         f.Cert.Subject,
		"issuer":          f.Cert.Issuer,
		"serial":          f.Cert.SerialNumber,
		"sans":            sansOf(f.Cert),
		"not_before":      f.Cert.NotBefore,
		"not_after":       f.Cert.NotAfter,
		"key_algorithm":   f.Cert.KeyAlgorithm,
		"public_key_bits": f.Cert.PublicKeyBits,
		"is_ca":           f.Cert.IsCA,
	})
	if err != nil {
		return err
	}
	nb, na := f.Cert.NotBefore, f.Cert.NotAfter
	if _, err := s.orch.RecordCertificate(ctx, s.tenantID, store.Certificate{
		Subject: f.Cert.Subject, SANs: sansOf(f.Cert), Issuer: f.Cert.Issuer,
		Serial: f.Cert.SerialNumber, Fingerprint: f.Cert.SHA256Fingerprint,
		KeyAlgorithm: f.Cert.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		DeploymentLocation: f.Address, Source: "discovery:network",
	}); err != nil {
		return err
	}
	_, err = s.orch.RecordDiscoveryFinding(ctx, s.tenantID, store.DiscoveryFinding{
		RunID: s.runID, SourceID: s.sourceID, Kind: "x509_certificate", Ref: f.Address,
		Provenance: "network:" + f.Address, Fingerprint: f.Cert.SHA256Fingerprint,
		RiskScore: discoveryRiskScore(f.Cert.NotAfter), Metadata: meta,
	})
	return err
}

func discoveryRiskScore(notAfter time.Time) int {
	switch {
	case notAfter.IsZero():
		return 50
	case time.Until(notAfter) < 7*24*time.Hour:
		return 80
	case time.Until(notAfter) < 30*24*time.Hour:
		return 40
	default:
		return 10
	}
}
