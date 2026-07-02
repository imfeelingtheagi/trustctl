package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSpineBurstProfileOverridesAndValidation(t *testing.T) {
	cfg := defaultProfile("cap-small")
	applyOverrides(&cfg, 3, 15, 90, 30, 2, 4, 0)
	if cfg.Samples != 3 || cfg.Step != 15*time.Second || cfg.EventWorkload != 90 || cfg.OutboxWorkload != 30 || cfg.Tenants != 2 || cfg.Agents != 4 {
		t.Fatalf("applyOverrides did not update profile: %+v", cfg)
	}
	if cfg.SlowUpstream != 0 {
		t.Fatalf("slow upstream = %s, want disabled", cfg.SlowUpstream)
	}
	if err := validateProfile(cfg); err != nil {
		t.Fatalf("validateProfile: %v", err)
	}
	for _, bad := range []profileConfig{
		{Name: "few-samples", Samples: 1, Step: time.Second, Tenants: 1, Agents: 1, EventWorkload: 1, OutboxWorkload: 1},
		{Name: "zero-step", Samples: 2, Tenants: 1, Agents: 1, EventWorkload: 1, OutboxWorkload: 1},
		{Name: "zero-work", Samples: 2, Step: time.Second, Tenants: 0, Agents: 1, EventWorkload: 1, OutboxWorkload: 1},
	} {
		if err := validateProfile(bad); err == nil {
			t.Fatalf("validateProfile(%+v) succeeded, want error", bad)
		}
	}
}

func TestSpineBurstMathAndMarshalHelpers(t *testing.T) {
	if got := uuidFromInt(42); got != "00000000-0000-4000-8000-00000000002a" {
		t.Fatalf("uuidFromInt = %q", got)
	}
	if ceilDiv(0, 9) != 0 || ceilDiv(10, 3) != 4 {
		t.Fatalf("ceilDiv unexpected")
	}
	if minInt(4, 9) != 4 || maxInt(4, 9) != 9 {
		t.Fatalf("min/max unexpected")
	}
	if percentile(nil, 0.95) != 0 {
		t.Fatalf("percentile(nil) should be 0")
	}
	if got := percentile([]float64{10, 1, 5, 20}, 0.95); got != 20 {
		t.Fatalf("p95 = %.1f, want 20", got)
	}
	data, err := marshal(map[string]any{"ok": true}, false)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Fatalf("marshal output missing trailing newline: %q", data)
	}
	var decoded map[string]bool
	if err := json.Unmarshal(data, &decoded); err != nil || !decoded["ok"] {
		t.Fatalf("marshal output did not decode: %v %#v", err, decoded)
	}
}
