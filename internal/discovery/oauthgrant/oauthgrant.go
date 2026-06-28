// Package oauthgrant normalizes metadata-only OAuth application grants into
// discovery findings. It models the SaaS-to-SaaS consent layer and never accepts
// client secrets, refresh tokens, or other credential bodies as finding material.
package oauthgrant

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// SourceKind is the served discovery source kind for CAP-OAUTH-01.
	SourceKind = "oauth_grant"
	// FindingKind is the read-model kind emitted for a discovered OAuth grant.
	FindingKind = "oauth_grant"
	// MaxGrants caps a single served source config so one run cannot exhaust the
	// discovery worker lane.
	MaxGrants = 10000
)

// Config is the persisted source configuration for OAuth app/grant discovery.
// Grants are metadata-only references exported from IdPs and SaaS admin APIs.
type Config struct {
	Grants []Grant `json:"grants"`
}

// Grant is one OAuth app authorization. AppID and Resource are public
// identifiers; credential material must stay behind provider-side references and
// never appears in this data model.
type Grant struct {
	Provider     string   `json:"provider"`
	AppID        string   `json:"app_id"`
	AppName      string   `json:"app_name,omitempty"`
	Principal    string   `json:"principal,omitempty"`
	Resource     string   `json:"resource"`
	Scopes       []string `json:"scopes"`
	ConsentType  string   `json:"consent_type,omitempty"`
	ThirdParty   bool     `json:"third_party,omitempty"`
	Owner        string   `json:"owner,omitempty"`
	Publisher    string   `json:"publisher,omitempty"`
	Tenant       string   `json:"tenant,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
	LastUsed     string   `json:"last_used,omitempty"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	Tags         []string `json:"tags,omitempty"`
}

// Finding is the normalized discovery finding material emitted by the server.
type Finding struct {
	Ref         string
	Provenance  string
	Fingerprint string
	RiskScore   int
	Metadata    map[string]any
}

// Findings decodes, validates, and normalizes a source config into OAuth grant
// findings. Each grant must include provider, app_id, resource, and at least one
// scope so CAP-OAUTH-01 covers app discovery, grant discovery, and scope discovery.
func Findings(raw json.RawMessage) ([]Finding, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode OAuth grant discovery config: %w", err)
	}
	if len(cfg.Grants) == 0 {
		return nil, errors.New("OAuth grant discovery requires grants")
	}
	if len(cfg.Grants) > MaxGrants {
		return nil, fmt.Errorf("OAuth grant discovery source has %d grants; maximum is %d", len(cfg.Grants), MaxGrants)
	}

	out := make([]Finding, 0, len(cfg.Grants))
	for i, grant := range cfg.Grants {
		finding, err := normalizeGrant(grant)
		if err != nil {
			return nil, fmt.Errorf("OAuth grant %d: %w", i, err)
		}
		out = append(out, finding)
	}
	return out, nil
}

// ValidateConfig checks the source config without returning normalized findings.
func ValidateConfig(raw json.RawMessage) error {
	_, err := Findings(raw)
	return err
}

func normalizeGrant(grant Grant) (Finding, error) {
	provider := strings.TrimSpace(grant.Provider)
	appID := strings.TrimSpace(grant.AppID)
	resource := strings.TrimSpace(grant.Resource)
	scopes := cleaned(grant.Scopes)
	if provider == "" || appID == "" || resource == "" {
		return Finding{}, errors.New("provider, app_id, and resource are required")
	}
	if len(scopes) == 0 {
		return Finding{}, errors.New("at least one scope is required")
	}

	principal := strings.TrimSpace(grant.Principal)
	ref := principal
	if ref == "" {
		ref = provider + "/" + appID + "/" + resource
	}
	provenance := SourceKind + ":" + provider + ":" + appID + ":" + resource
	meta := map[string]any{
		"provider":      provider,
		"app_id":        appID,
		"app_name":      strings.TrimSpace(grant.AppName),
		"principal":     principal,
		"resource":      resource,
		"scopes":        scopes,
		"consent_type":  strings.TrimSpace(grant.ConsentType),
		"third_party":   grant.ThirdParty,
		"owner":         strings.TrimSpace(grant.Owner),
		"publisher":     strings.TrimSpace(grant.Publisher),
		"tenant":        strings.TrimSpace(grant.Tenant),
		"created_at":    strings.TrimSpace(grant.CreatedAt),
		"last_used":     strings.TrimSpace(grant.LastUsed),
		"redirect_uris": cleaned(grant.RedirectURIs),
		"tags":          cleaned(grant.Tags),
	}
	return Finding{
		Ref:         ref,
		Provenance:  provenance,
		Fingerprint: provenance,
		RiskScore:   riskScore(grant, scopes),
		Metadata:    meta,
	}, nil
}

func cleaned(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func riskScore(grant Grant, scopes []string) int {
	score := 35
	if grant.ThirdParty {
		score += 20
	}
	if strings.EqualFold(strings.TrimSpace(grant.ConsentType), "admin") {
		score += 20
	}
	if hasSensitiveScope(scopes) {
		score += 10
	}
	if strings.TrimSpace(grant.Owner) == "" {
		score += 15
	}
	if score > 100 {
		return 100
	}
	return score
}

func hasSensitiveScope(scopes []string) bool {
	for _, scope := range scopes {
		s := strings.ToLower(scope)
		if strings.Contains(s, "admin") ||
			strings.Contains(s, "directory") ||
			strings.Contains(s, ".write") ||
			strings.Contains(s, "mail") ||
			strings.Contains(s, "drive") {
			return true
		}
	}
	return false
}
