package risk

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

const highBlastRadiusThreshold = 4

// ContextualPriority is one scored credential with the blast-radius evidence
// and operator action needed to answer "what should I fix first" (CAP-POST-05).
type ContextualPriority struct {
	Rank                   int            `json:"rank"`
	CredentialID           string         `json:"credential_id"`
	Subject                string         `json:"subject"`
	Kind                   string         `json:"kind"`
	Severity               string         `json:"severity"`
	ContextualScore        float64        `json:"contextual_score"`
	BaseScore              float64        `json:"base_score"`
	BlastRadius            int            `json:"blast_radius"`
	ResourceBlastRadius    int            `json:"resource_blast_radius"`
	WorkloadBlastRadius    int            `json:"workload_blast_radius"`
	CredentialBlastRadius  int            `json:"credential_blast_radius"`
	CryptoAssetBlastRadius int            `json:"crypto_asset_blast_radius"`
	WeakCryptoContext      int            `json:"weak_crypto_context"`
	Privilege              PrivilegeClass `json:"privilege"`
	Sensitivity            Sensitivity    `json:"sensitivity"`
	OwnerActive            bool           `json:"owner_active"`
	ExpiresAt              time.Time      `json:"expires_at"`
	Components             Components     `json:"components"`
	PriorityReasons        []string       `json:"priority_reasons"`
	EvidenceRefs           []string       `json:"evidence_refs"`
	RecommendedAction      string         `json:"recommended_action"`
}

// ContextualPriorities scores every tenant certificate, then raises priority
// when the credential's graph blast radius reaches resources or weak/quantum
// crypto assets. Reads stay tenant-scoped through the store and graph builder.
func ContextualPriorities(ctx context.Context, st *store.Store, tenantID string) ([]ContextualPriority, error) {
	g, err := graph.Build(ctx, st, tenantID)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	var out []ContextualPriority
	after := store.ZeroUUID
	for {
		page, err := st.ListCertificatesPage(ctx, tenantID, after, nil, pageSize, nil)
		if err != nil {
			return nil, err
		}
		for _, c := range page {
			base := scoreCertificate(g, c, now)
			impact := g.BlastRadius("cert:" + c.ID)
			out = append(out, contextualPriority(base, impact, now))
		}
		if len(page) < pageSize {
			break
		}
		after = page[len(page)-1].ID
	}

	SortByContextualPriority(out)
	for i := range out {
		out[i].Rank = i + 1
	}
	return out, nil
}

func contextualPriority(base CredentialRisk, impact graph.Impact, now time.Time) ContextualPriority {
	resourceBlast := len(impact.ByKind[graph.KindResource])
	workloadBlast := len(impact.ByKind[graph.KindWorkload])
	credentialBlast := len(impact.ByKind[graph.KindCredential])
	cryptoBlast := len(impact.ByKind[graph.KindCryptoAsset])
	weakCrypto := weakCryptoAssetCount(impact.ByKind[graph.KindCryptoAsset])
	totalBlast := len(impact.Affected)

	reasons := []string{}
	score := base.Score
	if totalBlast >= highBlastRadiusThreshold {
		reasons = append(reasons, "high_blast_radius")
		score += 18
	} else if resourceBlast > 0 {
		reasons = append(reasons, "resource_blast_radius")
		score += 6
	}
	if weakCrypto > 0 {
		reasons = append(reasons, "weak_crypto_context")
		score += 14
	}
	if base.Privilege >= PrivilegeHigh {
		reasons = append(reasons, "privileged_credential")
		score += 8
	}
	if !base.OwnerActive {
		reasons = append(reasons, "orphaned_owner")
		score += 10
	}
	if !base.ExpiresAt.IsZero() && base.ExpiresAt.Sub(now) <= 30*24*time.Hour {
		reasons = append(reasons, "near_expiry")
		score += 10
	}
	if base.Components.Rotation >= 0.75 {
		reasons = append(reasons, "stale_rotation")
		score += 6
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "baseline_risk")
	}

	score = math.Min(100, round1(score))
	evidenceRefs := []string{
		"credential:" + base.CredentialID,
		"graph:blast-radius:cert:" + base.CredentialID,
	}
	if weakCrypto > 0 && impact.Node.ID != "" {
		evidenceRefs = append(evidenceRefs, fmt.Sprintf("cbom:weak-crypto-assets:%d", weakCrypto))
	}

	return ContextualPriority{
		CredentialID:           base.CredentialID,
		Subject:                base.Subject,
		Kind:                   base.Kind,
		Severity:               contextualSeverity(score),
		ContextualScore:        score,
		BaseScore:              round1(base.Score),
		BlastRadius:            totalBlast,
		ResourceBlastRadius:    resourceBlast,
		WorkloadBlastRadius:    workloadBlast,
		CredentialBlastRadius:  credentialBlast,
		CryptoAssetBlastRadius: cryptoBlast,
		WeakCryptoContext:      weakCrypto,
		Privilege:              base.Privilege,
		Sensitivity:            base.Sensitivity,
		OwnerActive:            base.OwnerActive,
		ExpiresAt:              base.ExpiresAt,
		Components:             base.Components,
		PriorityReasons:        reasons,
		EvidenceRefs:           evidenceRefs,
		RecommendedAction:      contextualAction(score, totalBlast, weakCrypto, base.OwnerActive),
	}
}

func weakCryptoAssetCount(nodes []graph.Node) int {
	count := 0
	for _, n := range nodes {
		if n.Attrs["quantum_vulnerable"] == "true" || n.Attrs["out_of_policy"] == "true" || n.Attrs["strength"] == "weak" {
			count++
		}
	}
	return count
}

func contextualSeverity(score float64) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 50:
		return "medium"
	default:
		return "low"
	}
}

func contextualAction(score float64, blastRadius, weakCrypto int, ownerActive bool) string {
	switch {
	case score >= 85 || (blastRadius >= highBlastRadiusThreshold && weakCrypto > 0):
		return "Rotate and redeploy before lower-blast-radius work; review affected resources and weak crypto assets first."
	case !ownerActive:
		return "Assign an owner, then rotate or revoke according to the credential graph blast radius."
	case blastRadius >= highBlastRadiusThreshold:
		return "Schedule priority rotation and validate every affected graph node after deployment."
	default:
		return "Track in normal rotation order and keep graph evidence attached to the work item."
	}
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// SortByContextualPriority orders priorities by contextual score descending,
// then by blast radius and credential id for deterministic API responses.
func SortByContextualPriority(ps []ContextualPriority) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].ContextualScore != ps[j].ContextualScore {
			return ps[i].ContextualScore > ps[j].ContextualScore
		}
		if ps[i].BlastRadius != ps[j].BlastRadius {
			return ps[i].BlastRadius > ps[j].BlastRadius
		}
		return ps[i].CredentialID < ps[j].CredentialID
	})
}
