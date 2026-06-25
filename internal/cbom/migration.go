package cbom

import "strings"

// MigrationTarget names the FIPS-standard post-quantum replacement a finding
// should move toward. Generation is a closed label for progress math:
// "migration-required" for classical/deprecated usage and "post-quantum-ready"
// for already-PQC usage.
type MigrationTarget struct {
	Algorithm  string `json:"algorithm"`
	Standard   string `json:"standard"`
	Generation string `json:"generation"`
}

// MigrationTargetFor maps observed classical cryptography to the NIST PQC family
// that replaces its security job:
//   - FIPS 203 / ML-KEM for key establishment, especially TLS handshakes.
//   - FIPS 204 / ML-DSA for ordinary certificate/workload signatures.
//   - FIPS 205 / SLH-DSA for legacy/deprecated signature contexts where a
//     conservative hash-based signature is the safer migration target.
func MigrationTargetFor(f Finding) MigrationTarget {
	if f.Protocol != "" || f.Cipher != "" {
		return MigrationTarget{Algorithm: "ML-KEM-768", Standard: "FIPS 203", Generation: "migration-required"}
	}
	switch keyFamily(f.Algorithm) {
	case "RSA", "ECDSA", "EdDSA":
		return MigrationTarget{Algorithm: "ML-DSA-65", Standard: "FIPS 204", Generation: "migration-required"}
	case "DSA":
		return MigrationTarget{Algorithm: "SLH-DSA-SHA2-128s", Standard: "FIPS 205", Generation: "migration-required"}
	case "ML-KEM":
		return MigrationTarget{Algorithm: "ML-KEM", Standard: "FIPS 203", Generation: "post-quantum-ready"}
	case "ML-DSA":
		return MigrationTarget{Algorithm: "ML-DSA", Standard: "FIPS 204", Generation: "post-quantum-ready"}
	case "PQC":
		up := strings.ToUpper(f.Algorithm)
		if strings.Contains(up, "SLH-DSA") || strings.Contains(up, "SPHINCS") {
			return MigrationTarget{Algorithm: "SLH-DSA", Standard: "FIPS 205", Generation: "post-quantum-ready"}
		}
		return MigrationTarget{Algorithm: f.Algorithm, Standard: "FIPS 204", Generation: "post-quantum-ready"}
	default:
		return MigrationTarget{Algorithm: "ML-DSA-65", Standard: "FIPS 204", Generation: "migration-required"}
	}
}

// MigrationProgress summarizes how much of a tenant's observed CBOM is already
// post-quantum-ready. It intentionally uses all observed assets as the denominator:
// a classical TLS endpoint and a classical certificate key both count as migration
// work, even when they are not weak by today's classical policy.
type MigrationProgress struct {
	TotalAssets             int     `json:"total_assets"`
	QuantumVulnerableAssets int     `json:"quantum_vulnerable_assets"`
	OutOfPolicyAssets       int     `json:"out_of_policy_assets"`
	PostQuantumReadyAssets  int     `json:"post_quantum_ready_assets"`
	PercentMigrated         float64 `json:"percent_migrated"`
}

// ProgressFor computes migration progress over classified findings.
func ProgressFor(findings []Finding) MigrationProgress {
	var p MigrationProgress
	p.TotalAssets = len(findings)
	for _, f := range findings {
		if f.Class.QuantumVulnerable {
			p.QuantumVulnerableAssets++
		}
		if f.Class.OutOfPolicy {
			p.OutOfPolicyAssets++
		}
		if MigrationTargetFor(f).Generation == "post-quantum-ready" {
			p.PostQuantumReadyAssets++
		}
	}
	if p.TotalAssets > 0 {
		p.PercentMigrated = float64(p.PostQuantumReadyAssets) * 100 / float64(p.TotalAssets)
	}
	return p
}
