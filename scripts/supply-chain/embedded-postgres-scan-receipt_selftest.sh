#!/usr/bin/env bash
# Self-test for the embedded-postgres Trivy receipt policy. It proves HIGH and
# non-fixable Critical findings are recorded, while fixable Critical findings fail.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/trivy-version.txt" <<'EOF'
Version: 0.58.1
Vulnerability DB:
  Version: 2
  UpdatedAt: 2026-06-17 00:00:00 +0000 UTC
EOF

cat >"$tmp/pass.json" <<'EOF'
{
  "Results": [
    {
      "Target": "postgres",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-HIGH", "Severity": "HIGH", "FixedVersion": "16.4.1"},
        {"VulnerabilityID": "CVE-CRIT-UNFIXED", "Severity": "CRITICAL", "FixedVersion": ""}
      ]
    }
  ]
}
EOF

"$here/embedded-postgres-scan-receipt.sh" "$tmp/pass.json" "$tmp/trivy-version.txt" "$tmp/pass-receipt.json" linux-amd64 16.4.0 jar txz
jq -e '.result == "pass" and .counts.high.fixable == 1 and .counts.critical.total == 1 and .counts.critical.fixable == 0' "$tmp/pass-receipt.json" >/dev/null

cat >"$tmp/no-db-version.txt" <<'EOF'
Version: 0.58.1
EOF

set +e
"$here/embedded-postgres-scan-receipt.sh" "$tmp/pass.json" "$tmp/no-db-version.txt" "$tmp/no-db-receipt.json" linux-amd64 16.4.0 jar txz >/dev/null 2>"$tmp/no-db.err"
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "receipt policy accepted missing Trivy DB metadata"
  exit 1
fi
grep -q 'vulnerability DB version' "$tmp/no-db.err"

cat >"$tmp/fail.json" <<'EOF'
{
  "Results": [
    {
      "Target": "postgres",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-CRIT-FIXABLE", "Severity": "CRITICAL", "FixedVersion": "16.4.1"}
      ]
    }
  ]
}
EOF

set +e
"$here/embedded-postgres-scan-receipt.sh" "$tmp/fail.json" "$tmp/trivy-version.txt" "$tmp/fail-receipt.json" linux-amd64 16.4.0 jar txz >/dev/null 2>"$tmp/fail.err"
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "receipt policy accepted a fixable Critical finding"
  exit 1
fi
jq -e '.result == "fail" and .counts.critical.fixable == 1' "$tmp/fail-receipt.json" >/dev/null
grep -q 'fixable Critical' "$tmp/fail.err"

echo "ALL SELF-TESTS PASSED"
