#!/usr/bin/env bash
# Convert a Trivy JSON report for the embedded PostgreSQL rootfs into a compact
# scanner receipt, and fail closed when a fixable Critical finding exists.
set -euo pipefail

fail() {
  printf '::error::embedded-postgres scan receipt: %s\n' "$*" >&2
  exit 1
}

if [[ "$#" -ne 7 ]]; then
  fail "usage: embedded-postgres-scan-receipt.sh <trivy-json> <trivy-version.txt> <receipt-json> <arch> <postgres-version> <jar-sha256> <txz-sha256>"
fi

report="$1"
version_file="$2"
receipt="$3"
arch="$4"
postgres_version="$5"
jar_sha256="$6"
txz_sha256="$7"

command -v jq >/dev/null 2>&1 || fail "jq is required"
[[ -s "$report" ]] || fail "Trivy JSON report is missing or empty: $report"
[[ -s "$version_file" ]] || fail "Trivy version output is missing or empty: $version_file"

count_severity() {
  local severity="$1"
  jq --arg severity "$severity" '[.Results[]?.Vulnerabilities[]? | select(.Severity == $severity)] | length' "$report"
}

count_fixable() {
  local severity="$1"
  jq --arg severity "$severity" '[.Results[]?.Vulnerabilities[]? | select(.Severity == $severity and (((.FixedVersion // "") | tostring | length) > 0))] | length' "$report"
}

high_total="$(count_severity HIGH)"
high_fixable="$(count_fixable HIGH)"
critical_total="$(count_severity CRITICAL)"
critical_fixable="$(count_fixable CRITICAL)"
generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
trivy_version="$(awk -F': ' '/^Version:/ {print $2; exit}' "$version_file")"
db_version="$(awk '/^Vulnerability DB:/ {seen=1; next} seen && /^[[:space:]]*Version:/ {sub(/^[[:space:]]*Version:[[:space:]]*/, ""); print; exit}' "$version_file")"
db_updated_at="$(awk '/^Vulnerability DB:/ {seen=1; next} seen && /^[[:space:]]*UpdatedAt:/ {sub(/^[[:space:]]*UpdatedAt:[[:space:]]*/, ""); print; exit}' "$version_file")"

[[ -n "$trivy_version" ]] || fail "Trivy version output did not include the scanner version"
[[ -n "$db_version" ]] || fail "Trivy version output did not include the vulnerability DB version"
[[ -n "$db_updated_at" ]] || fail "Trivy version output did not include the vulnerability DB update timestamp"

mkdir -p "$(dirname "$receipt")"
jq -n \
  --arg generated_at "$generated_at" \
  --arg arch "$arch" \
  --arg postgres_version "$postgres_version" \
  --arg jar_sha256 "$jar_sha256" \
  --arg txz_sha256 "$txz_sha256" \
  --arg trivy_version "$trivy_version" \
  --arg db_version "$db_version" \
  --arg db_updated_at "$db_updated_at" \
  --rawfile trivy_version_output "$version_file" \
  --argjson high_total "$high_total" \
  --argjson high_fixable "$high_fixable" \
  --argjson critical_total "$critical_total" \
  --argjson critical_fixable "$critical_fixable" \
  '{
    schema: "trstctl.embedded-postgres.trivy-receipt.v1",
    generated_at_utc: $generated_at,
    arch: $arch,
    postgres_version: $postgres_version,
    artifact: {
      jar_sha256: $jar_sha256,
      txz_sha256: $txz_sha256
    },
    scanner: {
      tool: "trivy",
      version: $trivy_version,
      vulnerability_db_version: $db_version,
      vulnerability_db_updated_at: $db_updated_at,
      version_output: $trivy_version_output
    },
    policy: {
      severity: "HIGH,CRITICAL",
      ignore_unfixed: true,
      fail_on_fixable_critical: true
    },
    counts: {
      high: {
        total: $high_total,
        fixable: $high_fixable
      },
      critical: {
        total: $critical_total,
        fixable: $critical_fixable
      }
    },
    result: (if $critical_fixable == 0 then "pass" else "fail" end)
  }' >"$receipt"

if [[ "$critical_fixable" -ne 0 ]]; then
  fail "Trivy found ${critical_fixable} fixable Critical finding(s); see $receipt and $report"
fi
