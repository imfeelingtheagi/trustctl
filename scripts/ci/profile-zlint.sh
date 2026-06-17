#!/usr/bin/env bash
# Run the pinned external zlint gate over the served CA plus every generated
# emitted-profile fixture, preserving one JSON transcript per input certificate.
set -euo pipefail

fail() {
  printf '::error::profile-zlint: %s\n' "$*" >&2
  exit 1
}

if [[ "$#" -ne 3 ]]; then
  fail "usage: profile-zlint.sh <served-ca.pem> <fixture-dir> <output-dir>"
fi

served_ca="$1"
fixture_dir="$2"
output_dir="$3"

command -v zlint >/dev/null 2>&1 || fail "zlint is not installed"
[[ -s "$served_ca" ]] || fail "served CA PEM is missing or empty: $served_ca"
[[ -d "$fixture_dir" ]] || fail "fixture directory is missing: $fixture_dir"

mkdir -p "$output_dir"
manifest="$output_dir/MANIFEST.txt"
: >"$manifest"

failures=0

lint_cert() {
  local label="$1"
  local cert="$2"
  local out="$3"

  printf '%s %s\n' "$label" "$cert" >>"$manifest"
  if ! zlint -includeSources RFC5280 -pretty "$cert" >"$out"; then
    printf '::error file=%s::zlint exited non-zero for %s\n' "$cert" "$label" >&2
    failures=1
    return
  fi
  if grep -Eq '"result"[[:space:]]*:[[:space:]]*"error"' "$out"; then
    printf '::error file=%s::zlint reported RFC5280 error-level findings for %s\n' "$cert" "$label" >&2
    failures=1
  fi
}

lint_cert "served-ca" "$served_ca" "$output_dir/served-ca.zlint.json"

shopt -s nullglob
fixtures=("$fixture_dir"/*.pem)
if [[ "${#fixtures[@]}" -eq 0 ]]; then
  fail "fixture directory has no PEM certificates: $fixture_dir"
fi
for fixture in "${fixtures[@]}"; do
  base="$(basename "$fixture" .pem)"
  lint_cert "$base" "$fixture" "$output_dir/${base}.zlint.json"
done

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
