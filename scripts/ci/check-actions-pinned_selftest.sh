#!/usr/bin/env bash
# Self-test for check-actions-pinned.sh — proves the action-SHA-pinning guard
# accepts a fully SHA-pinned workflow and rejects a floating-tag regression
# (SUPPLY-002 acceptance: "a policy step fails on a tag-pinned external action").
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${here}/check-actions-pinned.sh"

fails=0
check() { if [[ "$2" == "$3" ]]; then echo "PASS: $1"; else echo "FAIL: $1 (want exit $2, got $3)"; fails=1; fi; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

sha='34e114876b0b11c390a56381ad16ebd13914f8d5' # a real 40-hex commit SHA shape

# --- GOOD fixture: every third-party action pinned to a 40-hex SHA -----------
mkdir -p "$tmp/good/.github/workflows"
cat >"$tmp/good/.github/workflows/ci.yml" <<EOF
jobs:
  build:
    steps:
      - uses: actions/checkout@${sha} # v4.3.1
      - uses: docker/build-push-action@${sha} # v6.19.2
      - uses: ./.github/actions/local-thing   # local action: out of scope
      - uses: docker://alpine:3.20             # container action: out of scope
  slsa:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
EOF

# --- BAD fixture A: a floating major tag (@v4) -------------------------------
mkdir -p "$tmp/bad1/.github/workflows"
cat >"$tmp/bad1/.github/workflows/ci.yml" <<EOF
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
EOF

# --- BAD fixture B: a quoted floating semver tag ('@v6.19.2') ----------------
mkdir -p "$tmp/bad2/.github/workflows"
cat >"$tmp/bad2/.github/workflows/release.yml" <<EOF
jobs:
  rel:
    steps:
      - uses: "docker/build-push-action@v6.19.2"
EOF

# --- BAD fixture C: a SHORT (12-hex) sha is not a real immutable pin ---------
mkdir -p "$tmp/bad3/.github/workflows"
cat >"$tmp/bad3/.github/workflows/ci.yml" <<EOF
jobs:
  build:
    steps:
      - uses: actions/setup-go@34e114876b0b # v5.6.0
EOF

# --- BAD fixture D: the SLSA exception is exact semver only, not @v2 ---------
mkdir -p "$tmp/bad4/.github/workflows"
cat >"$tmp/bad4/.github/workflows/release.yml" <<EOF
jobs:
  slsa:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2
EOF

# --- BAD fixture E: other reusable workflows do not inherit the SLSA exception
mkdir -p "$tmp/bad5/.github/workflows"
cat >"$tmp/bad5/.github/workflows/release.yml" <<EOF
jobs:
  rel:
    uses: some-owner/some-workflow/.github/workflows/reusable.yml@v1.2.3
EOF

set +e
main "$tmp/good" >/dev/null; check "accepts a fully SHA-pinned workflow plus exact SLSA generator tag" 0 $?
main "$tmp/bad1" >/dev/null; check "rejects a floating major tag (@v4)" 1 $?
main "$tmp/bad2" >/dev/null; check "rejects a quoted floating semver tag (@v6.19.2)" 1 $?
main "$tmp/bad3" >/dev/null; check "rejects a short (non-40-hex) sha" 1 $?
main "$tmp/bad4" >/dev/null; check "rejects non-exact SLSA generator tag (@v2)" 1 $?
main "$tmp/bad5" >/dev/null; check "rejects semver-tagged non-SLSA reusable workflow" 1 $?
set -e

if [[ "$fails" -ne 0 ]]; then echo "SELF-TEST FAILED"; exit 1; fi
echo "ALL SELF-TESTS PASSED"
