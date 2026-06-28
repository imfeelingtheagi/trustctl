#!/usr/bin/env bash
# Generate release provenance from a base64-encoded SLSA subject file, then sign
# and upload it unless the caller disables those steps for local self-tests.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  cat >&2 <<'EOF'
usage: SLSA_SUBJECTS_B64=<base64 subjects> slsa-release-provenance.sh <provenance-name> [out-dir]

Environment:
  TRSTCTL_SLSA_SIGN=0      skip cosign sign-blob (local tests)
  TRSTCTL_SLSA_UPLOAD=0    skip GitHub Release upload (local tests)
  TRSTCTL_SLSA_BUILDER_ID  override the builder id in the SLSA predicate
EOF
  exit 2
}

provenance_name="${1:-}"
out_dir="${2:-dist/provenance}"
subjects_b64="${SLSA_SUBJECTS_B64:-}"
[ -n "$provenance_name" ] && [ -n "$subjects_b64" ] || usage

mkdir -p "$out_dir"
subject_file="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/${provenance_name}.subjects"
provenance="${out_dir}/${provenance_name}"
bundle="${provenance}.bundle"

python3 - "$subjects_b64" "$subject_file" <<'PY'
import base64
import pathlib
import sys

payload = base64.b64decode(sys.argv[1].encode(), validate=True)
if not payload.strip():
    raise SystemExit("decoded SLSA subject file is empty")
pathlib.Path(sys.argv[2]).write_bytes(payload)
PY

builder_id="${TRSTCTL_SLSA_BUILDER_ID:-https://github.com/${GITHUB_REPOSITORY:-ctlplne/trstctl}/.github/workflows/release.yml@${GITHUB_SHA:-local}}"
TRSTCTL_SLSA_PROVENANCE_MODE="${TRSTCTL_SLSA_PROVENANCE_MODE:-release}" \
  "$root/scripts/release/slsa-dry-run.sh" "$subject_file" "$provenance" "$builder_id"

if [ "${TRSTCTL_SLSA_SIGN:-1}" != "0" ]; then
  command -v cosign >/dev/null 2>&1 || { echo "::error::cosign is required to sign ${provenance}" >&2; exit 1; }
  cosign sign-blob --yes --bundle "$bundle" "$provenance"
fi

if [ "${TRSTCTL_SLSA_UPLOAD:-1}" != "0" ]; then
  [ "${GITHUB_REF_TYPE:-}" = "tag" ] || { echo "::error::SLSA provenance release assets require a tag ref, got ${GITHUB_REF_TYPE:-unset} ${GITHUB_REF_NAME:-unset}" >&2; exit 1; }
  command -v gh >/dev/null 2>&1 || { echo "::error::gh is required to upload ${provenance}" >&2; exit 1; }
  gh release view "$GITHUB_REF_NAME" >/dev/null 2>&1 || \
    gh release create "$GITHUB_REF_NAME" --verify-tag --title "$GITHUB_REF_NAME" --notes "trstctl $GITHUB_REF_NAME"
  if [ -s "$bundle" ]; then
    gh release upload "$GITHUB_REF_NAME" "$provenance" "$bundle" --clobber
  else
    gh release upload "$GITHUB_REF_NAME" "$provenance" --clobber
  fi
fi

echo "wrote ${provenance}"
