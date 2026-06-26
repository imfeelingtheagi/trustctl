#!/usr/bin/env bash
# Build the `sha256  name` subject files consumed by slsa-github-generator's
# generic workflow. The file format is intentionally the same as sha256sum output,
# because that is what the upstream generator signs.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage:
  slsa-subjects.sh files <out.subjects> <artifact>...
  slsa-subjects.sh image <out.subjects> <image-ref> <sha256-digest> [artifact...]
  slsa-subjects.sh encode <in.subjects>

The image form writes the OCI image reference as the first SLSA subject and then
appends sha256sum subjects for any filesystem artifacts such as rendered manifests.
EOF
  exit 2
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file"
  else
    # macOS fallback. Keep two spaces between digest and name, matching sha256sum.
    local digest
    digest="$(shasum -a 256 "$file" | awk '{print $1}')"
    printf '%s  %s\n' "$digest" "$file"
  fi
}

encode_subjects() {
  local file="$1"
  # GNU base64 supports -w0; BSD/macOS does not. Trimming newlines is portable and
  # keeps the GitHub Actions output on one line.
  base64 <"$file" | tr -d '\n'
}

mode="${1:-}"
case "$mode" in
files)
  shift
  out="${1:-}"
  [ -n "$out" ] || usage
  shift
  [ "$#" -gt 0 ] || usage
  : >"$out"
  for artifact in "$@"; do
    [ -s "$artifact" ] || { echo "::error::missing SLSA artifact subject: $artifact" >&2; exit 1; }
    sha256_file "$artifact" >>"$out"
  done
  ;;
image)
  shift
  out="${1:-}"
  image_ref="${2:-}"
  digest="${3:-}"
  [ -n "$out" ] && [ -n "$image_ref" ] && [ -n "$digest" ] || usage
  shift 3
  digest="${digest#sha256:}"
  case "$digest" in
    *[!0-9a-f]* | "")
      echo "::error::image digest must be lowercase hex sha256, got ${digest}" >&2
      exit 1
      ;;
  esac
  if [ "${#digest}" -ne 64 ]; then
    echo "::error::image digest must be 64 hex characters, got ${#digest}" >&2
    exit 1
  fi
  printf '%s  %s\n' "$digest" "$image_ref" >"$out"
  for artifact in "$@"; do
    [ -s "$artifact" ] || { echo "::error::missing SLSA artifact subject: $artifact" >&2; exit 1; }
    sha256_file "$artifact" >>"$out"
  done
  ;;
encode)
  shift
  in="${1:-}"
  [ -s "$in" ] || usage
  encode_subjects "$in"
  ;;
*)
  usage
  ;;
esac
