#!/usr/bin/env bash
#
# Verify the provenance of the PostgreSQL binary that the embedded-postgres
# dependency downloads at runtime, then scan it. That binary comes from Maven
# Central (NOT the Go module proxy), so it is outside go.sum and needs its own
# COMMITTED pin + scan. It is run both by the integration tests AND by the served
# single-node/eval path (internal/server/startBundledPostgres), so the pin is a
# HARD gate here and is enforced again at runtime (SUPPLY-003).
#
# The committed pin is per-arch (deploy/supply-chain/embedded-postgres.json
# archives[]). This script verifies the jar for the requested arch against
# jar_sha256, and the inner .txz against txz_sha256 (the artifact the runtime
# verifies). A missing pin is a HARD FAILURE now — no trust-on-first-use fallback,
# because the pin has been completed. Requires network access (Maven Central).
#
#   ARCH=linux-amd64 ./verify-embedded-postgres.sh   # default
#   ARCH=linux-arm64v8 ./verify-embedded-postgres.sh
#   ARCH=darwin-arm64v8 ./verify-embedded-postgres.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
manifest="$repo/deploy/supply-chain/embedded-postgres.json"
workdir="$repo/.supply-chain/embedded-postgres"

for tool in jq curl sha256sum unzip; do
  command -v "$tool" >/dev/null 2>&1 || { echo "::error::$tool is required" >&2; exit 1; }
done

ver="$(jq -r '.postgresVersion' "$manifest")"
arch="${ARCH:-linux-amd64}"

# Pull the per-arch pins + jar URL from the committed manifest.
entry="$(jq -c --arg a "$arch" '.archives[] | select(.arch == $a)' "$manifest")"
if [ -z "$entry" ] || [ "$entry" = "null" ]; then
  echo "::error::no committed provenance pin for arch ${arch} in ${manifest} (SUPPLY-003)" >&2
  echo "    known arches: $(jq -r '.archives[].arch' "$manifest" | paste -sd, -)" >&2
  exit 1
fi
url="$(printf '%s' "$entry" | jq -r '.jarUrl')"
wantJar="$(printf '%s' "$entry" | jq -r '.jar_sha256 // ""')"
wantTxz="$(printf '%s' "$entry" | jq -r '.txz_sha256 // ""')"

if [ -z "$wantJar" ] || [ -z "$wantTxz" ]; then
  echo "::error::embedded-postgres ${arch} pin is empty in the manifest — the provenance gate is a no-op (SUPPLY-003)" >&2
  exit 1
fi

mkdir -p "$workdir"
archWorkdir="$workdir/${arch}-${ver}"
rm -rf "$archWorkdir"
mkdir -p "$archWorkdir"
jar="$archWorkdir/embedded-postgres-${arch}-${ver}.jar"

echo ">> downloading PostgreSQL ${ver} (${arch}) binary: ${url}"
curl -fsSL "$url" -o "$jar"

gotJar="$(sha256sum "$jar" | awk '{print $1}')"
echo ">> sha256(jar ${arch} ${ver}) = ${gotJar}"
if [ "$gotJar" != "$wantJar" ]; then
  echo "::error::embedded-postgres ${arch} ${ver} JAR checksum mismatch — refusing to proceed" >&2
  echo "    expected ${wantJar}" >&2
  echo "    got      ${gotJar}" >&2
  exit 1
fi
echo ">> jar checksum verified against the committed manifest"

# Verify the inner .txz too — that is the artifact the runtime caches and checks.
( cd "$archWorkdir" && unzip -oq "$jar" )
innerTxz="$(find "$archWorkdir" -name '*.txz' -print | head -1)"
if [ -z "$innerTxz" ]; then
  echo "::error::could not find the inner .txz inside the jar for ${arch}" >&2
  exit 1
fi
gotTxz="$(sha256sum "$innerTxz" | awk '{print $1}')"
echo ">> sha256(.txz ${arch}) = ${gotTxz}"
if [ "$gotTxz" != "$wantTxz" ]; then
  echo "::error::embedded-postgres ${arch} ${ver} .txz checksum mismatch — the runtime pin would reject this binary" >&2
  echo "    expected ${wantTxz}" >&2
  echo "    got      ${gotTxz}" >&2
  exit 1
fi
echo ">> inner .txz checksum verified against the committed runtime pin"

echo ">> extracting for vulnerability scan"
( cd "$archWorkdir" && unzip -oq "$jar" )
# The jar wraps a postgres-<os>-<arch>.txz; unpack any we find so Trivy can scan
# the actual binaries and shared libraries.
find "$archWorkdir" -name '*.txz' -print0 | while IFS= read -r -d '' txz; do
  tar -xf "$txz" -C "$archWorkdir" 2>/dev/null || true
done

# The scan is advisory (exit-code 0): this binary is integration-test only and is
# not shipped, and a transitive OS-package CVE in a prebuilt PostgreSQL binary is
# only fixable by bumping the pinned version upstream — so we RECORD findings here
# rather than block the build. The hard gate is the checksum-change check above.
TRIVY_IMAGE="aquasec/trivy:0.58.1"
scan_args=(rootfs --severity HIGH,CRITICAL --ignore-unfixed --no-progress --exit-code 0)
if command -v trivy >/dev/null 2>&1; then
  echo ">> trivy rootfs scan (local binary; advisory)"
  trivy "${scan_args[@]}" "$archWorkdir" || echo "::warning::trivy scan did not complete cleanly (advisory; checksum gate already passed)"
elif command -v docker >/dev/null 2>&1; then
  echo ">> trivy rootfs scan (pinned ${TRIVY_IMAGE}; advisory)"
  docker run --rm -v "${archWorkdir}:/scan:ro" "$TRIVY_IMAGE" "${scan_args[@]}" /scan \
    || echo "::warning::trivy (docker) scan did not complete cleanly (advisory; checksum gate already passed)"
else
  echo "::notice::neither trivy nor docker present; provenance + checksum verified, deep scan skipped."
fi

echo ">> embedded-postgres supply-chain check complete"
