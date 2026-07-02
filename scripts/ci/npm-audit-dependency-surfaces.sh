#!/usr/bin/env bash
# npm-audit-dependency-surfaces.sh — fail CI on HIGH/CRITICAL npm advisories
# across dependency trees that live outside go.sum. The web app scans production
# deps only; the TypeScript SDK scans dev deps too because its generator
# (openapi-typescript) is intentionally a devDependency used by scripts/gen-sdk.sh.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
npm_bin="${NPM:-npm}"

web_prefix="${TRSTCTL_WEB_NPM_PREFIX:-${repo}/web}"
sdk_prefix="${TRSTCTL_TS_SDK_NPM_PREFIX:-${repo}/clients/sdk/typescript}"

audit_lock() {
	local label="$1" prefix="$2"
	shift 2
	if [[ ! -f "${prefix}/package.json" ]]; then
		echo "FAIL: ${label} has no package.json at ${prefix}/package.json" >&2
		return 1
	fi
	if [[ ! -f "${prefix}/package-lock.json" ]]; then
		echo "FAIL: ${label} has no package-lock.json at ${prefix}/package-lock.json" >&2
		return 1
	fi

	echo ">> npm audit (${label})"
	"${npm_bin}" --prefix "${prefix}" audit --package-lock-only --audit-level=high "$@"
}

audit_lock "web production dependency tree" "${web_prefix}" --omit=dev
audit_lock "TypeScript SDK generator dependency tree" "${sdk_prefix}" --include=dev
