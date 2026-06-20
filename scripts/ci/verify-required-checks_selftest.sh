#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/.github"
cat >"$tmp/.github/branch-protection.json" <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "build / test / lint",
      "govulncheck",
      "container image scan (Trivy)"
    ]
  }
}
JSON

cat >"$tmp/status-success.json" <<'JSON'
{
  "statuses": [
    {
      "context": "govulncheck",
      "state": "success",
      "updated_at": "2026-06-20T00:00:00Z"
    }
  ]
}
JSON

cat >"$tmp/checks-success.json" <<'JSON'
{
  "check_runs": [
    {
      "name": "build / test / lint",
      "status": "completed",
      "conclusion": "success",
      "completed_at": "2026-06-20T00:00:00Z"
    },
    {
      "name": "container image scan (Trivy)",
      "status": "completed",
      "conclusion": "success",
      "completed_at": "2026-06-20T00:00:00Z"
    }
  ]
}
JSON

TRSTCTL_REQUIRED_CHECKS_ROOT="$tmp" \
TRSTCTL_REQUIRED_CHECKS_STATUS_JSON="$tmp/status-success.json" \
TRSTCTL_REQUIRED_CHECKS_CHECK_RUNS_JSON="$tmp/checks-success.json" \
"$script_dir/verify-required-checks.sh"

cat >"$tmp/checks-failed.json" <<'JSON'
{
  "check_runs": [
    {
      "name": "build / test / lint",
      "status": "completed",
      "conclusion": "failure",
      "completed_at": "2026-06-20T00:00:00Z"
    },
    {
      "name": "container image scan (Trivy)",
      "status": "completed",
      "conclusion": "success",
      "completed_at": "2026-06-20T00:00:00Z"
    }
  ]
}
JSON

if TRSTCTL_REQUIRED_CHECKS_ROOT="$tmp" \
	TRSTCTL_REQUIRED_CHECKS_STATUS_JSON="$tmp/status-success.json" \
	TRSTCTL_REQUIRED_CHECKS_CHECK_RUNS_JSON="$tmp/checks-failed.json" \
	"$script_dir/verify-required-checks.sh" >/tmp/trstctl-required-checks-failed.out 2>&1; then
	echo "expected failed required check to block release preflight" >&2
	exit 1
fi
if ! grep -q "build / test / lint" /tmp/trstctl-required-checks-failed.out; then
	echo "failed-check output did not name the failing context" >&2
	cat /tmp/trstctl-required-checks-failed.out >&2
	exit 1
fi

cat >"$tmp/checks-missing.json" <<'JSON'
{
  "check_runs": [
    {
      "name": "build / test / lint",
      "status": "completed",
      "conclusion": "success",
      "completed_at": "2026-06-20T00:00:00Z"
    }
  ]
}
JSON

if TRSTCTL_REQUIRED_CHECKS_ROOT="$tmp" \
	TRSTCTL_REQUIRED_CHECKS_STATUS_JSON="$tmp/status-success.json" \
	TRSTCTL_REQUIRED_CHECKS_CHECK_RUNS_JSON="$tmp/checks-missing.json" \
	"$script_dir/verify-required-checks.sh" >/tmp/trstctl-required-checks-missing.out 2>&1; then
	echo "expected missing required check to block release preflight" >&2
	exit 1
fi
if ! grep -q "container image scan (Trivy)" /tmp/trstctl-required-checks-missing.out; then
	echo "missing-check output did not name the missing context" >&2
	cat /tmp/trstctl-required-checks-missing.out >&2
	exit 1
fi

echo "ok: verify-required-checks self-test"
