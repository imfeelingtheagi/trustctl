#!/usr/bin/env bash
set -euo pipefail

root="${TRSTCTL_BRANCH_PROTECTION_ROOT:-.}"
policy="${TRSTCTL_BRANCH_PROTECTION_POLICY:-${root}/.github/branch-protection.json}"
repo="${TRSTCTL_BRANCH_PROTECTION_REPO:-${GITHUB_REPOSITORY:-}}"
branch="${TRSTCTL_BRANCH_PROTECTION_BRANCH:-main}"

if ! command -v jq >/dev/null 2>&1; then
	echo "jq is required to verify branch protection" >&2
	exit 2
fi

policy_json="$(jq -c . "$policy")"
if [ -n "${TRSTCTL_BRANCH_PROTECTION_LIVE_JSON:-}" ]; then
	live_json="$(jq -c . "$TRSTCTL_BRANCH_PROTECTION_LIVE_JSON")"
else
	if [ -z "$repo" ]; then
		echo "GITHUB_REPOSITORY or TRSTCTL_BRANCH_PROTECTION_REPO is required" >&2
		exit 2
	fi
	live_json="$(gh api "repos/${repo}/branches/${branch}/protection")"
fi

policy_contexts="$(jq -r '.required_status_checks.contexts[]' <<<"$policy_json" | sort)"
live_contexts="$(jq -r '.required_status_checks.contexts[]' <<<"$live_json" | sort)"

fail=0
if [ "$policy_contexts" != "$live_contexts" ]; then
	echo "branch protection required contexts drifted from .github/branch-protection.json" >&2
	diff -u <(printf '%s\n' "$policy_contexts") <(printf '%s\n' "$live_contexts") >&2 || true
	fail=1
fi

check_bool() {
	local label="$1"
	local policy_expr="$2"
	local live_expr="$3"
	local want live
	want="$(jq -r "$policy_expr" <<<"$policy_json")"
	live="$(jq -r "$live_expr" <<<"$live_json")"
	if [ "$want" != "$live" ]; then
		echo "branch protection ${label} drifted: policy=${want} live=${live}" >&2
		fail=1
	fi
}

check_bool "strict status checks" '.required_status_checks.strict' '.required_status_checks.strict'
check_bool "enforce admins" '.enforce_admins' '.enforce_admins.enabled'
check_bool "code-owner reviews" '.required_pull_request_reviews.require_code_owner_reviews' '.required_pull_request_reviews.require_code_owner_reviews'
check_bool "stale review dismissal" '.required_pull_request_reviews.dismiss_stale_reviews' '.required_pull_request_reviews.dismiss_stale_reviews'
check_bool "last-push approval" '.required_pull_request_reviews.require_last_push_approval' '.required_pull_request_reviews.require_last_push_approval'
check_bool "review count" '.required_pull_request_reviews.required_approving_review_count' '.required_pull_request_reviews.required_approving_review_count'
check_bool "linear history" '.required_linear_history' '.required_linear_history.enabled'
check_bool "force pushes" '.allow_force_pushes' '.allow_force_pushes.enabled'
check_bool "branch deletion" '.allow_deletions' '.allow_deletions.enabled'
check_bool "conversation resolution" '.required_conversation_resolution' '.required_conversation_resolution.enabled'

if [ "$fail" -ne 0 ]; then
	echo "branch protection drift check failed" >&2
	exit 1
fi

echo "ok: live branch protection matches ${policy} for ${repo:-offline}/${branch}"
