#!/usr/bin/env bash
set -euo pipefail

root="${TRSTCTL_REQUIRED_CHECKS_ROOT:-.}"
policy="${TRSTCTL_REQUIRED_CHECKS_POLICY:-${root}/.github/branch-protection.json}"
attempts="${TRSTCTL_REQUIRED_CHECKS_ATTEMPTS:-1}"
sleep_seconds="${TRSTCTL_REQUIRED_CHECKS_SLEEP_SECONDS:-10}"

if ! command -v jq >/dev/null 2>&1; then
	echo "jq is required to verify required checks" >&2
	exit 2
fi

repo="${TRSTCTL_REQUIRED_CHECKS_REPO:-${GITHUB_REPOSITORY:-}}"
sha="${TRSTCTL_REQUIRED_CHECKS_SHA:-${GITHUB_SHA:-}}"

resolve_commit_sha() {
	local candidate="$1"
	if [ -z "$candidate" ]; then
		git -C "$root" rev-parse HEAD
		return
	fi
	if git -C "$root" rev-parse --verify "${candidate}^{commit}" >/dev/null 2>&1; then
		git -C "$root" rev-parse --verify "${candidate}^{commit}"
		return
	fi
	printf '%s\n' "$candidate"
}

fetch_status_json() {
	if [ -n "${TRSTCTL_REQUIRED_CHECKS_STATUS_JSON:-}" ]; then
		jq -c . "$TRSTCTL_REQUIRED_CHECKS_STATUS_JSON"
		return
	fi
	if [ -z "$repo" ] || [ -z "$sha" ]; then
		echo "GITHUB_REPOSITORY and GITHUB_SHA, or TRSTCTL_REQUIRED_CHECKS_REPO and TRSTCTL_REQUIRED_CHECKS_SHA, are required" >&2
		exit 2
	fi
	gh api "repos/${repo}/commits/${sha}/status"
}

fetch_check_runs_json() {
	if [ -n "${TRSTCTL_REQUIRED_CHECKS_CHECK_RUNS_JSON:-}" ]; then
		jq -c . "$TRSTCTL_REQUIRED_CHECKS_CHECK_RUNS_JSON"
		return
	fi
	if [ -z "$repo" ] || [ -z "$sha" ]; then
		echo "GITHUB_REPOSITORY and GITHUB_SHA, or TRSTCTL_REQUIRED_CHECKS_REPO and TRSTCTL_REQUIRED_CHECKS_SHA, are required" >&2
		exit 2
	fi
	gh api --paginate "repos/${repo}/commits/${sha}/check-runs" -F per_page=100 | jq -s '{check_runs: map(.check_runs[])}'
}

required="$(jq -r '.required_status_checks.contexts[]' "$policy")"
if [ -z "$required" ]; then
	echo "no required checks in ${policy}" >&2
	exit 2
fi

if [ -z "${TRSTCTL_REQUIRED_CHECKS_STATUS_JSON:-}" ] || [ -z "${TRSTCTL_REQUIRED_CHECKS_CHECK_RUNS_JSON:-}" ]; then
	sha="$(resolve_commit_sha "$sha")"
fi

evaluate_once() {
	local status_json="$1"
	local check_runs_json="$2"
	local missing=()
	local pending=()
	local failed=()
	local passed=0
	local ctx state check_state

	while IFS= read -r ctx; do
		[ -n "$ctx" ] || continue
		state="$(jq -r --arg ctx "$ctx" '
			[.statuses[]? | select(.context == $ctx)]
			| sort_by(.updated_at // .created_at // "")
			| last
			| .state // ""
		' <<<"$status_json")"
		if [ "$state" = "success" ]; then
			passed=$((passed + 1))
			continue
		fi

		check_state="$(jq -r --arg ctx "$ctx" '
			[.check_runs[]? | select(.name == $ctx)]
			| sort_by(.completed_at // .started_at // .created_at // "")
			| last
			| if . == null then "" else "\(.status // "") \(.conclusion // "")" end
		' <<<"$check_runs_json")"
		case "$check_state" in
			"completed success")
				passed=$((passed + 1))
				;;
			"queued "*|"in_progress "*|"waiting "*|"requested "*|"pending "*)
				pending+=("$ctx")
				;;
			"")
				if [ -z "$state" ]; then
					missing+=("$ctx")
				elif [ "$state" = "pending" ]; then
					pending+=("$ctx")
				else
					failed+=("$ctx=status:${state}")
				fi
				;;
			*)
				failed+=("$ctx=check:${check_state}")
				;;
		esac
	done <<<"$required"

	if [ "${#missing[@]}" -eq 0 ] && [ "${#pending[@]}" -eq 0 ] && [ "${#failed[@]}" -eq 0 ]; then
		echo "ok: ${passed} required checks are green for ${repo:-offline}@${sha:-fixture}"
		return 0
	fi

	if [ "${#missing[@]}" -gt 0 ]; then
		printf 'missing required checks:\n' >&2
		printf '  %s\n' "${missing[@]}" >&2
	fi
	if [ "${#pending[@]}" -gt 0 ]; then
		printf 'pending required checks:\n' >&2
		printf '  %s\n' "${pending[@]}" >&2
	fi
	if [ "${#failed[@]}" -gt 0 ]; then
		printf 'failed required checks:\n' >&2
		printf '  %s\n' "${failed[@]}" >&2
	fi
	return 1
}

for attempt in $(seq 1 "$attempts"); do
	status_json="$(fetch_status_json)"
	check_runs_json="$(fetch_check_runs_json)"
	if evaluate_once "$status_json" "$check_runs_json"; then
		exit 0
	fi
	if [ "$attempt" -lt "$attempts" ]; then
		echo "required checks are not all green yet; retrying (${attempt}/${attempts})" >&2
		sleep "$sleep_seconds"
	fi
done

echo "release preflight failed: required CI/security checks are not all green" >&2
exit 1
