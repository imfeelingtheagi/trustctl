#!/usr/bin/env bash
# PERF-004: endurance/soak gate. Runs a sustained-load profile (or a self-test
# series) and ties the captured metrics to pass/fail thresholds: p95/p99 latency,
# RSS/heap, goroutines, FDs, DB pool, queue rejects, signer restarts, projection
# lag, outbox lag, and storage growth. It FAILS (exits non-zero) on a leak slope or
# an SLO breach and emits a JSON trend report.
#
# Self-test (no server, no embedded PostgreSQL required):
#   scripts/perf/soak.sh --selftest-fail   # induced leak/saturation -> exit non-zero
#   scripts/perf/soak.sh --selftest-ok     # healthy steady state     -> exit zero
#
# Real run (CI nightly profile): capture a sustained-load series to JSON and analyze
#   scripts/perf/soak.sh --in <series.json> --out <report.json>
#
# The threshold contract and analyzer live in internal/perf/soak.go so docs, this
# gate, and CI consume one denominator (the same pattern as the smoke gate).
set -euo pipefail

mode=""          # selftest-ok | selftest-fail | in
in_path=""
out=""
profile="soak"
samples="${SOAK_SAMPLES:-120}"
step_seconds="${SOAK_STEP_SECONDS:-60}"

usage() {
	cat >&2 <<'EOF'
usage: scripts/perf/soak.sh [--selftest-ok | --selftest-fail | --in <series.json>]
                            [--out <report.json>] [--profile NAME]
                            [--samples N] [--step-seconds S]
EOF
	exit 2
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--selftest-ok)   mode="selftest-ok"; shift ;;
		--selftest-fail) mode="selftest-fail"; shift ;;
		--in)            mode="in"; in_path="${2:?--in requires a path}"; shift 2 ;;
		--out)           out="${2:?--out requires a value}"; shift 2 ;;
		--profile)       profile="${2:?--profile requires a value}"; shift 2 ;;
		--samples)       samples="${2:?--samples requires a value}"; shift 2 ;;
		--step-seconds)  step_seconds="${2:?--step-seconds requires a value}"; shift 2 ;;
		-h|--help)       usage ;;
		*)               echo "unknown argument: $1" >&2; usage ;;
	esac
done

if [[ -z "$mode" ]]; then
	echo ">> soak: no mode selected" >&2
	usage
fi

args=(./scripts/perf/cmd/soakgate --profile "$profile" --samples "$samples" --step-seconds "$step_seconds")
case "$mode" in
	selftest-ok)   args+=(--selftest-ok) ;;
	selftest-fail) args+=(--selftest-fail) ;;
	in)            args+=(--in "$in_path") ;;
esac
if [[ -n "$out" ]]; then
	args+=(--out "$out")
fi

echo ">> soak ($mode) profile=$profile samples=$samples step=${step_seconds}s${out:+ out=$out}" >&2
go run "${args[@]}"
