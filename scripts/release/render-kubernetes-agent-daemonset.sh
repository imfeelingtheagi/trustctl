#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "render-kubernetes-agent-daemonset: $*" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
template="${TRSTCTL_AGENT_DAEMONSET_TEMPLATE:-${repo_root}/deploy/kubernetes/daemonset.yaml}"
placeholder='ghcr.io/imfeelingtheagi/trstctl@sha256:RELEASE_DIGEST_REQUIRED'

image="${1:-${TRSTCTL_AGENT_IMAGE:-}}"
if [[ -z "${image}" ]]; then
  fail "usage: TRSTCTL_AGENT_IMAGE='ghcr.io/<owner>/trstctl@sha256:<64-hex-digest>' $0 [image-ref]"
fi
if [[ ! "${image}" =~ ^[-./:_a-zA-Z0-9]+/trstctl@sha256:[0-9a-f]{64}$ ]]; then
  fail "agent image must be an immutable trstctl digest reference, got: ${image}"
fi
digest="${image##*@sha256:}"
if [[ "${digest}" =~ ^0{64}$ ]]; then
  fail "agent image digest must be a real release digest, not the all-zero placeholder"
fi
if [[ ! -f "${template}" ]]; then
  fail "template not found: ${template}"
fi
if ! grep -qF "${placeholder}" "${template}"; then
  fail "template does not contain the required digest marker: ${placeholder}"
fi

sed "s|${placeholder}|${image}|g" "${template}"
