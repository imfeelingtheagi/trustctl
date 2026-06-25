#!/usr/bin/env bash
set -euo pipefail

version="${TRSTCTL_GITLEAKS_VERSION:-v8.27.2}"
if [[ "${version}" != "v8.27.2" ]]; then
  echo "trstctl supports Gitleaks v8.27.2 for the served secrets scan bridge; got ${version}" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gobin="${GOBIN:-${root}/tools/bin}"
mkdir -p "${gobin}"

GOBIN="${gobin}" go install "github.com/zricethezav/gitleaks/v8@${version}"
echo "${gobin}/gitleaks"
