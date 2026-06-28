#!/usr/bin/env bash
# Acceptance test for DIST-10: a local release dry-run emits SLSA subjects for the
# same artifact classes release.yml publishes and verifies the resulting in-toto
# provenance against the actual artifact bytes.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/dist/kubernetes" "$tmp/provenance"
printf 'release image digest\n' >"$tmp/image-digest.txt"
image_digest="$(shasum -a 256 "$tmp/image-digest.txt" | awk '{print $1}')"
printf 'apiVersion: apps/v1\nkind: DaemonSet\nmetadata:\n  name: trstctl-agent\n' >"$tmp/dist/kubernetes/trstctl-agent-daemonset.yaml"
printf 'windows agent exe\n' >"$tmp/dist/trstctl-agent.exe"
printf 'windows agent msi\n' >"$tmp/dist/trstctl-agent.msi"
( cd "$tmp/dist" && shasum -a 256 trstctl-agent.exe trstctl-agent.msi > SHA256SUMS )
printf 'helm chart archive\n' >"$tmp/dist/trstctl-0.1.0.tgz"
( cd "$tmp/dist" && shasum -a 256 trstctl-0.1.0.tgz > trstctl-0.1.0.tgz.sha256 )

"$root/scripts/release/slsa-subjects.sh" image "$tmp/container.subjects" \
  "ghcr.io/ctlplne/trstctl@sha256:${image_digest}" "sha256:${image_digest}" \
  "$tmp/dist/kubernetes/trstctl-agent-daemonset.yaml"
"$root/scripts/release/slsa-subjects.sh" files "$tmp/windows.subjects" \
  "$tmp/dist/trstctl-agent.exe" "$tmp/dist/trstctl-agent.msi" "$tmp/dist/SHA256SUMS"
"$root/scripts/release/slsa-subjects.sh" files "$tmp/helm.subjects" \
  "$tmp/dist/trstctl-0.1.0.tgz" "$tmp/dist/trstctl-0.1.0.tgz.sha256"

"$root/scripts/release/slsa-dry-run.sh" "$tmp/container.subjects" "$tmp/provenance/trstctl-container-and-manifest.intoto.jsonl"
"$root/scripts/release/slsa-dry-run.sh" "$tmp/windows.subjects" "$tmp/provenance/trstctl-agent-windows.intoto.jsonl"
"$root/scripts/release/slsa-dry-run.sh" "$tmp/helm.subjects" "$tmp/provenance/trstctl-helm-chart.intoto.jsonl"
SLSA_SUBJECTS_B64="$("$root/scripts/release/slsa-subjects.sh" encode "$tmp/container.subjects")" \
TRSTCTL_SLSA_SIGN=0 \
TRSTCTL_SLSA_UPLOAD=0 \
TRSTCTL_SLSA_PROVENANCE_MODE=release \
  "$root/scripts/release/slsa-release-provenance.sh" trstctl-release-mode.intoto.jsonl "$tmp/provenance" >/dev/null

python3 - "$tmp" <<'PY'
import hashlib
import json
import pathlib
import sys

tmp = pathlib.Path(sys.argv[1])

def subjects(path):
    out = {}
    for raw in pathlib.Path(path).read_text().splitlines():
        digest, name = raw.split(None, 1)
        out[name.strip()] = digest
    return out

def verify(subject_file, provenance_file):
    want = subjects(subject_file)
    stmt = json.loads(pathlib.Path(provenance_file).read_text())
    assert stmt["_type"] == "https://in-toto.io/Statement/v0.1"
    assert stmt["predicateType"] == "https://slsa.dev/provenance/v0.2"
    assert stmt["predicate"]["buildType"] == "https://github.com/slsa-framework/slsa-github-generator/generic@v1"
    got = {s["name"]: s["digest"]["sha256"] for s in stmt["subject"]}
    if got != want:
        raise SystemExit(f"subject mismatch for {provenance_file}: got {got}, want {want}")
    for name, digest in got.items():
        p = pathlib.Path(name)
        if p.exists():
            actual = hashlib.sha256(p.read_bytes()).hexdigest()
            if actual != digest:
                raise SystemExit(f"{p} digest {actual} != provenance {digest}")

verify(tmp / "container.subjects", tmp / "provenance/trstctl-container-and-manifest.intoto.jsonl")
verify(tmp / "windows.subjects", tmp / "provenance/trstctl-agent-windows.intoto.jsonl")
verify(tmp / "helm.subjects", tmp / "provenance/trstctl-helm-chart.intoto.jsonl")
verify(tmp / "container.subjects", tmp / "provenance/trstctl-release-mode.intoto.jsonl")
release_stmt = json.loads((tmp / "provenance/trstctl-release-mode.intoto.jsonl").read_text())
if release_stmt["predicate"]["invocation"]["parameters"]["dryRun"] is not False:
    raise SystemExit("release-mode provenance must not be marked dryRun")
if release_stmt["predicate"]["invocation"]["environment"]["mode"] != "release":
    raise SystemExit("release-mode provenance did not record mode=release")
PY

echo "SLSA dry-run provenance self-test passed"
