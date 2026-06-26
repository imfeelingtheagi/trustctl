#!/usr/bin/env bash
# Local, offline SLSA provenance dry-run. GitHub's SLSA generator performs the real
# DSSE signing with OIDC in release.yml; this script creates an equivalent in-toto
# SLSA predicate for the same subject file so CI can verify the artifact hashing
# contract without network, Rekor, or GitHub OIDC.
set -euo pipefail

subjects="${1:-}"
out="${2:-}"
builder="${3:-https://github.com/slsa-framework/slsa-github-generator/generic@v1}"

if [ -z "$subjects" ] || [ -z "$out" ] || [ ! -s "$subjects" ]; then
  echo "usage: $0 <subjects-file> <out.intoto.jsonl> [builder-id]" >&2
  exit 2
fi

python3 - "$subjects" "$out" "$builder" <<'PY'
import json
import pathlib
import sys
import time

subjects_path = pathlib.Path(sys.argv[1])
out_path = pathlib.Path(sys.argv[2])
builder = sys.argv[3]

subjects = []
for raw in subjects_path.read_text().splitlines():
    if not raw.strip():
        continue
    parts = raw.split(None, 1)
    if len(parts) != 2:
        raise SystemExit(f"bad SLSA subject line {raw!r}: want '<sha256>  <name>'")
    digest, name = parts
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise SystemExit(f"bad sha256 digest for {name!r}: {digest!r}")
    subjects.append({"name": name.strip(), "digest": {"sha256": digest}})

if not subjects:
    raise SystemExit("no SLSA subjects to attest")

statement = {
    "_type": "https://in-toto.io/Statement/v0.1",
    "predicateType": "https://slsa.dev/provenance/v0.2",
    "subject": subjects,
    "predicate": {
        "builder": {"id": builder},
        "buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
        "invocation": {
            "configSource": {
                "uri": "git+https://github.com/ctlplne/trstctl",
                "entryPoint": ".github/workflows/release.yml",
            },
            "parameters": {"dryRun": True},
            "environment": {"local_dry_run": True},
        },
        "metadata": {
            "buildInvocationID": f"local-dry-run-{int(time.time())}",
            "completeness": {"parameters": True, "environment": False, "materials": False},
            "reproducible": False,
        },
        "materials": [{"uri": "git+https://github.com/ctlplne/trstctl"}],
    },
}

out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(statement, sort_keys=True, separators=(",", ":")) + "\n")
PY
