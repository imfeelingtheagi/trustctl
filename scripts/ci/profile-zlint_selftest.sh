#!/usr/bin/env bash
# Self-test for profile-zlint.sh. It stubs zlint so the CI gate proves both sides:
# normal generated fixtures pass, and a deliberately malformed generated leaf
# fixture fails as soon as the external linter reports an error-level result.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin" "$tmp/good" "$tmp/bad" "$tmp/out-good" "$tmp/out-bad"
cat >"$tmp/bin/zlint" <<'SH'
#!/usr/bin/env bash
cert="${@: -1}"
case "$cert" in
  *bad-generated-leaf.pem)
    printf '{"lints":{"e_profile_regression":{"result":"error","details":"malformed generated leaf"}}}\n'
    ;;
  *)
    printf '{"lints":{"e_profile_regression":{"result":"pass"}}}\n'
    ;;
esac
SH
chmod +x "$tmp/bin/zlint"

printf '%s\n' '-----BEGIN CERTIFICATE-----' 'FAKECA' '-----END CERTIFICATE-----' >"$tmp/served-ca.pem"
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'GOODLEAF' '-----END CERTIFICATE-----' >"$tmp/good/served-leaf-full-profile.pem"
cp "$tmp/good/served-leaf-full-profile.pem" "$tmp/bad/served-leaf-full-profile.pem"
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'BADLEAF' '-----END CERTIFICATE-----' >"$tmp/bad/bad-generated-leaf.pem"

PATH="$tmp/bin:$PATH" "$here/profile-zlint.sh" "$tmp/served-ca.pem" "$tmp/good" "$tmp/out-good" >/dev/null
[[ -s "$tmp/out-good/served-ca.zlint.json" ]]
[[ -s "$tmp/out-good/served-leaf-full-profile.zlint.json" ]]

set +e
PATH="$tmp/bin:$PATH" "$here/profile-zlint.sh" "$tmp/served-ca.pem" "$tmp/bad" "$tmp/out-bad" >/dev/null 2>"$tmp/bad.err"
status="$?"
set -e

if [[ "$status" -eq 0 ]]; then
  echo "profile-zlint accepted a generated leaf fixture with an external-linter error"
  exit 1
fi
if ! grep -q 'bad-generated-leaf' "$tmp/bad.err"; then
  echo "profile-zlint failure did not identify the malformed generated leaf fixture"
  cat "$tmp/bad.err"
  exit 1
fi
[[ -s "$tmp/out-bad/bad-generated-leaf.zlint.json" ]]

echo "ALL SELF-TESTS PASSED"
