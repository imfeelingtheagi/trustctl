#!/usr/bin/env bash
#
# scripts/ci/compose-e2e.sh — EXC-GATE-01 end-to-end gate against the running stack.
#
# Brings the served control plane up (the caller starts the compose stack and exports
# BASE_URL, e.g. https://localhost:8443), then proves the full issuance lifecycle end
# to end through the SERVED API: mint a first token, issue a real certificate, RETRY
# the issuing transition with the SAME Idempotency-Key and assert NO second credential
# is minted (AN-5), then revoke it and assert the served OCSP responder reports it
# revoked. This is the gate the audit could not run without Docker; it runs in CI.
#
# Requires: a reachable served control plane (BASE_URL), the trustctl binary on PATH
# (for the network-trust-free `token create` bootstrap), curl, jq, openssl.
# Exit 0 = the lifecycle holds end to end; non-zero = a gap.
set -euo pipefail

BASE_URL="${BASE_URL:?set BASE_URL to the served control plane, e.g. https://localhost:8443}"
TENANT="${TENANT:-$(uuidgen | tr 'A-Z' 'a-z')}"
CURL=(curl -fsS --cacert "${TRUSTCTL_CA:-/dev/null}" -k) # -k tolerated only for the eval self-signed stack

say() { printf '\n>> %s\n' "$*"; }
fail() { printf '::error::%s\n' "$*"; exit 1; }

say "bootstrap a first tenant-scoped API token (WIRE-002 path)"
TOKEN="$(trustctl token create --tenant "$TENANT" --quiet 2>/dev/null || trustctl token create --tenant "$TENANT" | awk '/tt_/{print $NF}')"
[ -n "${TOKEN:-}" ] || fail "bootstrap token mint produced no token"
AUTH=(-H "Authorization: Bearer ${TOKEN}")

say "create owner -> issuer -> identity"
OWNER=$("${CURL[@]}" "${AUTH[@]}" -XPOST "$BASE_URL/api/v1/owners"  -d '{"name":"e2e"}'                | jq -r .id)
ISSUER=$("${CURL[@]}" "${AUTH[@]}" -XPOST "$BASE_URL/api/v1/issuers" -d '{"name":"e2e-ca","kind":"internal"}' | jq -r .id)
IDENT=$("${CURL[@]}" "${AUTH[@]}" -XPOST "$BASE_URL/api/v1/identities" \
          -d "{\"owner_id\":\"$OWNER\",\"issuer_id\":\"$ISSUER\",\"subject\":\"e2e.example\"}" | jq -r .id)

say "issue (transition -> issued) with an Idempotency-Key, then RETRY the same key"
IDEM="e2e-$(date +%s)-$RANDOM"
issue() { "${CURL[@]}" "${AUTH[@]}" -H "Idempotency-Key: $IDEM" -XPOST \
            "$BASE_URL/api/v1/identities/$IDENT/transitions" -d '{"to":"issued"}'; }
C1=$(issue | jq -r '.certificate_id // .certificate.serial // .serial')
C2=$(issue | jq -r '.certificate_id // .certificate.serial // .serial')
[ -n "$C1" ] || fail "issuance returned no certificate"
[ "$C1" = "$C2" ] || fail "AN-5 VIOLATED: retry with same Idempotency-Key minted a different credential ($C1 != $C2)"
say "idempotent issuance holds: $C1 == $C2"

say "revoke and confirm the served OCSP responder reports revoked"
"${CURL[@]}" "${AUTH[@]}" -XPOST "$BASE_URL/api/v1/identities/$IDENT/transitions" -d '{"to":"revoked","reason":"e2e"}' >/dev/null
# Pull the issued leaf + issuer, ask the served OCSP responder.
"${CURL[@]}" "${AUTH[@]}" "$BASE_URL/api/v1/certificates/$C1?format=pem" -o leaf.pem 2>/dev/null \
  || "${CURL[@]}" "${AUTH[@]}" "$BASE_URL/api/v1/certificates/$C1" | jq -r .pem > leaf.pem
"${CURL[@]}" "$BASE_URL/api/v1/ca/$ISSUER/cert?format=pem" -o issuer.pem 2>/dev/null || true
STATUS=$(openssl ocsp -issuer issuer.pem -cert leaf.pem -url "$BASE_URL/ocsp/$TENANT" -noverify -resp_text 2>/dev/null | grep -iEo 'Cert Status: (good|revoked)' | head -1 || true)
echo "OCSP says: ${STATUS:-<none>}"
case "$STATUS" in
  *revoked) say "EXC-GATE-01 e2e PASS: issue -> idempotent-retry -> revoke -> OCSP revoked" ;;
  *) fail "served OCSP did not report the revoked cert as revoked (got: ${STATUS:-none})" ;;
esac
