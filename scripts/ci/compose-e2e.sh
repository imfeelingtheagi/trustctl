#!/usr/bin/env bash
#
# scripts/ci/compose-e2e.sh — EXC-GATE-01 end-to-end gate against the running stack.
#
# The caller (the CI job) brings up the compose eval stack and exports BASE_URL
# (e.g. https://localhost:8443). This proves the SHIPPED deployment works end to end
# against real external PostgreSQL + NATS + the separate isolated signer process:
#   1. the control-plane container boots and serves (/readyz),
#   2. served auth + RLS hold (unauthenticated 401; a bootstrapped token 200),
#   3. a real event-sourced mutation round-trips (create owner -> read it back),
#   4. the served issuance lifecycle runs: issue a cert, RETRY the issuing transition
#      with the same Idempotency-Key and assert NO second credential (AN-5), revoke,
#   5. the served PKI surfaces are mounted: ACME /directory advertises newOrder +
#      revokeCert, the OCSP responder answers for the tenant, and EST /cacerts hands
#      back the issuing CA chain (which the CI job then lints with zlint).
#
# The bootstrap API token is minted INSIDE the running control-plane container
# (`docker compose exec ... trustctl token create`): the compose Postgres has no host
# port and the token must land in the same database the server reads, so the
# network-trust-free first-run bootstrap (WIRE-002) runs where the DSN resolves. This
# is exactly the operator's real first-run step.
#
# Requires: docker compose (the eval stack up), a reachable served control plane
# (BASE_URL), curl, jq, openssl.
set -euo pipefail

BASE_URL="${BASE_URL:?set BASE_URL to the served control plane, e.g. https://localhost:8443}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker/docker-compose.yml}"
COMPOSE=(docker compose -f "$COMPOSE_FILE")
TENANT="${TENANT:-$(cat /proc/sys/kernel/random/uuid)}"
CURL=(curl -fsS -k)          # -k: the eval stack serves a self-signed cert (TLS internal mode)
Q=(curl -s -k -o /dev/null -w '%{http_code}')

say()  { printf '\n>> %s\n' "$*"; }
fail() { printf '::error::compose-e2e: %s\n' "$*"; exit 1; }

say "1. control plane is serving (/readyz)"
code=$("${Q[@]}" "$BASE_URL/readyz" || true)
[ "$code" = "200" ] || fail "/readyz returned '$code' (control plane not serving on $BASE_URL)"

say "2. served auth + RLS: unauthenticated is rejected, a bootstrapped token is accepted"
code=$("${Q[@]}" "$BASE_URL/api/v1/owners" || true)
[ "$code" = "401" ] || fail "unauthenticated GET /api/v1/owners returned '$code', want 401 (auth not enforced)"
# A first-run, network-trust-free token, minted INSIDE the control-plane container so it
# lands in the same Postgres the server reads (the compose DB has no host port). Grant
# certs:issue for this throwaway EVAL run so the gate can drive served issuance
# (production withholds it — the loaded-gun guard, RED-004).
TOKEN=$("${COMPOSE[@]}" exec -T trustctl /usr/local/bin/trustctl token create \
          --tenant "$TENANT" --tenant-name e2e \
          --scopes "owners:read,owners:write,issuers:read,issuers:write,identities:read,identities:write,certs:read,certs:write,certs:issue" \
        2>/dev/null | grep -oE 'tt_[A-Za-z0-9_.-]+' | head -1)
[ -n "${TOKEN:-}" ] || fail "bootstrap token mint (docker compose exec trustctl token create) produced no tt_ token"
AUTH=(-H "Authorization: Bearer ${TOKEN}")
code=$("${Q[@]}" "${AUTH[@]}" "$BASE_URL/api/v1/owners" || true)
[ "$code" = "200" ] || fail "bootstrapped GET /api/v1/owners returned '$code', want 200"

say "3. event-sourced mutation round-trips (create owner -> read back)"
OWNER=$("${CURL[@]}" "${AUTH[@]}" -XPOST "$BASE_URL/api/v1/owners" -d '{"name":"e2e","kind":"team"}' | jq -r .id)
[ -n "$OWNER" ] && [ "$OWNER" != "null" ] || fail "owner create returned no id"
"${CURL[@]}" "${AUTH[@]}" "$BASE_URL/api/v1/owners/$OWNER" >/dev/null || fail "could not read back the created owner $OWNER"

say "4. served issuance lifecycle: issue -> idempotent retry -> revoke"
ISSUER=$("${CURL[@]}" "${AUTH[@]}" -XPOST "$BASE_URL/api/v1/issuers" -d '{"name":"e2e-ca","kind":"internal"}' | jq -r .id)
IDENT=$("${CURL[@]}" "${AUTH[@]}" -XPOST "$BASE_URL/api/v1/identities" \
          -d "{\"owner_id\":\"$OWNER\",\"issuer_id\":\"$ISSUER\",\"subject\":\"e2e.example\",\"kind\":\"x509\"}" | jq -r .id)
[ -n "$IDENT" ] && [ "$IDENT" != "null" ] || fail "identity create returned no id"
IDEM="e2e-$(date +%s)-$RANDOM"
issue() { "${CURL[@]}" "${AUTH[@]}" -H "Idempotency-Key: $IDEM" -XPOST \
            "$BASE_URL/api/v1/identities/$IDENT/transitions" -d '{"to":"issued"}'; }
issue >/dev/null || fail "transition->issued failed"
# inventory now holds exactly one cert for this identity; a retried transition with the
# same Idempotency-Key must NOT mint a second one (AN-5).
n1=$("${CURL[@]}" "${AUTH[@]}" "$BASE_URL/api/v1/certificates" | jq '[.items[]? | select(.subject=="e2e.example")] | length')
issue >/dev/null || fail "idempotent retry of transition->issued failed"
n2=$("${CURL[@]}" "${AUTH[@]}" "$BASE_URL/api/v1/certificates" | jq '[.items[]? | select(.subject=="e2e.example")] | length')
[ "${n1:-0}" -ge 1 ] || fail "no certificate minted for the identity (got $n1)"
[ "$n1" = "$n2" ] || fail "AN-5 VIOLATED: retry with same Idempotency-Key minted another credential ($n1 -> $n2)"
say "   idempotent issuance holds: $n1 == $n2 cert(s)"
"${CURL[@]}" "${AUTH[@]}" -XPOST "$BASE_URL/api/v1/identities/$IDENT/transitions" \
  -d '{"to":"revoked","reason":"e2e"}' >/dev/null || fail "transition->revoked failed"

say "5. served PKI surfaces are mounted: ACME directory + OCSP responder + EST cacerts"
"${CURL[@]}" "$BASE_URL/directory" | jq -e '.newOrder and .revokeCert' >/dev/null || fail "served ACME /directory missing newOrder/revokeCert"
ocsp=$("${Q[@]}" -XPOST -H 'Content-Type: application/ocsp-request' --data-binary $'\x30\x03\x02\x01\x00' "$BASE_URL/ocsp/$TENANT" || true)
case "$ocsp" in 2??|400) say "   served OCSP responder answered (HTTP $ocsp)";; *) fail "served OCSP responder /ocsp/$TENANT did not answer (HTTP $ocsp)";; esac
# Pull the issuing CA chain the deployment serves (RFC 7030 §4.1 cacerts, unauthenticated)
# and write it as PEM for the zlint conformance step. base64 PKCS#7 -> DER -> PEM certs.
if "${CURL[@]}" "$BASE_URL/.well-known/est/cacerts" 2>/dev/null | base64 -d 2>/dev/null \
     | openssl pkcs7 -inform DER -print_certs -out served-ca.pem 2>/dev/null \
   && [ -s served-ca.pem ]; then
  say "   served EST /cacerts returned the issuing CA chain -> served-ca.pem ($(grep -c 'BEGIN CERTIFICATE' served-ca.pem) cert(s))"
else
  fail "served EST /cacerts did not return a parseable CA chain (PKI surface not mounted?)"
fi

say "EXC-GATE-01 e2e PASS: deploy -> served auth -> mutation -> issue/idempotent/revoke -> ACME+OCSP+cacerts mounted"
