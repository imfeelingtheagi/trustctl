# internal/protocols — issuance & enrollment protocol servers

This tree groups the credential-issuance/enrollment protocol servers, one per
subpackage: `acme` (RFC 8555) + `ari` (RFC 9773), `est` (RFC 7030), `scep` (RFC 8894),
`cmp` (RFC 4210/6712), `spiffe` (the SPIFFE Workload API), and `ssh` (the SSH CA). This
file captures the conventions every subpackage shares; the root `CLAUDE.md` is canonical
for architecture.

## Untrusted input is the threat model here

Every one of these parses bytes off the wire from a client we do not control. So:

- **Fuzz every parser that touches untrusted input** and wire it for OSS-Fuzz / the CI
  fuzz-smoke job (root `CLAUDE.md` §6). A new parser without a `FuzzXxx` target fails the
  coverage guard (`TestEveryUntrustedParserIsFuzzed`).
- **Property-based tests** for each protocol parser, and **differential tests** against an
  independent implementation where one exists: ACME vs **Pebble** (CI job), EST vs
  OpenSSL's PKCS#7 (every `make test`; libest on the CI backstop), CMP's PKIMessage vs
  OpenSSL's ASN.1 parser. Don't remove a differential to go green; ratchet up.
- **Fail closed.** A malformed/oversized/unauthenticated request is rejected, never
  best-effort accepted. Validators reject by default (no accept-everything path in the
  production build — see `acme` `dvmethod.go`).

## Crypto & custody

All signing routes through `internal/crypto` (AN-3); these packages import no `crypto/*`
directly and never hold a CA private key (it lives in the signer, AN-4).

## Served-vs-library honesty (don't over-claim)

These are **complete, tested implementations, NOT placeholders** — but **none is yet
mounted on the served control-plane listener** of the running binary. Serving them (with
auth + tenant scoping) is tracked as **EXC-WIRE-02**. Keep `docs/limitations.md`
"Protocols" and each subpackage's `doc.go` honest: a `doc.go` must not call a complete
protocol a placeholder, and the docs must not claim a protocol is served end-to-end while
nothing under `internal/server`/`internal/api`/`cmd` imports it
(`go test ./docs/...` enforces both directions).
