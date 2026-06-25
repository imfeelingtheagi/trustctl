# ADR: crypto-agility guardrail and runtime-engine non-goals

- **Status:** Accepted.
- **Scope:** Internal architecture decision record. This is design hygiene to
  reduce infringement surface; it is not legal advice and not a freedom-to-operate opinion.
- **Drives:** PQC, KMS, HSM, signing-service, and crypto-backend work.

## Decision

trstctl's crypto-agility model is **compile-time Go interfaces plus dependency injection
behind the AN-3 `internal/crypto` boundary**.

The simple version: callers do not load crypto tools at runtime. They ask a typed
interface (`Backend`, `KeyGenerator`, `Signer`, `DigestSigner`) to do work. The
binary assembler chooses the concrete implementation by ordinary Go construction
and dependency injection. Adding ML-DSA, SLH-DSA, KMS, HSM, or software signing
means implementing those interfaces inside `internal/crypto` or the isolated
signer path, then injecting that implementation at assembly time.

This follows long-standing interface/provider patterns, including:

- Go's standard `crypto.Signer` interface;
- Java JCA provider interfaces;
- OpenSSL ENGINE/provider style boundaries;
- PKCS#11's slot/token/session interface model.

Those examples are named only to explain the prior-art engineering pattern:
callers program to stable interfaces, and concrete providers sit behind that
contract.

## Deliberately not this

trstctl deliberately does **not** implement the runtime-engine architecture
described by US 12,340,262 and the InfoSec Global / Keyfactor crypto-agility
patent family. In particular:

| Runtime-engine element | trstctl decision |
| --- | --- |
| A runtime crypto engine that loads DLLs, Go `plugin` providers, or equivalent provider modules at runtime. | Forbidden. Crypto providers are compiled Go code behind `internal/crypto` interfaces and are injected when the binary is assembled. |
| A runtime step that registers a new crypto suite into a mutable crypto library/engine registry. | Forbidden. Algorithms are typed values and backend implementations. There is no runtime-mutable global provider, engine, backend, or suite registry. |
| A separate control entity that feeds runtime policy into crypto providers to select algorithms. | Forbidden. Policy can decide whether a caller may request an operation, and it may pass an algorithm parameter to the caller. It must not import into or control `internal/crypto`, `internal/signing`, or `cmd/trstctl-signer`. |

## Mechanical guard

`tools/trstctllint/cryptoagility` enforces this ADR on the crypto/signer boundary.
It fails CI if guarded packages introduce:

- an import of Go's `plugin` package;
- an import of `trstctl.com/trstctl/internal/policy`;
- a package-level mutable provider/engine/backend registry;
- a `RegisterCryptoSuite` / provider / engine / backend / algorithm function shape.

The analyzer is registered in `tools/trstctllint/main.go`, so `make lint` and
`go test ./tools/trstctllint/...` exercise it for every later card.

## Consequences

- PQC and KMS/HSM work stays inside the compile-time interface boundary. This is
  boring on purpose: boring boundaries are easier to audit.
- Runtime extension remains the job of the WASM plugin host for deployment and CA
  integrations, not a way to load cryptographic primitive providers into the
  signer.
- If a future card appears to require a runtime crypto engine, runtime suite
  registration, or policy-controlled crypto provider selection, that card is an
  architecture decision and must be blocked for human review instead of built.
