# Plugins (`plugins/ca`, `plugins/connectors`)

These directories are the **drop-in location for third-party / community WASM
plugins** — CA integrations (`ca/`) and deployment connectors (`connectors/`) that
are *not* part of the core build. A plugin here is a WASM module loaded by the
plugin host (`internal/pluginhost`, wazero) under an explicit **capability grant**
and admitted only after passing the **conformance suite**.

They are intentionally near-empty in this repository, and that is **not** a gap to
be confused with the shipped integrations:

- **First-party CAs and connectors do not live here.** The ~9 CA integrations
  (`internal/ca/…`) and ~10 deployment connectors (`internal/connector/…`) ship as
  **trusted in-process Go code**, by design — see the
  [plugin trust model & blast radius](../docs/security/threat-model.md) and
  [limitations](../docs/limitations.md). They are not WASM-sandboxed.
- **This directory is for the isolated path.** A plugin dropped here runs in the
  WASM sandbox: no ambient capabilities, only the host functions its grant permits,
  and a fault is contained to its own runtime (the host holds no DB pool or signer
  handle — proven by `internal/pluginhost`'s containment test). That isolation is
  what makes it safe to load code the core team did not write.

## Authoring a plugin

See [`docs/guides/plugin-authoring.md`](../docs/guides/plugin-authoring.md). In
short: build a WASM module that exports the host's run entrypoint, declare the
minimal capability grant it needs, and validate it against the conformance suite
before distribution.

Built `.wasm` artifacts are **not** committed to this repository; they are produced
by each plugin's own build and distributed separately.
