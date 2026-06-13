# trustctl agent on Windows

The trustctl agent runs on Windows as a Service Control Manager service and
installs certificates into the Windows certificate store (CryptoAPI / CNG). This
directory holds the MSI installer definition; the agent binary itself is built
from `cmd/trustctl-agent`.

## Build, sign, and publish

```sh
make dist-windows
```

This cross-compiles `trustctl-agent.exe` for `windows/amd64`, copies the WiX
source, optionally Authenticode-signs the binary, builds the MSI (when a WiX
toolchain is present), and writes a `SHA256SUMS` manifest into `dist/`.

- **Signing.** Set `SIGN_PFX` (and `SIGN_PASS`) to a code-signing PKCS#12 to
  Authenticode-sign the binary with `osslsigncode` (Linux/macOS) — on Windows,
  sign with `signtool`. Without a signing identity the binary is left unsigned.
- **MSI.** `make dist-windows` builds the MSI with `wixl` (msitools) when
  available; on Windows use the WiX Toolset (`candle` + `light`) against
  `trustctl-agent.wxs`. Sign the resulting `.msi` the same way as the binary.
- **SHA-256.** `dist/SHA256SUMS` is the published checksum manifest
  (`sha256sum -c` compatible). The same manifest can be produced
  programmatically via `internal/dist.Checksums`.

CI exercises this on two jobs: `windows cross-build` (Linux,
`make windows-build`: `GOOS=windows go build ./... && go vet ./...`) for a fast
guard, and `windows / test + MSI` (a real `windows-latest` runner) which runs
the Windows agent tests — including a round-trip against the live per-user
certificate store — and builds the MSI with the WiX Toolset.

## Install / uninstall

The MSI registers the service automatically (its `ServiceInstall` /
`ServiceControl` elements, generated from the same `winservice.Spec` the agent
uses). The agent can also manage the service directly:

```bat
trustctl-agent.exe --service=install --enroll-url https://cp:8443/enroll ^
    --ca-bundle C:\ProgramData\trustctl\ca-bundle.pem --server cp:9443 --name %COMPUTERNAME%
trustctl-agent.exe --service=uninstall
```

`--service=install` registers an auto-start `LocalSystem` service whose command
line reproduces the supplied flags with `--service=run`; the SCM then starts the
agent, which enrolls, maintains mutual TLS, and installs and rotates credentials.

## Certificate store destination

The agent installs certificates into a Windows system store — for example the
machine Personal store, `LocalMachine\MY` — associating the private key
non-exportable under the Microsoft Software Key Storage Provider (CNG). The
CryptoAPI/CNG backend (`internal/agent/destination/certstore`, build-tagged for
Windows) installs a cert-with-key by encoding a transient PKCS#12 in the crypto
boundary (`internal/crypto/pfx`) and importing it with `PFXImportCertStore`,
which persists and links the key. The `windows / test + MSI` CI job runs this
end-to-end against the per-user store on a real Windows runner; the
platform-neutral contract is also exercised on every platform by the in-process
`Memory` store.
