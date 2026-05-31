# Configuration

certctl resolves its configuration from, in increasing precedence: built-in
defaults, an optional JSON config file (`CERTCTL_CONFIG_FILE`), and environment
variables. The configuration is validated on boot — a bad combination **fails
fast** rather than starting half-configured.

Inspect the effective configuration at any time (credentials are redacted):

```bash
certctl -check-config
```

## Server

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_SERVER_ADDR` | `:8443` | Address the control plane listens on. |
| `CERTCTL_SERVER_TLS_MODE` | `internal` | `internal` (self-signed), `file` (operator cert), or `disabled` (plaintext, dev only). |
| `CERTCTL_SERVER_TLS_CERT_FILE` | — | Server certificate chain (PEM); **required** when `mode=file`. |
| `CERTCTL_SERVER_TLS_KEY_FILE` | — | Server private key (PEM); **required** when `mode=file`. |
| `CERTCTL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `CERTCTL_LOG_FORMAT` | `json` | `json` or `text`. |

### Transport encryption (TLS)

The control plane serves over **TLS by default** so no credential, token, or
session ever travels in cleartext.

- **`internal`** (default) — the control plane presents a self-signed certificate
  it generates at startup, covering `localhost`, `127.0.0.1`, the container
  hostname, and the Compose service name `certctl`. Clients must trust it (or use
  `curl -k`); suitable for evaluation and internal/air-gapped use.
- **`file`** — the control plane presents an operator-provided certificate and
  key. Use this in production with a certificate from your CA. A missing or
  malformed file fails fast at startup rather than falling back to plaintext.
- **`disabled`** — plaintext HTTP. **Local development only**; the server logs a
  loud warning at startup. If you terminate TLS at a reverse proxy instead,
  configure the proxy to **strip inbound `X-*` identity headers** — certctl does
  not trust them (R1.2), so a proxy cannot reintroduce a header-auth bypass.

The mutual-TLS transport between the control plane and the isolated signing
service (AN-4) is independent of this setting and always enabled.

## Datastores

certctl stores its read state in **PostgreSQL** (the source-of-truth event log
lives in **NATS JetStream**). Both can run **bundled** for single-node evaluation
or **external** for production. PostgreSQL is the datastore in every deployment
mode — there is no SQLite path.

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_POSTGRES_MODE` | `bundled` | `bundled` or `external`. |
| `CERTCTL_POSTGRES_DSN` | — | Connection string; **required** when external. |
| `CERTCTL_POSTGRES_DATA_DIR` | `data/postgres` | Data directory when bundled. |
| `CERTCTL_NATS_MODE` | `embedded` | `embedded` or `external`. |
| `CERTCTL_NATS_URL` | — | NATS URL; **required** when external. |
| `CERTCTL_NATS_STORE_DIR` | `data/nats` | JetStream store directory when embedded. |

### External datastores

To point certctl at managed PostgreSQL and NATS, switch both to external mode and
supply their connection strings:

```bash
export CERTCTL_POSTGRES_MODE=external
export CERTCTL_POSTGRES_DSN='postgres://user:pass@db.internal:5432/certctl?sslmode=require'
export CERTCTL_NATS_MODE=external
export CERTCTL_NATS_URL='nats://nats.internal:4222'
```

When a mode is `external`, its connection string is mandatory; certctl refuses to
start without it. This is the same wiring the Compose stack uses, so the
evaluation path and a production deployment exercise identical code.

## Lifecycle

How far ahead of expiry certctl renews and alerts. Values are Go durations.

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_LIFECYCLE_RENEW_BEFORE` | `720h` (30 days) | Renew this far before expiry. |
| `CERTCTL_LIFECYCLE_ALERT_BEFORE` | `336h` (14 days) | Alert this far before expiry. |

## Telemetry

Telemetry is **off by default** and never sends anything unless you opt in. When
enabled, it sends only coarse, anonymized, non-PII data.

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_TELEMETRY_ENABLED` | `false` | Set `true` to opt in. A malformed value is ignored (stays off). |
| `CERTCTL_TELEMETRY_ENDPOINT` | `https://telemetry.certctl.io/v1/usage` | Where reports go; must be `https`. |
| `CERTCTL_TELEMETRY_INTERVAL` | `24h` | Reporting interval. |

See [Telemetry](telemetry.md) for exactly what is and is not collected.

## Config file

Any of the above can also be set in a JSON file named by `CERTCTL_CONFIG_FILE`;
environment variables override file values, which override defaults.

```json
{
  "server": { "addr": ":8443" },
  "postgres": { "mode": "external", "dsn": "postgres://..." },
  "nats": { "mode": "external", "url": "nats://..." },
  "telemetry": { "enabled": false }
}
```
