# trstctl Java SDK

`trstctl-sdk` is the Java client for the served trstctl OpenAPI contract. The
runtime uses only the JDK: `java.net.http` for transport plus a small JSON codec for
the request and response shapes used by the supported helpers.

## Use

```java
import com.trstctl.sdk.PkiSecret;
import com.trstctl.sdk.Secret;
import com.trstctl.sdk.TrstctlClient;

TrstctlClient client = TrstctlClient.fromEnv();

PkiSecret issued = client.issuePkiSecret(
    "payments.service",
    900,
    "payments-pki-2026-06-25"
);
Secret created = client.createSecret(
    "apps/payments/api-token",
    "initial-fixture-value",
    "payments-secret-create"
);

System.out.println(issued.serial() + " " + created.version());
```

`TrstctlClient.fromEnv()` reads:

- `TRSTCTL_SERVER`
- `TRSTCTL_TOKEN`
- `TRSTCTL_TENANT`

The client sends `Authorization: Bearer ...` when a token is present, sends
`X-Tenant-ID` when a tenant hint is present, generates stable idempotency keys for
mutations when the caller does not provide one, parses RFC 7807 `problem+json`
responses into `ProblemException`, and retries `429`, `502`, `503`, and `504` while
honoring `Retry-After`.

## Test

```bash
clients/sdk/java/scripts/run_tests.sh
```

The repository-level `make sdk-test` target runs this script. CI sets
`TRSTCTL_REQUIRE_JAVA_SDK=1` so the Java SDK cannot silently skip when a JDK is
missing.
