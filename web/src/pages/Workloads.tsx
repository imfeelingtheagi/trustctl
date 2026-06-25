import { UnavailableState } from "@/components/StatePrimitives";
import { PageHeader } from "@/components/PageHeader";

interface LeaseRow {
  credential: string;
  ttl: string;
  evidence: string;
  expiry: string;
  revoke: string;
}

interface AttestationRow {
  evidence: string;
  fixture: string;
  result: string;
  reason: string;
}

interface BrokerRow {
  field: string;
  value: string;
}

const leaseRows: LeaseRow[] = [
  {
    credential: "X.509-SVID",
    ttl: "15 minute default TTL, 5 minute renew window",
    evidence: "SPIFFE selector match plus attestation digest",
    expiry: "lease expires unless workload re-attests",
    revoke: "revoke-now is explained, not executable",
  },
  {
    credential: "JWT-SVID",
    ttl: "5 minute audience-bound token TTL",
    evidence: "audience, SPIFFE ID, and selector digest",
    expiry: "audience-specific token dies without renewal",
    revoke: "deny new minting by policy; no live revocation button",
  },
  {
    credential: "PKI secret bundle",
    ttl: "30 minute certificate plus key bundle",
    evidence: "secret name, profile, and attestation digest",
    expiry: "bundle must be reissued through served PKI secret path",
    revoke: "manual identity revoke is separate from this lease preview",
  },
];

const attestationRows: AttestationRow[] = [
  {
    evidence: "TPM quote",
    fixture: "accepted",
    result: "PCR digest matches the tenant policy",
    reason: "hardware-rooted proof, raw quote redacted",
  },
  {
    evidence: "AWS IID",
    fixture: "rejected",
    result: "account or region does not match policy",
    reason: "wrong cloud boundary",
  },
  {
    evidence: "GCP instance identity",
    fixture: "accepted",
    result: "service account and project match policy",
    reason: "metadata signature verified by library code",
  },
  {
    evidence: "Azure IMDS",
    fixture: "expired",
    result: "evidence timestamp is outside the freshness window",
    reason: "stale attestation",
  },
  {
    evidence: "Kubernetes SAT",
    fixture: "wrong-tenant",
    result: "namespace or service account maps to a different tenant",
    reason: "tenant isolation guardrail",
  },
  {
    evidence: "GitHub OIDC",
    fixture: "rejected",
    result: "repository claim is not in the allowed list",
    reason: "workflow provenance mismatch",
  },
];

const brokerRows: BrokerRow[] = [
  { field: "Agent identity", value: "spiffe://tenant/ai/build-agent" },
  { field: "Allowed tools and scopes", value: "mcp:read-only, secrets:read:ci, certs:issue:short" },
  { field: "Issued credentials", value: "short lease only; no standing secret" },
  { field: "Attestation", value: "OIDC subject, workload digest, and policy version" },
  { field: "Expiry", value: "15 minute max lease with no silent extension" },
  { field: "Audit", value: "credential lease audit event" },
];

export function Workloads() {
  return (
    <section aria-labelledby="workload-heading" className="grid gap-6">
      <PageHeader
        titleId="workload-heading"
        title="Workload identity"
        description="Served SPIFFE, attested X.509-SVID, approval-gated ephemeral JIT, broker, and PKI-secret paths can issue short-lived credentials. The console keeps raw proofs out of the browser and renders the remaining lease-ledger workflow as a disclosure fixture."
      />

      <UnavailableState title="Browser lease controls are not served yet">
        Lease state and browser-side approval controls are not served yet. Attested issuance, approval-gated ephemeral JIT issuance, and broker minting are
        available through REST and CLI, so no live issue, revoke, approve, or mint controls are rendered here.
      </UnavailableState>

      <section aria-labelledby="lease-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="lease-heading" className="text-title font-semibold">
            Ephemeral credential leases
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            A lease is a short promise: a workload proves who it is, receives one credential class, and loses it at expiry unless it re-attests.
          </p>
        </div>
        <ol className="grid gap-2 rounded-md border border-border p-3 text-sm md:grid-cols-3">
          <li>
            <p className="font-medium">00:00 issued</p>
            <p className="text-muted-foreground">policy and attestation digest bind the lease</p>
          </li>
          <li>
            <p className="font-medium">00:45 renew window</p>
            <p className="text-muted-foreground">workload must re-attest before renewal</p>
          </li>
          <li>
            <p className="font-medium">01:00 expires</p>
            <p className="text-muted-foreground">credential is no longer trusted by policy</p>
          </li>
        </ol>
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[56rem]">
            <caption className="sr-only">Ephemeral credential lease fixture</caption>
            <thead>
              <tr>
                <th scope="col">Credential class</th>
                <th scope="col">TTL policy</th>
                <th scope="col">Attestation evidence</th>
                <th scope="col">Lease expiry</th>
                <th scope="col">Revoke-now posture</th>
              </tr>
            </thead>
            <tbody>
              {leaseRows.map((row) => (
                <tr key={row.credential} className="align-top">
                  <td className="font-medium">{row.credential}</td>
                  <td>{row.ttl}</td>
                  <td>{row.evidence}</td>
                  <td>{row.expiry}</td>
                  <td>{row.revoke}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <UnavailableState title="Ephemeral JIT issuance is REST and CLI only">
          Approval-gated ephemeral issuance is served at POST /api/v1/ephemeral and POST /api/v1/ephemeral/&lt;request-id&gt;/approvals, plus the ephemeral
          issue and ephemeral approve CLI commands. This console does not collect live proof payloads or approval actions.
        </UnavailableState>
      </section>

      <section aria-labelledby="attestation-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="attestation-heading" className="text-title font-semibold">
            Workload attestation chain
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Attestation proves the workload and its platform. This preview keeps raw tokens and signed evidence out of the browser and shows only decision
            fixtures.
          </p>
        </div>
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[54rem]">
            <caption className="sr-only">Workload attestation fixtures</caption>
            <thead>
              <tr>
                <th scope="col">Evidence</th>
                <th scope="col">Fixture</th>
                <th scope="col">Decision</th>
                <th scope="col">Reason</th>
              </tr>
            </thead>
            <tbody>
              {attestationRows.map((row) => (
                <tr key={`${row.evidence}:${row.fixture}`} className="align-top">
                  <td className="font-medium">{row.evidence}</td>
                  <td>{row.fixture}</td>
                  <td>{row.result}</td>
                  <td>{row.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <UnavailableState title="Raw attestation evidence stays out of the browser">
          Accepted, rejected, expired, and wrong-tenant fixtures show the served decision shape. Use the attested-issuance or ephemeral REST/CLI paths for live
          proofs so raw tokens and signed evidence never enter this console.
        </UnavailableState>
      </section>

      <section aria-labelledby="broker-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="broker-heading" className="text-title font-semibold">
            AI-agent / NHI broker
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            A broker turns an agent identity plus policy into a short credential lease. Broker issuance is served through REST and CLI; this fixture shows the
            scope and audit shape without collecting live proofs in the browser.
          </p>
        </div>
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[42rem]">
            <caption className="sr-only">AI agent broker lifecycle fixture</caption>
            <tbody>
              {brokerRows.map((row) => (
                <tr key={row.field} className="align-top">
                  <th scope="row" className="text-left font-medium text-foreground">
                    {row.field}
                  </th>
                  <td>{row.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <UnavailableState title="Broker issuance is REST and CLI only">
          Agent-scoped broker issuance is served at POST /api/v1/broker/agent-identities and by the broker agent-identities issue CLI command. This console
          does not mint live broker credentials because the request carries raw proof material.
        </UnavailableState>
      </section>
    </section>
  );
}
