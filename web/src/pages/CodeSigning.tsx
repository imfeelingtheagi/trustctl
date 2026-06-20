import { PageHeader } from "@/components/PageHeader";
import { UnavailableState } from "@/components/StatePrimitives";

const signingRequests = [
  {
    artifact: "release/linux/amd64/trstctl-agent",
    digest: "sha256:7d7c0d0f6e5a4b3c2a190817161514131211100ffeeddccbbaa9988776655443",
    mode: "key-backed signing",
    approval: "2 of 2 release approvers",
    decision: "policy allowed: release tag, provenance, and artifact digest match",
    output: "signature download: pending backend artifact store",
  },
  {
    artifact: "container:registry.example.test/trstctl/api@sha256:9f9e",
    digest: "sha256:9f9e8d8c7b7a696857565554535251504f4e4d4c4b4a494847464544434241",
    mode: "keyless signing",
    approval: "workload identity plus release manager",
    decision: "policy denied: missing build attestation",
    output: "no signature material produced",
  },
  {
    artifact: "sbom/trstctl-web.spdx.json",
    digest: "sha256:4142434445464748495051525354555657585960616263646566676869707172",
    mode: "timestamp-only",
    approval: "automated release lane",
    decision: "policy allowed with TSA receipt",
    output: "audit receipt references immutable event sequence",
  },
];

const auditReceipts = [
  "artifact digest is the signed subject; artifact bytes never enter the browser",
  "approval, policy decision, signer identity, and timestamp become audit evidence",
  "signing key material remains inside the dedicated signer or keyless provider",
];

export function CodeSigning() {
  return (
    <section aria-labelledby="codesign-heading" className="grid gap-6">
      <PageHeader
        titleId="codesign-heading"
        title="Code signing"
        description="Code-signing requests bind an artifact digest to an approval, policy decision, signer mode, signature receipt, and immutable audit trail. This page is read-only until a served signing workflow exists."
      />

      <UnavailableState title="Code-signing workflow is library-only">
        Signing requests, key-backed and keyless modes, approval state, policy decisions, signature download receipts, and audit links are available via the API and CLI today; console management is coming soon, so this console cannot submit signing work yet.
      </UnavailableState>

      <section aria-labelledby="requests-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="requests-heading" className="text-title font-semibold">
            Signing request ledger
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            A valid request names the artifact, digest, signing mode, approval posture, policy result, and downloadable signature receipt. No private key or artifact bytes are exposed.
          </p>
        </div>
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[72rem]">
            <caption className="sr-only">Code signing request fixtures</caption>
            <thead>
              <tr>
                <th scope="col">Artifact</th>
                <th scope="col">Artifact digest</th>
                <th scope="col">Mode</th>
                <th scope="col">Approval</th>
                <th scope="col">Policy decision</th>
                <th scope="col">Signature receipt</th>
              </tr>
            </thead>
            <tbody>
              {signingRequests.map((request) => (
                <tr key={request.digest} className="align-top">
                  <td className="font-medium">{request.artifact}</td>
                  <td className="font-mono text-xs">{request.digest}</td>
                  <td>{request.mode}</td>
                  <td>{request.approval}</td>
                  <td>{request.decision}</td>
                  <td>{request.output}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="audit-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="audit-heading" className="text-title font-semibold">
            Audit and key boundary
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            The browser can review request evidence, but the signer boundary remains the place where signing keys live and signature bytes are produced.
          </p>
        </div>
        <ul className="grid gap-2 md:grid-cols-3">
          {auditReceipts.map((receipt) => (
            <li key={receipt} className="ui-panel p-3 text-sm text-muted-foreground">
              {receipt}
            </li>
          ))}
        </ul>
      </section>
    </section>
  );
}
