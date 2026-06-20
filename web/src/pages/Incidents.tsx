import { useEffect, useState } from "react";
import { api, ApiError, type GraphImpact, type GraphNode } from "@/lib/api";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";

const compromisedCredential = {
  id: "cert:payments-api",
  subject: "CN=payments-api.prod",
  fingerprint: "SHA256:2b7c0d0f6e5a4b3c2a190817161514131211100ffeeddccbbaa9988776655443",
  evidence: "SIEM alert, key export attempt, and owner acknowledgement",
};

const remediationPlan = [
  { step: "1. Freeze", action: "block new deploys for the affected issuer and credential family" },
  { step: "2. Reissue", action: "mint replacements and deploy them before revoking the compromised credential" },
  { step: "3. Verify", action: "health checks prove workloads accepted the replacement chain" },
  { step: "4. Revoke", action: "publish CRL/OCSP/KRL state after replacements are confirmed" },
  { step: "5. Evidence", action: "seal approvals, graph impact, audit events, and connector receipts" },
];

const fleetStages = [
  {
    batch: "Wave 0",
    scope: "issuer inventory and canary service",
    status: "12 percent complete",
    health: "synthetic check passed",
    failed: "0 failed targets",
  },
  {
    batch: "Wave 1",
    scope: "payments and checkout workloads",
    status: "48 percent complete",
    health: "two targets paused for owner review",
    failed: "2 failed targets",
  },
  {
    batch: "Wave 2",
    scope: "remaining edge and appliance targets",
    status: "scheduled",
    health: "resume requires incident commander approval",
    failed: "rollback plan staged",
  },
];

const breakGlassChecklist = [
  "emergency declaration names incident ID, commander, reason, and expiry",
  "quorum approval records two operators outside the affected owner team",
  "offline issue uses signer ceremony evidence and a short TTL",
  "verification checks fingerprint, chain, scope, and tenant before deployment",
  "reconciliation imports the offline event stream delta after control-plane recovery",
  "post-incident checklist rotates emergency material and closes temporary access",
];

export function Incidents() {
  const [impact, setImpact] = useState<GraphImpact | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    api
      .graphBlastRadius(compromisedCredential.id)
      .then((result) => {
        if (!active) return;
        setImpact(result);
        setError(null);
      })
      .catch((err) => {
        if (!active) return;
        setError(apiProblemMessage(err, "Could not load blast-radius preview"));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <section aria-labelledby="incidents-heading" className="grid gap-6">
      <PageHeader
        titleId="incidents-heading"
        title="Incidents"
        description="Incident handling starts with a compromised credential, reads graph impact, plans reissue-before-revoke remediation, captures approvals, and seals evidence. This page does not execute remediation."
      />

      <UnavailableState title="Incident execution is not served">
        Incident records, remediation state, evidence bundles, and break-glass reconciliation are available via the API and CLI today; console management is coming soon. Deployment receipts are not surfaced in the console yet, so fleet reissue cannot run from here.
      </UnavailableState>

      <section aria-labelledby="compromise-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="compromise-heading" className="text-title font-semibold">
            Credential compromise workflow
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            The intake fixture is read-only; blast-radius evidence comes from `GET /api/v1/graph/blast-radius/{"{id}"}` for the compromised credential ID.
          </p>
        </div>
        <dl className="grid gap-2 md:grid-cols-4">
          <div className="rounded-md border border-border p-3">
            <dt className="text-xs font-semibold uppercase text-muted-foreground">Credential</dt>
            <dd className="mt-1 font-mono text-xs">{compromisedCredential.id}</dd>
          </div>
          <div className="rounded-md border border-border p-3">
            <dt className="text-xs font-semibold uppercase text-muted-foreground">Subject</dt>
            <dd className="mt-1 text-sm">{compromisedCredential.subject}</dd>
          </div>
          <div className="rounded-md border border-border p-3">
            <dt className="text-xs font-semibold uppercase text-muted-foreground">Fingerprint</dt>
            <dd className="mt-1 font-mono text-xs">{compromisedCredential.fingerprint}</dd>
          </div>
          <div className="rounded-md border border-border p-3">
            <dt className="text-xs font-semibold uppercase text-muted-foreground">Evidence</dt>
            <dd className="mt-1 text-sm">{compromisedCredential.evidence}</dd>
          </div>
        </dl>
        {loading && <LoadingState>Loading blast-radius preview...</LoadingState>}
        {error && <ErrorState title="Blast-radius preview unavailable">{error}</ErrorState>}
        {impact && <BlastRadiusPreview impact={impact} />}
      </section>

      <section aria-labelledby="plan-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="plan-heading" className="text-title font-semibold">
            Reissue-before-revoke plan
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            The remediation library orders replacement before revocation so services do not lose trust while an incident is being contained.
          </p>
        </div>
        <ol className="grid gap-2 md:grid-cols-5">
          {remediationPlan.map((item) => (
            <li key={item.step} className="rounded-md border border-border p-3">
              <p className="font-semibold">{item.step}</p>
              <p className="mt-1 text-sm text-muted-foreground">{item.action}</p>
            </li>
          ))}
        </ol>
        <UnavailableState title="Remediation execute is library-only">
          Approvals, evidence bundle creation, connector dispatch, and revocation are displayed as a plan only. There is no live execute, revoke, bypass, or deploy control on this page.
        </UnavailableState>
      </section>

      <section aria-labelledby="fleet-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="fleet-heading" className="text-title font-semibold">
            Fleet re-issuance for CA compromise
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            CA compromise reissue is staged by issuer, batch, health check, resume point, rollback plan, failed target list, and audit receipt before revocation completes.
          </p>
        </div>
        <div className="overflow-x-auto rounded-panel border border-border">
          <table className="ui-table min-w-[56rem]">
            <caption className="sr-only">Fleet reissuance fixture</caption>
            <thead>
              <tr>
                <th scope="col">Batch</th>
                <th scope="col">Affected issuer scope</th>
                <th scope="col">Percent complete</th>
                <th scope="col">Health / resume</th>
                <th scope="col">Failed targets / rollback</th>
              </tr>
            </thead>
            <tbody>
              {fleetStages.map((stage) => (
                <tr key={stage.batch} className="align-top">
                  <td className="font-medium">{stage.batch}</td>
                  <td>{stage.scope}</td>
                  <td>{stage.status}</td>
                  <td>{stage.health}</td>
                  <td>{stage.failed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-sm text-muted-foreground">
          Audit receipts are held for every staged batch, including skipped targets and rollback decisions.
        </p>
      </section>

      <section aria-labelledby="break-glass-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="break-glass-heading" className="text-title font-semibold">
            Break-glass procedures
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Emergency issuance requires declaration, quorum, offline issue evidence, verification, expiry, reconciliation, and a post-incident checklist. There is no one-click bypass.
          </p>
        </div>
        <ul className="grid gap-2 md:grid-cols-2">
          {breakGlassChecklist.map((item) => (
            <li key={item} className="rounded-md border border-border p-3 text-sm text-muted-foreground">
              {item}
            </li>
          ))}
        </ul>
      </section>
    </section>
  );
}

function BlastRadiusPreview({ impact }: { impact: GraphImpact }) {
  return (
    <section aria-labelledby="incident-blast-heading" className="ui-panel p-comfortable">
      <h3 id="incident-blast-heading" className="text-title font-semibold">
        Blast-radius preview
      </h3>
      <p className="mt-1 text-sm text-muted-foreground">
        Compromise of {impact.node.name || impact.node.id} affects {impact.affected.length} downstream node{impact.affected.length === 1 ? "" : "s"}.
      </p>
      <dl className="mt-3 grid gap-2 md:grid-cols-3">
        {Object.entries(impact.by_kind ?? {}).map(([kind, value]) => (
          <div key={kind} className="rounded-md border border-border p-2">
            <dt className="font-medium">{kind}</dt>
            <dd className="text-sm text-muted-foreground">{displayValue(value)}</dd>
          </div>
        ))}
      </dl>
      <AffectedNodes nodes={impact.affected} />
    </section>
  );
}

function AffectedNodes({ nodes }: { nodes: GraphNode[] }) {
  if (nodes.length === 0) {
    return <p className="mt-3 text-sm text-muted-foreground">No downstream affected nodes were returned.</p>;
  }
  return (
    <ul className="mt-3 grid gap-2 md:grid-cols-2">
      {nodes.map((node) => (
        <li key={node.id} className="rounded-md border border-border p-2">
          <p className="font-medium">{node.name || node.id}</p>
          <p className="font-mono text-xs text-muted-foreground">{node.kind} - {node.id}</p>
        </li>
      ))}
    </ul>
  );
}

function displayValue(value: unknown): string {
  if (value == null) return "-";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function apiProblemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.retryAfterSeconds != null) return `${fallback}: retry in ${err.retryAfterSeconds}s.`;
    const body = err.body.trim();
    if (body) {
      try {
        const problem = JSON.parse(body) as { detail?: string; title?: string };
        const message = problem.detail || problem.title;
        if (message) return `${fallback}: ${message}`;
      } catch {
        return `${fallback}: ${body}`;
      }
    }
    return `${fallback}: ${err.message}`;
  }
  return `${fallback}: ${err instanceof Error ? err.message : String(err)}`;
}
