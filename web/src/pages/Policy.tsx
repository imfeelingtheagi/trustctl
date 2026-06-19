import { Link } from "react-router-dom";
import { UnavailableState } from "@/components/StatePrimitives";

const policyOutcomes = [
  {
    state: "Allowed",
    meaning: "The bound profile and deployed Rego policy explicitly allow the requested issue, deploy, or revoke action.",
    evidence: "policy.decision allow plus the normal lifecycle event",
  },
  {
    state: "Denied",
    meaning: "Default-deny wins when no rule allows the action, RA scope is wrong, approval is missing, or the profile rejects the request.",
    evidence: "policy.decision deny or issuance.profile_evaluated deny",
  },
  {
    state: "Policy error",
    meaning: "A compile or evaluation error fails closed. The browser should show the backend problem detail, not retry as an allow.",
    evidence: "problem+json denial and policy.decision error",
  },
  {
    state: "Overload 503",
    meaning: "The policy bulkhead sheds work when saturated. Operators see a 503 and retry later; issuance is not allowed through.",
    evidence: "503 problem+json, Retry-After when served",
  },
];

export function Policy() {
  return (
    <section aria-labelledby="policy-heading" className="grid gap-6">
      <div>
        <h1 id="policy-heading" className="text-2xl font-semibold">
          Policy
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Served issue, deploy, and revoke mutations pass through the OPA/Rego default-deny gate, RA separation, dual-control approval, and bound-profile checks before state changes are emitted.
        </p>
      </div>

      <section aria-labelledby="policy-gate-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="policy-gate-heading" className="text-lg font-semibold">
            Served enforcement path
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            The browser does not send a tenant id or bypass policy. It asks the served lifecycle endpoint to mutate state; the backend evaluates policy and either emits the event or returns a fail-closed problem.
          </p>
        </div>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[54rem] text-left text-sm">
            <caption className="sr-only">Policy decision outcomes</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Outcome</th>
                <th scope="col" className="py-2 pr-4 font-medium">ELI5 technical meaning</th>
                <th scope="col" className="py-2 pr-3 font-medium">Audit evidence</th>
              </tr>
            </thead>
            <tbody>
              {policyOutcomes.map((outcome) => (
                <tr key={outcome.state} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{outcome.state}</td>
                  <td className="py-2 pr-4">{outcome.meaning}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{outcome.evidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-sm text-muted-foreground">
          Denials are visible in the action error path on <Link className="underline" to="/identities">Identities</Link> and in <Link className="underline" to="/audit?type=policy.decision">Audit policy decisions</Link>. Profile-bound issuance denials are also visible through <Link className="underline" to="/audit?type=issuance.profile_evaluated">profile evaluation evidence</Link>.
        </p>
      </section>

      <section aria-labelledby="policy-dry-run-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="policy-dry-run-heading" className="text-lg font-semibold">
            Policy authoring and dry run
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            A real editor needs a tenant-scoped API that reads active Rego, validates candidate modules, runs dry-run input, and returns a decision trace. That endpoint is not served yet.
          </p>
        </div>
        <UnavailableState title="Policy authoring and dry-run API not served yet">
          `BACKEND-POLICY-AUTHOR` must serve active policy read, candidate validation, dry-run input, allow/deny output, and trace rows before this page can expose an editor or evaluator. Until then, lifecycle mutations remain the real enforcement path.
        </UnavailableState>
      </section>
    </section>
  );
}
