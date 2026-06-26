import { FormEvent, useState } from "react";
import { api, type BreakglassReconcileResponse } from "@/lib/api";
import { SectionCard } from "@/components/dashboard";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/StatePrimitives";

/** BreakGlassReconcile takes the bundles a quorum issued OFFLINE during an outage
 * (when the control plane could not be reached) and reconciles them back into the
 * event log through the served POST /breakglass/reconcile endpoint, so the
 * emergency certificates become first-class, audited records after the fact. */
export function BreakGlassReconcile() {
  const [bundles, setBundles] = useState("");
  const [result, setResult] = useState<BreakglassReconcileResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function reconcile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setResult(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(bundles);
    } catch {
      setError("Bundles must be a JSON array of offline-issued break-glass bundles.");
      setBusy(false);
      return;
    }
    const list = Array.isArray(parsed) ? parsed : [parsed];
    try {
      setResult(await api.breakglassReconcile({ bundles: list as never }));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <SectionCard
      title="Break-glass reconciliation"
      description="Reconcile offline-issued, quorum-approved break-glass certificate bundles back into the control plane once connectivity returns."
    >
      <form onSubmit={reconcile} className="grid gap-3">
        <label className="grid gap-1 text-sm font-medium" htmlFor="breakglass-bundles">
          Offline-issued bundles (JSON)
          <textarea
            id="breakglass-bundles"
            value={bundles}
            onChange={(event) => setBundles(event.target.value)}
            rows={6}
            placeholder='[{"request_id":"…","subject":"…","approvals":["…"],"cert_der":"…","signature":"…","issued_at":"…","reason":"…"}]'
            className="rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
          />
        </label>
        <div>
          <Button type="submit" disabled={busy || !bundles.trim()}>
            {busy ? "Reconciling…" : "Reconcile break-glass bundles"}
          </Button>
        </div>
      </form>
      {error ? <ErrorState title="Reconcile failed">{error}</ErrorState> : null}
      {result ? (
        <p role="status" className="mt-3 rounded-panel border border-border p-comfortable text-sm">
          Reconciled {result.reconciled} break-glass bundle{result.reconciled === 1 ? "" : "s"} into the event log.
        </p>
      ) : null}
    </SectionCard>
  );
}
