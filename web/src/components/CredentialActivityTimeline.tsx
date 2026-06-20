import { UnavailableState } from "@/components/StatePrimitives";

const blockedStates = ["Accepted", "Issuing", "Deploying", "Delivered / failed"];

export function CredentialActivityTimeline({ credentialLabel }: { credentialLabel?: string }) {
  return (
    <section aria-labelledby="credential-activity-timeline-heading" className="mt-5 border-t border-border pt-4">
      <h3 id="credential-activity-timeline-heading" className="font-semibold">
        Credential activity timeline
      </h3>
      <p className="mt-1 text-sm text-muted-foreground">
        {credentialLabel ? `${credentialLabel} has` : "This credential has"} served lifecycle state, but per-operation
        outbox delivery status is not exposed yet.
      </p>
      <div className="mt-3">
        <UnavailableState title="Delivery status not exposed yet">
          FE-PTR-OUTBOX / BACKEND-OUTBOX-STATUS must serve operation states, delivery attempts, delivered/failed
          results, and `last_error` before this drawer can render a live timeline. No outbox status request is made
          from this view.
        </UnavailableState>
      </div>
      <ol className="mt-3 grid gap-2 text-sm sm:grid-cols-4">
        {blockedStates.map((state) => (
          <li key={state} className="rounded-md border border-dashed border-border p-2">
            <p className="font-medium">{state}</p>
            <p className="mt-1 text-xs text-muted-foreground">Waiting on served outbox status</p>
          </li>
        ))}
      </ol>
    </section>
  );
}
