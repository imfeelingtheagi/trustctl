import type { ConnectorDelivery, RotationRun } from "@/lib/api";

function shortFingerprint(value?: string): string {
  if (!value) return "-";
  return value.length <= 16 ? value : `${value.slice(0, 12)}...${value.slice(-8)}`;
}

export function CredentialActivityTimeline({
  credentialLabel,
  deliveryReceipt,
  rotationRun,
}: {
  credentialLabel?: string;
  deliveryReceipt?: ConnectorDelivery;
  rotationRun?: RotationRun;
}) {
  const rows = [
    { label: "Lifecycle accepted", value: "state is projected from the event log" },
    {
      label: "Connector delivery",
      value: deliveryReceipt
        ? `${deliveryReceipt.status} ${deliveryReceipt.connector}/${deliveryReceipt.target} after ${deliveryReceipt.attempts} attempt${deliveryReceipt.attempts === 1 ? "" : "s"}`
        : "no connector delivery receipt yet",
    },
    {
      label: "Rotation run",
      value: rotationRun
        ? `${rotationRun.status} via ${rotationRun.trigger}; successor ${shortFingerprint(rotationRun.successor_fingerprint)}`
        : "no lifecycle rotation run yet",
    },
    {
      label: "Rollback evidence",
      value: rotationRun?.rollback_ref || deliveryReceipt?.rollback_ref || "no rollback reference recorded yet",
    },
  ];

  return (
    <section aria-labelledby="credential-activity-timeline-heading" className="mt-5 border-t border-border pt-4">
      <h3 id="credential-activity-timeline-heading" className="font-semibold">
        Credential activity timeline
      </h3>
      <p className="mt-1 text-sm text-muted-foreground">
        {credentialLabel ? `${credentialLabel} has` : "This credential has"} served lifecycle state plus projected
        connector and rotation evidence when an outbox worker has produced it.
      </p>
      <ol className="mt-3 grid gap-2 text-sm sm:grid-cols-4">
        {rows.map((row) => (
          <li key={row.label} className="rounded-md border border-border p-2">
            <p className="font-medium">{row.label}</p>
            <p className="mt-1 text-xs text-muted-foreground">{row.value}</p>
          </li>
        ))}
      </ol>
    </section>
  );
}
