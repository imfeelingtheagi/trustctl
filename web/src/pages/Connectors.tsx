import { useEffect, useState } from "react";
import { PageHeader } from "@/components/PageHeader";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { api, type ConnectorCatalogItem, type ConnectorDelivery } from "@/lib/api";

export function Connectors() {
  const [catalog, setCatalog] = useState<ConnectorCatalogItem[] | null>(null);
  const [deliveries, setDeliveries] = useState<ConnectorDelivery[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.connectorCatalog(), api.connectorDeliveries({ limit: 20 })])
      .then(([catalogResult, deliveryResult]) => {
        if (cancelled) return;
        setCatalog(catalogResult.items ?? []);
        setDeliveries(deliveryResult.items ?? []);
        setError(null);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section aria-labelledby="connectors-heading" className="grid gap-6">
      <PageHeader
        titleId="connectors-heading"
        title="Connector delivery evidence"
        description="Read-only evidence from the connector registry and delivery receipts. Target catalogs and rollout procedures belong in deployment documentation; this page does not run deploy actions."
      />

      {error && <ErrorState title="Connector evidence failed to load">{error}</ErrorState>}
      {!catalog && !error && <LoadingState>Loading connector registry...</LoadingState>}

      {catalog && (
        <section aria-labelledby="connectors-registry-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="connectors-registry-heading" className="text-title font-semibold">
              Connector registry
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              These rows are returned by the authenticated API. Delivery still moves through the outbox, so the registry is read evidence, not a deploy button.
            </p>
          </div>
          {catalog.length === 0 ? (
            <EmptyState title="No connectors registered">No connector catalog rows were returned.</EmptyState>
          ) : (
            <div className="ui-panel overflow-x-auto">
              <table className="ui-table min-w-[54rem]">
                <caption className="sr-only">Connector registry</caption>
                <thead>
                  <tr>
                    <th scope="col">Connector</th>
                    <th scope="col">Kind</th>
                    <th scope="col">Delivery mode</th>
                    <th scope="col">Rollback evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {catalog.map((connector) => (
                    <tr key={connector.name} className="align-top">
                      <td className="font-mono text-xs font-semibold">{connector.name}</td>
                      <td>{connector.kind}</td>
                      <td>{connector.delivery_mode}</td>
                      <td>{connector.rollback}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {deliveries && (
        <section aria-labelledby="delivery-receipts-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="delivery-receipts-heading" className="text-title font-semibold">
              Recent delivery receipts
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              Receipts are projected from `connector.delivery.recorded` events. They contain routing, status, attempts, fingerprint, and rollback references,
              never certificate private-key bytes.
            </p>
          </div>
          {deliveries.length === 0 ? (
            <EmptyState title="No connector delivery receipts">No deploy outbox attempt has produced a receipt yet.</EmptyState>
          ) : (
            <div className="ui-panel overflow-x-auto">
              <table className="ui-table min-w-[76rem]">
                <caption className="sr-only">Recent connector delivery receipts</caption>
                <thead>
                  <tr>
                    <th scope="col">Status</th>
                    <th scope="col">Connector</th>
                    <th scope="col">Destination</th>
                    <th scope="col">Target</th>
                    <th scope="col">Attempts</th>
                    <th scope="col">Fingerprint</th>
                    <th scope="col">Reason</th>
                    <th scope="col">Rollback</th>
                  </tr>
                </thead>
                <tbody>
                  {deliveries.map((receipt) => (
                    <tr key={receipt.id} className="align-top">
                      <td className="font-mono text-xs">{receipt.status}</td>
                      <td>{receipt.connector}</td>
                      <td className="font-mono text-xs">{receipt.destination}</td>
                      <td>{receipt.target}</td>
                      <td>{receipt.attempts}</td>
                      <td className="break-all font-mono text-xs">{receipt.fingerprint || "-"}</td>
                      <td>{receipt.reason || receipt.detail || "-"}</td>
                      <td>{receipt.rollback_ref || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </section>
  );
}
