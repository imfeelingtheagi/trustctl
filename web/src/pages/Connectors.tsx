import { useEffect, useState } from "react";
import { PageHeader } from "@/components/PageHeader";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { api, type ConnectorCatalogItem, type ConnectorDelivery } from "@/lib/api";

const coreConnectors = [
  {
    target: "nginx",
    grant: "connector.deploy + file.write:/etc/nginx/tls",
    secretRef: "secret://connectors/nginx/prod",
    dryRun: "renders PEM path diff and reload command",
    rollback: "restore prior fullchain/key pair and reload nginx",
  },
  {
    target: "Apache",
    grant: "connector.deploy + file.write:/etc/httpd/tls",
    secretRef: "secret://connectors/apache/prod",
    dryRun: "validates vhost certificate path changes",
    rollback: "restore prior SSLCertificateFile and graceful reload",
  },
  {
    target: "HAProxy",
    grant: "connector.deploy + file.write:/etc/haproxy/certs",
    secretRef: "secret://connectors/haproxy/prod",
    dryRun: "assembles bundle and verifies config parse",
    rollback: "restore previous bundle and reload process",
  },
  {
    target: "IIS",
    grant: "connector.deploy + windows.certstore.write",
    secretRef: "secret://connectors/iis/prod",
    dryRun: "maps certificate to binding thumbprint",
    rollback: "restore previous binding thumbprint",
  },
  {
    target: "AWS ACM",
    grant: "connector.deploy + aws.acm.import",
    secretRef: "secret://connectors/aws-acm/prod",
    dryRun: "checks account, region, ARN, and chain shape",
    rollback: "repoint listener to previous ACM ARN",
  },
  {
    target: "Azure Key Vault",
    grant: "connector.deploy + azure.keyvault.certificate.write",
    secretRef: "secret://connectors/azure-kv/prod",
    dryRun: "checks vault, certificate name, and policy",
    rollback: "reactivate prior certificate version",
  },
  {
    target: "GCP Certificate Manager",
    grant: "connector.deploy + gcp.certmanager.certificate.write",
    secretRef: "secret://connectors/gcp-cm/prod",
    dryRun: "checks project, location, and map binding",
    rollback: "reattach prior certificate resource",
  },
  {
    target: "Java keystore",
    grant: "connector.deploy + keystore.write",
    secretRef: "secret://connectors/jks/prod",
    dryRun: "validates alias, store type, and chain order",
    rollback: "restore previous keystore object",
  },
];

const applianceConnectors = [
  {
    target: "F5 BIG-IP",
    reachability: "management endpoint reachable, partition scoped",
    rollback: "swap virtual server back to previous cert/key object",
  },
  {
    target: "NetScaler",
    reachability: "NSIP reachable and certKey object readable",
    rollback: "bind previous certKey to the service group",
  },
  {
    target: "Cisco",
    reachability: "RESTCONF or SSH transport reachable",
    rollback: "restore previous trustpoint binding",
  },
  {
    target: "FortiGate",
    reachability: "API profile scoped to certificate import",
    rollback: "restore previous local certificate reference",
  },
  {
    target: "Palo Alto",
    reachability: "device group and commit queue reachable",
    rollback: "revert candidate config to prior certificate object",
  },
];

const outboxStates = [
  { state: "pending", meaning: "intent was written in the same transaction as the lifecycle state change" },
  { state: "processing", meaning: "bounded connector worker owns the delivery attempt" },
  { state: "delivered", meaning: "a native registry entry or signed connector plugin accepted the deployment" },
  { state: "unrouted", meaning: "the outbox acknowledged the attempt, but no native registry entry or signed plugin owned the payload" },
  { state: "failed", meaning: "the native connector or plugin returned an error and the outbox retry policy remains authoritative" },
];

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
        title="Deployment connectors"
        description="Connector deployment is an outbox-backed worker path. This console reads the served connector registry and delivery receipts without performing a live deploy."
      />

      {error && <ErrorState title="Connector evidence failed to load">{error}</ErrorState>}
      {!catalog && !error && <LoadingState>Loading connector registry...</LoadingState>}

      {catalog && (
        <section aria-labelledby="served-connectors-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="served-connectors-heading" className="text-title font-semibold">
              Served connector registry
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              These rows are returned by the authenticated API. Delivery still moves through the outbox, so the registry is read evidence, not a deploy button.
            </p>
          </div>
          {catalog.length === 0 ? (
            <EmptyState title="No connectors registered">No served connector catalog rows were returned.</EmptyState>
          ) : (
            <div className="ui-panel overflow-x-auto">
              <table className="ui-table min-w-[54rem]">
                <caption className="sr-only">Served connector registry</caption>
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

      <section aria-labelledby="core-connectors-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="core-connectors-heading" className="text-title font-semibold">
            Core deployment targets
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Each target needs a bounded worker, explicit capability grant, masked credential reference, dry-run or test-deploy preflight, and rollback plan
            before it can receive a certificate. Raw token hidden is the rule: only sealed secret references appear here.
          </p>
        </div>
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[72rem]">
            <caption className="sr-only">Core connector deployment fixtures</caption>
            <thead>
              <tr>
                <th scope="col">Target</th>
                <th scope="col">Capability grant</th>
                <th scope="col">Masked secret reference</th>
                <th scope="col">Dry-run / test-deploy preflight</th>
                <th scope="col">Rollback evidence</th>
              </tr>
            </thead>
            <tbody>
              {coreConnectors.map((connector) => (
                <tr key={connector.target} className="align-top">
                  <td className="font-medium">{connector.target}</td>
                  <td className="font-mono text-xs">{connector.grant}</td>
                  <td className="font-mono text-xs">{connector.secretRef}:****</td>
                  <td>{connector.dryRun}</td>
                  <td>{connector.rollback}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="appliance-connectors-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="appliance-connectors-heading" className="text-title font-semibold">
            Appliance and network targets
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Appliance connectors require target secret references, reachability checks, scoped API grants, and rollback commands because a failed deploy can
            break load balancers or edge firewalls.
          </p>
        </div>
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[48rem]">
            <caption className="sr-only">Appliance connector fixtures</caption>
            <thead>
              <tr>
                <th scope="col">Target</th>
                <th scope="col">Reachability fixture</th>
                <th scope="col">Rollback fixture</th>
              </tr>
            </thead>
            <tbody>
              {applianceConnectors.map((connector) => (
                <tr key={connector.target} className="align-top">
                  <td className="font-medium">{connector.target}</td>
                  <td>{connector.reachability}</td>
                  <td>{connector.rollback}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="outbox-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="outbox-heading" className="text-title font-semibold">
            Outbox delivery posture
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            External deployment calls are never made inside the request path. The state change and outbox intent commit together; workers deliver at least once,
            and target idempotency makes the effect safe to retry.
          </p>
        </div>
        <dl className="grid gap-2 md:grid-cols-4">
          {outboxStates.map((item) => (
            <div key={item.state} className="ui-panel p-3">
              <dt className="font-mono text-xs font-semibold">{item.state}</dt>
              <dd className="mt-1 text-sm text-muted-foreground">{item.meaning}</dd>
            </div>
          ))}
        </dl>
      </section>
    </section>
  );
}
