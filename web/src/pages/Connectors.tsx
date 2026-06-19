import { UnavailableState } from "@/components/StatePrimitives";

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
  {
    target: "Kubernetes",
    grant: "connector.deploy + kubernetes.secret.patch",
    secretRef: "secret://connectors/kubernetes/prod",
    dryRun: "server-side apply preview for TLS secret",
    rollback: "reapply previous Secret resourceVersion",
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
  { state: "queued", meaning: "intent was written in the same transaction as the lifecycle state change" },
  { state: "dispatching", meaning: "bounded connector worker owns the delivery attempt" },
  { state: "acked", meaning: "connector.deploy was acknowledged by the outbox" },
  { state: "held", meaning: "not routed until a signed connector plugin with matching capability grants is loaded" },
];

export function Connectors() {
  return (
    <section aria-labelledby="connectors-heading" className="grid gap-6">
      <div>
        <h1 id="connectors-heading" className="text-2xl font-semibold">
          Deployment connectors
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Connector deployment is an outbox-backed worker path. This console shows destination shape, capability grants, masked target secret references, dry-run posture, reachability, and rollback evidence without performing a live deploy.
        </p>
      </div>

      <UnavailableState title="Connector routing is not served">
        `BACKEND-CONNECTORS` and `BACKEND-OUTBOX-STATUS` must expose signed plugin inventory, worker queue state, delivery attempts, and rollback receipts. `connector.deploy` can be acknowledged by the outbox, but it is not routed unless a signed connector plugin is loaded.
      </UnavailableState>

      <section aria-labelledby="core-connectors-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="core-connectors-heading" className="text-lg font-semibold">
            Core deployment targets
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Each target needs a bounded worker, explicit capability grant, masked credential reference, dry-run or test-deploy preflight, and rollback plan before it can receive a certificate. Raw token hidden is the rule: only sealed secret references appear here.
          </p>
        </div>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[72rem] text-left text-sm">
            <caption className="sr-only">Core connector deployment fixtures</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Target</th>
                <th scope="col" className="py-2 pr-4 font-medium">Capability grant</th>
                <th scope="col" className="py-2 pr-4 font-medium">Masked secret reference</th>
                <th scope="col" className="py-2 pr-4 font-medium">Dry-run / test-deploy preflight</th>
                <th scope="col" className="py-2 pr-3 font-medium">Rollback evidence</th>
              </tr>
            </thead>
            <tbody>
              {coreConnectors.map((connector) => (
                <tr key={connector.target} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{connector.target}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{connector.grant}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{connector.secretRef}:****</td>
                  <td className="py-2 pr-4">{connector.dryRun}</td>
                  <td className="py-2 pr-3">{connector.rollback}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="appliance-connectors-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="appliance-connectors-heading" className="text-lg font-semibold">
            Appliance and network targets
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Appliance connectors require target secret references, reachability checks, scoped API grants, and rollback commands because a failed deploy can break load balancers or edge firewalls.
          </p>
        </div>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[48rem] text-left text-sm">
            <caption className="sr-only">Appliance connector fixtures</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Target</th>
                <th scope="col" className="py-2 pr-4 font-medium">Reachability fixture</th>
                <th scope="col" className="py-2 pr-3 font-medium">Rollback fixture</th>
              </tr>
            </thead>
            <tbody>
              {applianceConnectors.map((connector) => (
                <tr key={connector.target} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{connector.target}</td>
                  <td className="py-2 pr-4">{connector.reachability}</td>
                  <td className="py-2 pr-3">{connector.rollback}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="outbox-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="outbox-heading" className="text-lg font-semibold">
            Outbox delivery posture
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            External deployment calls are never made inside the request path. The state change and outbox intent commit together; workers deliver at least once, and target idempotency makes the effect safe to retry.
          </p>
        </div>
        <dl className="grid gap-2 md:grid-cols-4">
          {outboxStates.map((item) => (
            <div key={item.state} className="rounded-md border border-border p-3">
              <dt className="font-mono text-xs font-semibold">{item.state}</dt>
              <dd className="mt-1 text-sm text-muted-foreground">{item.meaning}</dd>
            </div>
          ))}
        </dl>
      </section>
    </section>
  );
}
