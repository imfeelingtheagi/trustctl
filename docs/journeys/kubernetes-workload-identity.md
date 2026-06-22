# Give your Kubernetes workloads an identity

## Goal

When you finish this journey, your Kubernetes services will prove *what they are* and
receive short-lived certificates from trstctl — with **no static secret** baked into
any pod to be copied into logs, images, or git. It is for platform teams running
services on Kubernetes that need service-to-service identity (mutual TLS, SPIFFE)
without long-lived API keys. In plain terms: instead of planting a permanent
password in each pod, the workload presents proof of its identity at the moment it
needs access, and gets a pass (an SVID) that expires in minutes.

## Before you start

- A running trstctl control plane with a provisioned issuing CA. Bring one up via
  [Issue your first certificate](first-certificate.md) or
  [Getting started](../getting-started.md).
- A Kubernetes cluster whose service-account token signing keys (its JWKS) trstctl
  can verify against — this is the trust source for pod attestation.
- An API token exported as `TRSTCTL_TOKEN` to drive the CLI (from the
  first-certificate journey).
- A workload-side SVID consumer: `spiffe-helper`, a go-spiffe client, or an
  Envoy SDS integration.

## Steps

1. **Understand the building block: attestation before trust.** Before issuing
   anything, trstctl demands proof of the workload's identity and verifies it. For
   Kubernetes the relevant method is the **projected service-account token**
   (`k8s_sat`), verified against the cluster's JWKS — a forged token is rejected and
   nothing is signed (fail-closed). The full attestation chain (TPM, AWS, GCP, Azure,
   Kubernetes, GitHub OIDC) is covered in
   [Workload identity](../features/workload-identity.md).

2. **Enable the SPIFFE Workload API.** trstctl serves a SPIRE-compatible Workload API
   as a gRPC service on a Unix domain socket. Turn it on and bind it to your tenant:

   ```yaml
   protocols:
     spiffe:
       enabled: true
       tenant_id: "11111111-1111-1111-1111-111111111111"
   ```

   You should see the control plane mount the Workload API on the socket at startup.
   It activates only when an issuing CA is provisioned.

3. **Register the workloads as managed identities.** Model each service as a
   non-human identity through the served CLI (this is idempotent — a retry never
   creates a duplicate):

   ```sh
   trstctl-cli identities create -f service-account.json
   ```

   You should see the identity created with its lifecycle state. The non-human
   identity lifecycle (created, scoped, rotated, disabled, retired) is described in
   [Workload identity](../features/workload-identity.md).

4. **Fetch a short-lived SVID from inside a pod.** A workload that passes attestation
   presents its selectors (e.g. `k8s:ns:default`, `k8s:sa:web`) over the socket; the
   server matches them against registration entries and returns an SVID plus the
   trust bundle. With a stock client this is a `FetchX509SVID` call against the
   served socket. You should see the workload receive an X.509-SVID — a single
   `spiffe://` URI identity, signed through the separate signing service — that
   expires in minutes, not months. The wire details are in
   [Workload identity](../features/workload-identity.md).

5. **Confirm there is no static secret to steal.** Because the SVID is short-lived
   and minted only after attestation, there is nothing long-lived in the pod to leak,
   and even a captured credential is useless within minutes. A `NeedsRotation` helper
   flags an SVID for renewal once it is half-expired, so the workload renews itself.
   You should see SVIDs rotating on their own with no secret material at rest in the
   pod spec.

6. **See the workloads land in inventory and the graph.** Each attested identity and
   its credential are recorded, so you can find them like any other credential:

   ```sh
   trstctl-cli certificates list --limit 50
   ```

   You should see the workload identities tracked alongside everything else trstctl
   knows about. How the inventory is built and what else discovery finds is covered
   in [Discovery & inventory](../features/discovery-and-inventory.md).

   > Honest status: the SPIFFE Workload API is served over the socket and proven
   > end-to-end against stock go-spiffe and `spiffe-helper` clients in CI. The
   > attestation, ephemeral-issuance, and AI-agent-broker components are built and
   > tested behind their interfaces with their own served surfaces tracked in
   > [Current limitations](../limitations.md).

## Where next

- [Enroll devices and IoT fleets](enroll-devices.md)
- [Automate TLS across your fleet with ACME](automate-fleet-tls.md)

**Journey:** J3
**Steps through:** F24, F25, F30, F59, F61, F3, F49
