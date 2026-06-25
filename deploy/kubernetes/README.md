# trstctl agent on Kubernetes

The trstctl agent runs as a **DaemonSet** (one pod per node). It installs
certificates into Kubernetes **Secrets** and acts as a **cert-manager external
issuer**, signing `CertificateRequest`s through trstctl.

The agent talks to the Kubernetes API server directly over its JSON/HTTPS wire
protocol, authenticating with the pod's service-account token and trusting the
in-cluster CA — no `client-go` dependency.

## Deploy

First make the control plane publish the agent steady-state channel. The packaged
DaemonSet connects to the in-namespace `trstctl` Service on `:9443`, so the chart
must enable that port and mint the channel certificate with `trstctl` as a DNS SAN:

```sh
helm upgrade --install trstctl deploy/helm/trstctl \
  --namespace trstctl --create-namespace \
  --set agentChannel.enabled=true \
  --set agentChannel.serverName=trstctl
```

Then choose the immutable release image, mint a one-time bootstrap token, store it
in the Secret the DaemonSet mounts, create the CA bundle ConfigMap, render the
DaemonSet with that release digest, and apply the agent manifests:

```sh
export TRSTCTL_SERVER=https://cp.example.com
export TRSTCTL_TOKEN=trst_...
export TRSTCTL_AGENT_IMAGE='ghcr.io/ctlplne/trstctl@sha256:<release-image-digest>'

TOKEN="$(trstctl-cli agents enroll-token | jq -r .token)"
rendered_agent_daemonset="$(mktemp)"
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl -n trstctl create secret generic trstctl-agent-bootstrap \
  --from-literal=token="$TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n trstctl create configmap trstctl-ca-bundle \
  --from-file=ca-bundle.pem=/path/to/agent-channel-ca.pem \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy/kubernetes/rbac.yaml
scripts/release/render-kubernetes-agent-daemonset.sh "$TRSTCTL_AGENT_IMAGE" > "$rendered_agent_daemonset"
kubectl apply -f "$rendered_agent_daemonset"
```

The bootstrap token is single-use and short-lived. The DaemonSet mounts it from
`Secret/trstctl-agent-bootstrap` at `/var/run/trstctl/bootstrap/token` and passes
`--bootstrap-token-file`; the token is not placed directly on the agent command
line. The enrollment URL must be an `https://` control-plane base URL
(`https://trstctl:8443`); the agent appends `/enroll/bootstrap` itself.

`TRSTCTL_AGENT_IMAGE` must be a real `.../trstctl@sha256:<64-hex-digest>` release
image; the render script rejects tags, short digests, and the all-zero placeholder.
Create `ConfigMap/trstctl-ca-bundle` with `ca-bundle.pem` before applying the
rendered DaemonSet. The PEM bundle may contain more than one certificate; the agent
uses only this bundle to pin bootstrap HTTPS before posting the one-time token and
for the steady-state mTLS channel. The DaemonSet intentionally treats the ConfigMap
as required so a missing bundle fails before the pod can attempt enrollment.

These are also embedded in the agent binary (`deploy/kubernetes`.`Manifests`) and
validated in tests. The `ClusterRole` grants least privilege: write Secrets, and
read `CertificateRequest`s plus update their status — nothing else.

The DaemonSet runs `trstctl-agent --k8s`, which:

1. bootstraps the agent identity (mutual-TLS, S5.1);
2. publishes that certificate into the Secret named by `--k8s-secret`
   (`namespace/name`), as a `kubernetes.io/tls` Secret (`tls.crt` / `tls.key`);
3. if `--cert-manager-issuer` and `--bridge-signer-url` are set, reconciles
   cert-manager `CertificateRequest`s for that issuer, forwarding each CSR to the
   control plane for signing and writing the result back to the request status.

For node-level certificate inventory, add read-only hostPath mounts for the public
certificate directories you want to enumerate and pass
`--inventory-cert-roots=/host/etc/ssl,/host/etc/pki/tls/certs`. The agent reports
fingerprints and metadata over the mTLS agent channel; it does not send private keys or
secret values.

For node trust-store inventory, add read-only hostPath mounts for the public trust
anchor directories and pass `--inventory-os-trust-roots=/host/etc/ssl/certs`.
Java, NSS, and browser trust-store exports use the corresponding
`--inventory-java-trust-stores`, `--inventory-nss-trust-roots`, and
`--inventory-browser-trust-roots` flags.

For private-key-material discovery, mount only the directories you intentionally
want inspected and pass `--inventory-private-key-roots=/host/etc/ssl/private,/host/etc/ssh`.
The agent classifies key format/algorithm locally, derives a public-key fingerprint
when possible, wipes file buffers after inspection, and reports `private_key`
findings without sending PEM/DER key bytes.

## cert-manager bridge

Point a cert-manager `Issuer`/`ClusterIssuer` (or a raw `CertificateRequest`) at
trstctl by `issuerRef` (`name: trstctl`, `group: trstctl.com`). The agent signs
matching requests and sets their `Ready` condition with the issued certificate.
Only a CSR ever crosses the wire to the control plane — never a private key.

## End-to-end test

`test/e2e/kubernetes` exercises the secret destination and the cert-manager
bridge against a real API server. CI runs it on a `kind` cluster with the
cert-manager CRDs installed (the `kubernetes / kind e2e` job). The agent uses
its restricted service-account token (`K8S_TOKEN`); fixtures and verification
use an admin token (`K8S_ADMIN_TOKEN`), because the agent service account is
least-privilege and cannot create `CertificateRequest`s. Locally:

```sh
export K8S_SERVER=... K8S_TOKEN=... K8S_ADMIN_TOKEN=... K8S_CA_FILE=... K8S_NAMESPACE=trstctl
go test -tags e2e ./test/e2e/kubernetes/...
```

The bridge merges into a request's status (it preserves conditions such as
cert-manager's `Approved`, upserting `Ready`), so it composes with cert-manager's
approval flow; exercising that full controller/approval path end-to-end is a
follow-up. The platform-neutral logic is covered on every platform by unit
tests against an in-process Kubernetes API double (`internal/agent/k8s`).
