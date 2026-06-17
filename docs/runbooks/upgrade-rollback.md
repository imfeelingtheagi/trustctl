# Runbook: chart upgrade and rollback

This runbook upgrades the Helm chart and rolls it back when readiness, signer
health, agent heartbeat, or inventory checks fail. It covers the control-plane
chart in `deploy/helm/trstctl` and the fleet surfaces that chart exposes.

## Prerequisites

- Save the current release revision: `helm history trstctl -n trstctl`.
- Export the current values:

```sh
helm get values trstctl -n trstctl -o yaml > trstctl-values.before.yaml
```

- Confirm `/readyz` is `200`.
- Confirm `trstctl_signer_up == 1`.
- Record `trstctl-cli agents list` and inventory counts before the upgrade.
- Run `trstctl --check-config` in the candidate environment and confirm the
  `agent_channel.*` lines match the planned fleet topology.

## Commands: preflight

Render the chart with the exact values file and inspect the agent channel and
isolated-signer surfaces:

```sh
helm template trstctl deploy/helm/trstctl \
  --namespace trstctl \
  -f trstctl-values.before.yaml > rendered.before.yaml

grep -n 'agent-grpc\|TRSTCTL_AGENT_CHANNEL\|trstctl-signer' rendered.before.yaml
```

If the upgrade changes signer mode, verify the signer key store, KEK, signer auth
Secret, and mTLS Secret are present before applying. The signer must keep the same
key material unless a key ceremony explicitly says otherwise.

## Commands: upgrade

```sh
helm upgrade trstctl deploy/helm/trstctl \
  --namespace trstctl \
  -f trstctl-values.before.yaml \
  --wait --timeout=10m

kubectl -n trstctl rollout status deployment/trstctl --timeout=10m
kubectl -n trstctl rollout status daemonset/trstctl-agent --timeout=10m
```

If isolated signer mode is enabled:

```sh
kubectl -n trstctl rollout status deployment/trstctl-signer --timeout=10m
```

## Expected metrics and logs

- `/readyz` returns `200` after each Deployment becomes Ready.
- `trstctl_signer_up` stays `1`, or returns to `1` before the control plane is
  marked ready.
- Agent logs return to `heartbeat ok`.
- `trstctl-cli agents list` keeps the same fleet count and shows expected versions.
- Inventory counts stay stable. Upgrade should not remove certificate, SSH, or
  agent inventory rows.
- Kubernetes events do not show repeated crash loops, failed mounts, or readiness
  probe failures.

## Abort criteria

Rollback immediately when:

- `/readyz` stays `503` for longer than two readiness probe periods.
- `trstctl_signer_up == 0` after signer rollout completes.
- More than 2 percent of agents miss two heartbeat intervals.
- `trstctl-cli agents list` loses hosts that were healthy before the upgrade.
- Inventory counts decrease without an explicit migration note.
- The rendered chart opens or closes the agent channel differently from the
  `trstctl --check-config` output.

## Rollback commands

```sh
helm history trstctl -n trstctl
helm rollback trstctl <last-good-revision> -n trstctl --wait --timeout=10m

kubectl -n trstctl rollout status deployment/trstctl --timeout=10m
kubectl -n trstctl rollout status daemonset/trstctl-agent --timeout=10m
kubectl -n trstctl rollout status deployment/trstctl-signer --timeout=10m
```

If the rollback itself cannot reach readiness, stop fleet churn first, then use
the signer or DR runbook depending on the failing dependency:

```sh
kubectl -n trstctl rollout pause daemonset/trstctl-agent
curl -fksS https://cp.example.com/readyz
curl -fksS https://cp.example.com/metrics | grep trstctl_signer_up
```

## Post-checks

1. `/readyz` is `200`.
2. `trstctl_signer_up == 1`.
3. Agent heartbeat age is inside the configured `agent_channel.heartbeat_interval`
   or the default interval.
4. `trstctl-cli agents list` has the expected host count.
5. Inventory counts match the pre-upgrade baseline.
6. Store `helm history`, rendered manifests, and the before/after counts in the
   change ticket.
