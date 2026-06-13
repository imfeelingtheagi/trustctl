# Uninstall

trustctl is designed to leave cleanly. Removing it never touches the credentials
it manages on your hosts — those certificates and keys stay where they were
deployed. Uninstalling only removes the trustctl binaries, services, and (if you
choose) its datastore.

Pick your platform.

## Docker

If you used the evaluation stack, tear it down. To keep the data, omit
`--volumes`:

```bash
docker compose -f deploy/docker/docker-compose.yml down            # stop, keep data
docker compose -f deploy/docker/docker-compose.yml down --volumes  # also delete Postgres/NATS data
```

For a standalone container, stop and remove it, then drop the image:

```bash
docker rm -f trustctl
docker image rm ghcr.io/imfeelingtheagi/trustctl:latest
```

## Kubernetes

Delete the agent DaemonSet and its supporting objects (deleting the namespace
removes everything in it):

```bash
kubectl delete -f deploy/kubernetes/daemonset.yaml
kubectl delete -f deploy/kubernetes/rbac.yaml
kubectl delete -f deploy/kubernetes/namespace.yaml
```

## Linux

Stop and disable the service, then remove the binaries:

```bash
sudo systemctl disable --now trustctl-agent
sudo rm -f /etc/systemd/system/trustctl-agent.service
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/trustctl /usr/local/bin/trustctl-agent /usr/local/bin/trustctl-signer
```

Optionally remove the agent's local state directory (its data dir and the
telemetry instance ID, if you enabled telemetry).

## macOS

Unload the `launchd` job and remove the binary:

```bash
sudo launchctl unload /Library/LaunchDaemons/io.trustctl.agent.plist
sudo rm -f /Library/LaunchDaemons/io.trustctl.agent.plist
sudo rm -f /usr/local/bin/trustctl-agent
```

Certificates the agent placed in the keychain remain until you remove them.

## Windows

Uninstall the MSI, which stops and unregisters the SCM service:

```powershell
msiexec /x trustctl-agent.msi /qn
```

Or remove **trustctl agent** from *Settings → Apps*. Certificates already in the
Windows certificate store are left in place.

## Remove the datastore (optional)

trustctl's own state lives entirely in PostgreSQL and NATS JetStream. If you ran
external datastores and want trustctl gone completely, drop its database and
JetStream streams on those servers. With the bundled Compose datastores, the
`down --volumes` command above already removed them.
