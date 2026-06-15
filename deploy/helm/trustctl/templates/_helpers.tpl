{{/* Common naming + labels for the trustctl control-plane chart. */}}

{{- define "trustctl.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "trustctl.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "trustctl.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "trustctl.labels" -}}
helm.sh/chart: {{ include "trustctl.chart" . }}
{{ include "trustctl.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: trustctl
{{- end -}}

{{- define "trustctl.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trustctl.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: control-plane
{{- end -}}

{{- define "trustctl.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "trustctl.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the control-plane image reference (OPS-003).

The release pipeline (.github/workflows/release.yml) tags every image `vX.Y.Z`
(from `git describe`) plus `:latest`. Chart.AppVersion follows Helm's
leading-`v`-stripped convention, so when the operator does not override
image.tag we form the tag as `v<appVersion>` — which is exactly a tag the
pipeline publishes — rather than a bare `<appVersion>` that was never pushed and
would ImagePullBackOff. An explicit image.tag (e.g. a digest or a specific
`vX.Y.Z`/`latest`) is honored verbatim.
*/}}
{{- define "trustctl.imageTag" -}}
{{- if .Values.image.tag -}}
{{- .Values.image.tag -}}
{{- else -}}
{{- printf "v%s" .Chart.AppVersion -}}
{{- end -}}
{{- end -}}

{{- define "trustctl.image" -}}
{{- printf "%s:%s" .Values.image.repository (include "trustctl.imageTag" .) -}}
{{- end -}}

{{/*
Guard for the not-yet-implemented isolated/mTLS signer topology (S15.1, OPS-001).

The isolated signer would run as its own pod reached over an mTLS gRPC channel,
but that cross-node transport is unimplemented: the trustctl-signer binary
defines only --socket/--keystore/--kek/--version and has NO --mtls-listen flag
and no TCP listener (it is UDS-only — see docs/limitations.md "Multi-replica HA"
and SIGNER-005). Rendering the isolated topology therefore produced a pod whose
`trustctl-signer --mtls-listen :9443` crash-loops ("flag provided but not
defined"). Rather than ship a chart-selectable switch that cannot start, fail the
render with guidance and keep the supported, co-located sidecar (UDS) topology.

Every isolated-mode template includes this first, so a default install (sidecar)
renders cleanly while `--set signer.mode=isolated` fails fast with a clear
message instead of a CrashLoopBackOff on the cluster.
*/}}
{{- define "trustctl.signer.guardMode" -}}
{{- if eq .Values.signer.mode "isolated" -}}
{{- fail "signer.mode=isolated runs the signer as a separate pod over an mTLS gRPC channel, but that cross-node transport is not yet implemented (the trustctl-signer binary is UDS-only and has no --mtls-listen; see docs/limitations.md \"Multi-replica HA\"). Use the default signer.mode=sidecar (co-located signer over an in-memory UDS), which is the supported topology." -}}
{{- else if ne .Values.signer.mode "sidecar" -}}
{{- fail (printf "signer.mode=%q is not recognized; supported values are \"sidecar\" (default; co-located signer over an in-memory UDS) and \"isolated\" (separate pod over mTLS — not yet implemented)." .Values.signer.mode) -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding the deployment KEK. */}}
{{- define "trustctl.kekSecretName" -}}
{{- if .Values.kek.existingSecret -}}
{{- .Values.kek.existingSecret -}}
{{- else -}}
{{- printf "%s-kek" (include "trustctl.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding the PostgreSQL DSN. */}}
{{- define "trustctl.dbSecretName" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecret -}}
{{- else -}}
{{- printf "%s-db" (include "trustctl.fullname" .) -}}
{{- end -}}
{{- end -}}
