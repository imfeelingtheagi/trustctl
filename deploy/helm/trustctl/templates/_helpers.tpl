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

{{- define "trustctl.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
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
