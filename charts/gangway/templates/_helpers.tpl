{{- define "gangway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "gangway.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- include "gangway.name" . }}
{{- end }}
{{- end }}

{{- define "gangway.labels" -}}
app.kubernetes.io/name: {{ include "gangway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: kubernetes-oidc
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{- define "gangway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "gangway.name" . }}
{{- end }}
