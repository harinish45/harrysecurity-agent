{{- define "nexus-strike.name" -}}
nexus-strike
{{- end -}}

{{- define "nexus-strike.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "nexus-strike.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Name of the Secret the container's envFrom should reference: an
operator-managed Secret (.Values.secrets.existingSecret) takes precedence,
so nothing sensitive ever needs to pass through values.yaml or Helm release
history; otherwise, when .Values.secrets.data is non-empty, the chart's own
Secret (templates/secret.yaml) rendered under the release's fullname.
*/}}
{{- define "nexus-strike.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{ .Values.secrets.existingSecret }}
{{- else -}}
{{ include "nexus-strike.fullname" . }}
{{- end -}}
{{- end -}}
