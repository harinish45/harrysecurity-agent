{{- define "nexus-strike.name" -}}
nexus-strike
{{- end -}}

{{- define "nexus-strike.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "nexus-strike.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
