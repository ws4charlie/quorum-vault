{{- define "qm.labels" -}}
app.kubernetes.io/name: qv-monitoring
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: quorum-vault
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "qm.guards" -}}
{{- if not (has .Values.clusterKind (list "central" "business" "signing")) }}{{ fail "clusterKind must be central, business or signing" }}{{ end -}}
{{- end -}}
