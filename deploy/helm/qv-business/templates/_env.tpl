{{/* The data of each environment ConfigMap, one template per component: the ConfigMap and the Deployment that reads it both take the name from the content. */}}
{{- define "qv.env.core" -}}
QV_HTTP_ADDR: {{ printf "0.0.0.0:%d" (int .Values.core.port) | quote }}
DATABASE_URL: {{ include "qv.dsn" (dict "ctx" . "role" "qv_core" "dir" "/etc/qv/tls") | quote }}
QV_TEMPORAL_ADDR: {{ .Values.temporal.address | quote }}
QV_OIDC_ISSUER: {{ .Values.oidc.issuer | quote }}
QV_OIDC_AUDIENCE: {{ .Values.oidc.audience | quote }}
QV_OIDC_ROLES_CLAIM: {{ .Values.oidc.rolesClaim | quote }}
QV_OIDC_STEPUP_ACR: {{ .Values.oidc.stepupAcr | quote }}
QV_CORE_SERVICE_ALLOW: {{ ternary (printf "%s,business/agentgate" .Values.serviceAllow) .Values.serviceAllow (and .Values.agentgate .Values.agentgate.enabled) | quote }}
{{- with .Values.oidc.jwksUrl }}
QV_OIDC_JWKS_URL: {{ . | quote }}
{{- end }}
{{- with .Values.oidc.roleMap }}
QV_OIDC_ROLE_MAP: {{ . | quote }}
{{- end }}
{{- with .Values.oidc.serviceClients }}
QV_OIDC_SERVICE_CLIENTS: {{ . | quote }}
{{- end }}
{{- if .Values.oidc.caSecret }}
QV_OIDC_CA_FILE: /etc/qv/oidc/ca.crt
{{- end }}
{{- if .Values.approval.enabled }}
QV_APPROVAL_ORIGINS: {{ include "qv.approvalOrigin" . | quote }}
{{- end }}
{{- if .Values.metrics.enabled }}
QV_METRICS_ALLOW_NON_LOOPBACK: "1"
QV_CORE_METRICS_LISTEN: {{ printf "0.0.0.0:%d" (int .Values.metrics.port) | quote }}
{{- end }}
{{- include "qv.tlsEnv" (dict "ctx" . "dir" "/etc/qv/tls") | nindent 0 }}
{{- include "qv.healthEnv" .Values.core.probes | nindent 0 }}
{{- end -}}

{{- define "qv.env.worker" -}}
DATABASE_URL: {{ include "qv.dsn" (dict "ctx" . "role" "qv_worker" "dir" "/etc/qv/tls") | quote }}
QV_TEMPORAL_ADDR: {{ .Values.temporal.address | quote }}
{{- if .Values.custody.autoApprover.enabled }}
QV_AUTO_APPROVER_KEY_FILE: /etc/qv/approver/{{ .Values.custody.autoApprover.key }}
{{- end }}
{{- if .Values.metrics.enabled }}
QV_METRICS_ALLOW_NON_LOOPBACK: "1"
QV_WORKER_METRICS_LISTEN: {{ printf "0.0.0.0:%d" (int .Values.metrics.port) | quote }}
{{- end }}
{{- include "qv.tlsEnv" (dict "ctx" . "dir" "/etc/qv/tls") | nindent 0 }}
{{- include "qv.healthEnv" .Values.worker.probes | nindent 0 }}
{{- end -}}

{{- define "qv.env.relay" -}}
DATABASE_URL: {{ include "qv.dsn" (dict "ctx" . "role" "qv_relay" "dir" "/etc/qv/tls") | quote }}
QV_KAFKA_BROKERS: {{ .Values.kafka.brokers | quote }}
{{- if .Values.metrics.enabled }}
QV_METRICS_ALLOW_NON_LOOPBACK: "1"
{{- end }}
{{- include "qv.tlsEnv" (dict "ctx" . "dir" "/etc/qv/tls") | nindent 0 }}
{{- include "qv.healthEnv" .Values.relay.probes | nindent 0 }}
{{- end -}}

{{- define "qv.env.archiver" -}}
QV_KAFKA_BROKERS: {{ .Values.kafka.brokers | quote }}
QV_ARCHIVE_BUCKET: {{ .Values.archive.bucket | quote }}
QV_ARCHIVE_REGION: {{ .Values.archive.region | quote }}
{{- with .Values.archive.endpoint }}
QV_ARCHIVE_ENDPOINT: {{ . | quote }}
{{- end }}
{{- if .Values.archive.credentialsSecret }}
QV_ARCHIVE_ACCESS_KEY_FILE: /etc/qv/archive/{{ .Values.archive.accessKeyKey }}
QV_ARCHIVE_SECRET_KEY_FILE: /etc/qv/archive/{{ .Values.archive.secretKeyKey }}
{{- end }}
{{- if .Values.archive.tls.secretName }}
QV_ARCHIVE_TLS_CERT: /etc/qv/archive-tls/tls.crt
QV_ARCHIVE_TLS_KEY: /etc/qv/archive-tls/tls.key
QV_ARCHIVE_TLS_CA: /etc/qv/archive-tls/ca.crt
{{- end }}
{{- if .Values.metrics.enabled }}
QV_METRICS_ALLOW_NON_LOOPBACK: "1"
{{- end }}
{{- include "qv.tlsEnv" (dict "ctx" . "dir" "/etc/qv/tls") | nindent 0 }}
{{- include "qv.healthEnv" .Values.archiver.probes | nindent 0 }}
{{- end -}}

{{- define "qv.env.approval" -}}
QV_APPROVAL_LISTEN: {{ printf "0.0.0.0:%d" (int .Values.approval.port) | quote }}
QV_APPROVAL_DIR: /srv/approval
QV_OIDC_ISSUER: {{ .Values.oidc.issuer | quote }}
QV_APPROVAL_CLIENT_ID: {{ .Values.approval.clientId | quote }}
QV_APPROVAL_API: {{ printf "https://%s" .Values.ingress.public.host | quote }}
{{- with .Values.approval.assetDecimals }}
QV_APPROVAL_ASSET_DECIMALS: {{ . | quote }}
{{- end }}
{{- end -}}
