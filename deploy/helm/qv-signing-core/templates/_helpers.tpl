{{- define "qvs.name" -}}{{ default "qv" .Values.nameOverride }}{{- end -}}

{{- define "qvs.fullname" -}}{{ printf "%s-%s" .ctx.Release.Name .c | trunc 63 | trimSuffix "-" }}{{- end -}}

{{- define "qvs.labels" -}}
app.kubernetes.io/name: {{ include "qvs.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .c }}
app.kubernetes.io/part-of: quorum-vault
quorumvault.io/zone: signing
app.kubernetes.io/managed-by: {{ .ctx.Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .ctx.Chart.Name .ctx.Chart.Version }}
{{- end -}}

{{- define "qvs.selector" -}}
app.kubernetes.io/name: {{ include "qvs.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .c }}
{{- end -}}

{{/* A value that has no default: the chart refuses the literal REQUIRED and an empty string. */}}
{{- define "qvs.req" -}}
{{- if or (eq (toString .v) "REQUIRED") (eq (toString .v) "") -}}{{ fail (printf "%s is required: set it in the values of this release" .k) }}{{- end -}}{{ .v }}
{{- end -}}

{{/* Image reference: repository@digest, or repository:tag outside production. The all-zero placeholder digest is refused. */}}
{{- define "qvs.image" -}}
{{- $i := index .ctx.Values.images .k -}}
{{- if $i.digest -}}
{{- if regexMatch "^sha256:0+$" $i.digest -}}{{ fail (printf "images.%s.digest is the all-zero placeholder: set the real digest" .k) }}{{- end -}}
{{ $i.repository }}@{{ $i.digest }}
{{- else if $i.tag -}}{{ $i.repository }}:{{ $i.tag }}
{{- else -}}{{ fail (printf "images.%s needs a digest (or, outside production, a tag)" .k) }}{{- end -}}
{{- end -}}

{{/* A DSN for a service's own role; the certificate is the credential, so there is no password. */}}
{{- define "qvs.dsn" -}}
postgres://{{ .role }}@{{ .host }}:{{ .port }}/{{ .name }}?sslmode={{ .sslmode }}&sslrootcert={{ .dir }}/ca.crt&sslcert={{ .dir }}/tls.crt&sslkey={{ .dir }}/tls.key
{{- end -}}
{{- define "qvs.guardDSN" -}}{{- $g := .Values.guard -}}{{ include "qvs.dsn" (dict "role" $g.role "host" $g.host "port" $g.port "name" $g.name "sslmode" $g.sslmode "dir" "/etc/qv/tls") }}{{- end -}}
{{- define "qvs.jobsDSN" -}}{{- $j := .Values.jobs -}}{{ include "qvs.dsn" (dict "role" $j.role "host" (include "qvs.req" (dict "k" "jobs.host" "v" $j.host)) "port" $j.port "name" $j.name "sslmode" $j.sslmode "dir" "/etc/qv/link-tls") }}{{- end -}}

{{- define "qvs.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .Values.runAsUser }}
runAsGroup: {{ .Values.runAsUser }}
fsGroup: {{ .Values.runAsUser }}
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "qvs.containerSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .Values.runAsUser }}
runAsGroup: {{ .Values.runAsUser }}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
privileged: false
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/* A Secret volume with group-readable files: mode 0440 (288 decimal) and the pod's fsGroup (the image uid's group) make them readable by the non-root user and by nobody else. */}}
{{- define "qvs.secretVolume" -}}
- name: {{ .name }}
  secret:
    secretName: {{ .secret }}
    defaultMode: 288
{{- end -}}

{{- define "qvs.tlsEnv" -}}
QV_TLS_CERT: /etc/qv/tls/tls.crt
QV_TLS_KEY: /etc/qv/tls/tls.key
QV_TLS_CA: /etc/qv/tls/ca.crt
QV_TLS_RELOAD: {{ .Values.tls.reload | quote }}
{{- end -}}

{{- define "qvs.pullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets: {{ toJson . }}
{{- end }}
{{- end -}}

{{/* The name of an immutable ConfigMap: the content hash is part of the name, so a change is a new object and a new rollout. */}}
{{- define "qvs.cmName" -}}{{ printf "%s-%s-%s" .ctx.Release.Name .c (.data | toJson | sha256sum | trunc 10) | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "qvs.signingConfigName" -}}{{ include "qvs.cmName" (dict "ctx" . "c" "config" "data" (include "qvs.signingConfig" .)) }}{{- end -}}

{{- define "qvs.signingConfig" -}}
{{- $c := .Values.config.signing -}}
{{- if not $c -}}{{ fail "config.signing is required: the signing config JSON (--set-file config.signing=...)" }}{{- end -}}
{{- if kindIs "string" $c -}}{{ $c }}{{- else -}}{{ toPrettyJson $c }}{{- end -}}
{{- end -}}

{{/* The gateway's environment. One place, so the Deployment's name hash and the ConfigMap agree. */}}
{{- define "qvs.gatewayEnv" -}}
QV_GATEWAY_JOBS_DSN: {{ include "qvs.jobsDSN" . | quote }}
QV_GATEWAY_GUARD_DSN: {{ include "qvs.guardDSN" . | quote }}
QV_KAFKA_BROKERS: {{ include "qvs.req" (dict "k" "kafka.brokers" "v" .Values.kafka.brokers) | quote }}
QV_HEALTH_LISTEN: {{ printf "0.0.0.0:%d" (int .Values.gateway.healthPort) | quote }}
QV_MPC_METRICS_FILE: /var/lib/qv/metrics/mpc.prom
{{ include "qvs.tlsEnv" . }}
QV_LINK_TLS_CERT: /etc/qv/link-tls/tls.crt
QV_LINK_TLS_KEY: /etc/qv/link-tls/tls.key
QV_LINK_TLS_CA: /etc/qv/link-tls/ca.crt
QV_LINK_TLS_RELOAD: {{ .Values.tls.reload | quote }}
{{- if .Values.env }}
QV_ENV: {{ .Values.env | quote }}
{{- end }}
{{- if ne .Values.hsm.mode "none" }}
QV_HSM_PIN_FILE: /etc/qv/hsm-pin/pin
{{- end }}
{{- if eq .Values.hsm.mode "pkcs11" }}
QV_PKCS11_LIB: {{ .Values.hsm.pkcs11.module | quote }}
{{- else if eq .Values.hsm.mode "softhsm" }}
QV_PKCS11_LIB: /usr/lib/softhsm/libsofthsm2.so
SOFTHSM2_CONF: /run/qv/softhsm/softhsm2.conf
{{- end }}
{{- end -}}

{{- define "qvs.spread" -}}
{{- if .ctx.Values.topologySpread.enabled }}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        {{- include "qvs.selector" . | nindent 8 }}
{{- end }}
{{- end -}}

{{/* Guards that turn a wrong combination into a failed render instead of a bad cluster. */}}
{{- define "qvs.validate" -}}
{{- $m := .Values.hsm.mode -}}
{{- if not (has $m (list "none" "pkcs11" "softhsm")) -}}{{ fail "hsm.mode must be none, pkcs11 or softhsm" }}{{- end -}}
{{- if and (eq $m "softhsm") (ne .Values.env "dev") -}}{{ fail "hsm.mode softhsm is for development only: it needs env: dev (and the binary refuses SoftHSM otherwise)" }}{{- end -}}
{{- if and (eq .Values.env "dev") (ne $m "softhsm") (ne $m "none") -}}{{ fail "env: dev with a real HSM: dev is for kind only" }}{{- end -}}
{{- if and (eq $m "pkcs11") (not .Values.hsm.pkcs11.volume) -}}{{ fail "hsm.pkcs11.volume is required: where the PKCS#11 module comes from (README, HSM)" }}{{- end -}}
{{- if lt (int .Values.gateway.terminationGracePeriodSeconds) (add (int .Values.config.signTimeoutSeconds) 30) -}}{{ fail "gateway.terminationGracePeriodSeconds must be at least config.signTimeoutSeconds + 30" }}{{- end -}}
{{- end -}}

{{/* The metrics agent (Grafana Alloy): reads the textfile the gateway writes, in the pod, and remote-writes outward. It listens on loopback only. */}}
{{- define "qvs.agentConfig" -}}
{{- $a := .Values.metrics.agent -}}
prometheus.exporter.unix "gateway" {
  set_collectors = ["textfile"]
  textfile {
    directory = "/var/lib/qv/metrics"
  }
}
prometheus.scrape "gateway" {
  targets    = prometheus.exporter.unix.gateway.targets
  forward_to = [prometheus.remote_write.out.receiver]
}
prometheus.remote_write "out" {
  endpoint {
    url = {{ include "qvs.req" (dict "k" "metrics.agent.remoteWrite.url" "v" $a.remoteWrite.url) | quote }}
    tls_config {
      cert_file = "/etc/qv/remote-write/tls.crt"
      key_file  = "/etc/qv/remote-write/tls.key"
      ca_file   = "/etc/qv/remote-write/ca.crt"
    }
  }
  external_labels = {
    {{- range $k, $v := $a.externalLabels }}
    {{- if ne $k "qv_cluster" }}
    {{ $k }} = {{ $v | quote }},
    {{- end }}
    {{- end }}
    qv_cluster = {{ include "qvs.req" (dict "k" "metrics.agent.cluster" "v" $a.cluster) | quote }},
  }
}
{{- end -}}
