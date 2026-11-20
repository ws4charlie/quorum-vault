{{- define "qv.name" -}}{{ default "qv" .Values.nameOverride }}{{- end -}}

{{/* qv.fullname: <release>-<component> */}}
{{- define "qv.fullname" -}}{{ printf "%s-%s" .ctx.Release.Name .c | trunc 63 | trimSuffix "-" }}{{- end -}}

{{- define "qv.labels" -}}
app.kubernetes.io/name: {{ include "qv.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .c }}
app.kubernetes.io/part-of: quorum-vault
quorumvault.io/zone: business
app.kubernetes.io/managed-by: {{ .ctx.Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .ctx.Chart.Name .ctx.Chart.Version }}
{{- end -}}

{{- define "qv.selector" -}}
app.kubernetes.io/name: {{ include "qv.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .c }}
{{- end -}}

{{/* The image reference: repository@digest, or repository:tag when only a tag is given (kind). A digest wins. */}}
{{- define "qv.image" -}}
{{- $i := index .ctx.Values.images .k -}}
{{- if $i.digest -}}
{{- if regexMatch "^sha256:0+$" $i.digest -}}{{ fail (printf "images.%s.digest is the all-zero placeholder: set the real digest" .k) }}{{- end -}}
{{ $i.repository }}@{{ $i.digest }}
{{- else if $i.tag -}}{{ $i.repository }}:{{ $i.tag }}
{{- else -}}{{ fail (printf "images.%s needs a digest (or, outside production, a tag)" .k) }}{{- end -}}
{{- end -}}

{{/* A database URL for a service's own role. The certificate is the credential: no password. The files are the service's TLS identity. */}}
{{- define "qv.dsn" -}}
{{- $d := .ctx.Values.database -}}
postgres://{{ .role }}@{{ $d.host }}:{{ $d.port }}/{{ $d.name }}?sslmode={{ $d.sslmode }}&sslrootcert={{ .dir }}/ca.crt&sslcert={{ .dir }}/tls.crt&sslkey={{ .dir }}/tls.key
{{- end -}}

{{/* The approval page's origin (scheme://host), the one value the page's Ingress and the core's -approval-origins both come from. It must differ from the core's: the page is
     served from its own origin so that a script of the API's origin can never run as the page (and the passkey is bound to the page's origin). */}}
{{- define "qv.approvalOrigin" -}}
{{- $a := .Values.approval -}}
{{- $h := required "approval.ingress.host is required when approval.enabled" $a.ingress.host -}}
{{- if not .Values.ingress.public.enabled }}{{ fail "approval.enabled needs ingress.public.enabled: the page calls the core's public origin" }}{{ end -}}
{{- if eq (lower $h) (lower .Values.ingress.public.host) }}{{ fail (printf "approval.ingress.host %q is the core's public host: the approval page must be a different origin" $h) }}{{ end -}}
{{- if and .Values.ingress.passthrough.enabled (eq (lower $h) (lower .Values.ingress.passthrough.host)) }}{{ fail (printf "approval.ingress.host %q is the core's passthrough host: the approval page must be a different origin" $h) }}{{ end -}}
https://{{ $h }}
{{- end -}}

{{- define "qv.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .Values.runAsUser }}
runAsGroup: {{ .Values.runAsUser }}
fsGroup: {{ .Values.runAsUser }}
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "qv.containerSecurityContext" -}}
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

{{/* A Secret volume with group-readable files (mode 0440 = 288 decimal; fsGroup makes them readable by the image uid; the key is not world readable). */}}
{{- define "qv.secretVolume" -}}
- name: {{ .name }}
  secret:
    secretName: {{ .secret }}
    defaultMode: 288
{{- end -}}

{{/* The TLS identity of a service, as the three environment variables the binaries read (deploy/images/README.md). */}}
{{- define "qv.tlsEnv" -}}
QV_TLS_CERT: {{ .dir }}/tls.crt
QV_TLS_KEY: {{ .dir }}/tls.key
QV_TLS_CA: {{ .dir }}/ca.crt
QV_TLS_RELOAD: {{ .ctx.Values.tls.reload | quote }}
{{- end -}}

{{/* Probes: mode health (the default: the service's own health listener, plain http, /readyz for startup and readiness, /livez for liveness; PR #97), tcp (a named port or number) or none. */}}
{{- define "qv.probes" -}}
{{- $p := .probes -}}
{{- if eq $p.mode "tcp" }}
startupProbe: { tcpSocket: { port: {{ .tcpPort }} }, periodSeconds: 5, failureThreshold: 30 }
readinessProbe: { tcpSocket: { port: {{ .tcpPort }} }, periodSeconds: 10, failureThreshold: 3 }
livenessProbe: { tcpSocket: { port: {{ .tcpPort }} }, periodSeconds: 20, failureThreshold: 3 }
{{- else if eq $p.mode "health" }}
startupProbe: { httpGet: { path: /readyz, port: {{ int $p.healthPort }} }, periodSeconds: 5, failureThreshold: 30 }
readinessProbe: { httpGet: { path: /readyz, port: {{ int $p.healthPort }} }, periodSeconds: 10, failureThreshold: 3 }
livenessProbe: { httpGet: { path: /livez, port: {{ int $p.healthPort }} }, periodSeconds: 20, failureThreshold: 3 }
{{- end -}}
{{- end -}}

{{/* The environment that turns the health listener on (QV_HEALTH_LISTEN), only in mode health. */}}
{{- define "qv.healthEnv" -}}
{{- if eq .mode "health" }}
QV_HEALTH_LISTEN: {{ printf "0.0.0.0:%d" (int .healthPort) | quote }}
{{- end }}
{{- end -}}

{{/* The custody config is one existing Secret (custody.existingSecret), mounted whole. The chart renders no custody config. */}}
{{- define "qv.custodyVolume" -}}
- name: custody
  secret:
    secretName: {{ required "custody.existingSecret is required: the Secret that holds the whole custody config" .ctx.Values.custody.existingSecret }}
    defaultMode: 288
{{- end -}}

{{- define "qv.spread" -}}
{{- if .ctx.Values.topologySpread.enabled }}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        {{- include "qv.selector" . | nindent 8 }}
{{- end }}
{{- end -}}

{{- define "qv.pullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets: {{ toJson . }}
{{- end }}
{{- end -}}

{{/* ConfigMap name: release-qualified component + a hash of the content, so a change of content is a new object and a new pod template. */}}
{{- define "qv.cmName" -}}{{ printf "%s-%s-%s" .ctx.Release.Name .c (.data | sha256sum | trunc 10) | trunc 63 | trimSuffix "-" }}{{- end -}}
