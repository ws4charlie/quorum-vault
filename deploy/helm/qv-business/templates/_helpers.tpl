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
{{- if $i.digest -}}{{ $i.repository }}@{{ $i.digest }}
{{- else if $i.tag -}}{{ $i.repository }}:{{ $i.tag }}
{{- else -}}{{ fail (printf "images.%s needs a digest (or, outside production, a tag)" .k) }}{{- end -}}
{{- end -}}

{{/* A database URL for a service's own role. The certificate is the credential: no password. The files are the service's TLS identity. */}}
{{- define "qv.dsn" -}}
{{- $d := .ctx.Values.database -}}
postgres://{{ .role }}@{{ $d.host }}:{{ $d.port }}/{{ $d.name }}?sslmode={{ $d.sslmode }}&sslrootcert={{ .dir }}/ca.crt&sslcert={{ .dir }}/tls.crt&sslkey={{ .dir }}/tls.key
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

{{/* Probes: mode tcp (port), http (path, port) or none. */}}
{{- define "qv.probes" -}}
{{- $p := .probes -}}
{{- if eq $p.mode "tcp" }}
startupProbe: { tcpSocket: { port: {{ .port }} }, periodSeconds: 5, failureThreshold: 30 }
readinessProbe: { tcpSocket: { port: {{ .port }} }, periodSeconds: 10, failureThreshold: 3 }
livenessProbe: { tcpSocket: { port: {{ .port }} }, periodSeconds: 20, failureThreshold: 3 }
{{- else if eq $p.mode "http" }}
startupProbe: { httpGet: { path: {{ $p.httpPath }}, port: {{ .port }}, scheme: HTTPS }, periodSeconds: 5, failureThreshold: 30 }
readinessProbe: { httpGet: { path: {{ $p.httpPath }}, port: {{ .port }}, scheme: HTTPS }, periodSeconds: 10, failureThreshold: 3 }
livenessProbe: { httpGet: { path: {{ $p.httpPath }}, port: {{ .port }}, scheme: HTTPS }, periodSeconds: 20, failureThreshold: 3 }
{{- end -}}
{{- end -}}

{{/* The custody config pieces. The merged file is read by the core and the worker. */}}
{{- define "qv.custodyJSON" -}}
{{- $j := toJson .Values.custody.config -}}
{{- if or (contains "\"rpc_password\"" $j) (contains "\"rpc_user\"" $j) -}}
{{- fail "custody.config must not hold rpc_user or rpc_password: put chain credentials in the overlay Secret (custody.credentials)" -}}
{{- end -}}
{{- toPrettyJson .Values.custody.config -}}
{{- end -}}

{{/* Init container: merge the credential overlay (a Secret) over the base config (a ConfigMap) into a memory-backed emptyDir. */}}
{{- define "qv.renderInit" -}}
- name: render-config
  image: {{ include "qv.image" (dict "ctx" .ctx "k" "render") | quote }}
  imagePullPolicy: {{ .ctx.Values.imagePullPolicy }}
  command: ["sh", "-c", "jq -s '.[0] * .[1]' /in/base/config.json /in/credentials/{{ .ctx.Values.custody.credentials.key }} > /out/config.json"]
  securityContext:
    {{- include "qv.containerSecurityContext" .ctx | nindent 4 }}
  resources:
    requests: { cpu: 10m, memory: 16Mi }
    limits: { cpu: 100m, memory: 64Mi }
  volumeMounts:
    - { name: custody-base, mountPath: /in/base, readOnly: true }
    - { name: custody-credentials, mountPath: /in/credentials, readOnly: true }
    - { name: custody, mountPath: /out }
{{- end -}}

{{- define "qv.custodyVolumes" -}}
- name: custody-base
  configMap: { name: {{ include "qv.fullname" (dict "ctx" .ctx "c" "custody") }} }
- name: custody-credentials
  secret: { secretName: {{ .ctx.Values.custody.credentials.secretName }}, defaultMode: 288 }
- name: custody
  emptyDir: { medium: Memory, sizeLimit: 1Mi }
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
