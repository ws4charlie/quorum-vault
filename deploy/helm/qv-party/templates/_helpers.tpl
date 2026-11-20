{{- define "qp.name" -}}{{ default "qv-party" .Values.nameOverride }}{{- end -}}

{{/* The party this release runs. Refuses anything but A, B or C. */}}
{{- define "qp.role" -}}
{{- $r := .Values.role | default "" -}}
{{- if not (has $r (list "A" "B" "C")) }}{{ fail (printf "role is required and must be A, B or C (got %q)" $r) }}{{ end -}}
{{ $r }}
{{- end -}}

{{/* The release name is the name of the StatefulSet: <release>. Other objects: <release>-<what>. */}}
{{- define "qp.fullname" -}}{{ .Release.Name | trunc 52 | trimSuffix "-" }}{{- end -}}
{{- define "qp.child" -}}{{ printf "%s-%s" (include "qp.fullname" .ctx) .c | trunc 63 | trimSuffix "-" }}{{- end -}}

{{- define "qp.labels" -}}
app.kubernetes.io/name: {{ include "qp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: party
app.kubernetes.io/part-of: quorum-vault
quorumvault.io/zone: signing
quorumvault.io/party: {{ include "qp.role" . | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/* Labels of the backup Job's pod: NOT the party's selector labels (a Service or the StatefulSet must never pick it up). */}}
{{- define "qp.jobLabels" -}}
app.kubernetes.io/name: {{ include "qp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: party-backup
app.kubernetes.io/part-of: quorum-vault
quorumvault.io/zone: signing
quorumvault.io/party: {{ include "qp.role" . | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "qp.selector" -}}
app.kubernetes.io/name: {{ include "qp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: party
{{- end -}}

{{/* The image reference: repository@digest, or repository:tag when only a tag is given (kind). A digest wins. The all-zero placeholder is refused. */}}
{{- define "qp.image" -}}
{{- $i := index .ctx.Values.images .k -}}
{{- if $i.digest -}}
{{- if regexMatch "^sha256:0+$" $i.digest -}}{{ fail (printf "images.%s.digest is the all-zero placeholder: set the real digest" .k) }}{{- end -}}
{{ $i.repository }}@{{ $i.digest }}
{{- else if $i.tag -}}{{ $i.repository }}:{{ $i.tag }}
{{- else -}}{{ fail (printf "images.%s needs a digest (or, outside production, a tag)" .k) }}{{- end -}}
{{- end -}}

{{- define "qp.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .Values.runAsUser }}
runAsGroup: {{ .Values.runAsUser }}
fsGroup: {{ .Values.runAsUser }}
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "qp.containerSecurityContext" -}}
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

{{/* A Secret volume with group-readable files (0440 = 288 decimal; fsGroup makes them readable by the image uid; the PIN file rule accepts 0440, no world bit). */}}
{{- define "qp.secretVolume" -}}
- name: {{ .name }}
  secret:
    secretName: {{ .secret }}
    defaultMode: 288
{{- end -}}

{{- define "qp.partySecret" -}}{{ default (printf "qv-signing-mpc-party-%s-tls" (include "qp.role" . | lower)) .Values.tls.party.secretName }}{{- end -}}
{{- define "qp.token" -}}{{ default (get (dict "A" "qv-party-1" "B" "qv-party-2" "C" "qv-party-3") (include "qp.role" .)) .Values.hsm.token }}{{- end -}}

{{/* Probes: the health listener of the container (plain http, GET /livez and /readyz). Ready never depends on the other parties. */}}
{{- define "qp.probes" -}}
startupProbe: { httpGet: { path: /readyz, port: {{ .port }} }, periodSeconds: 5, failureThreshold: 60 }
readinessProbe: { httpGet: { path: /readyz, port: {{ .port }} }, periodSeconds: 10, failureThreshold: 3 }
livenessProbe: { httpGet: { path: /livez, port: {{ .port }} }, periodSeconds: 20, failureThreshold: 3 }
{{- end -}}

{{- define "qp.pullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets: {{ toJson . }}
{{- end }}
{{- end -}}

{{/* Guards shared by the pod templates. */}}
{{- define "qp.guards" -}}
{{- $role := include "qp.role" . -}}
{{- if and .Values.hsm.softhsm.enabled .Values.images.party.digest }}{{ fail "hsm.softhsm.enabled needs the -dev image referenced by tag: SoftHSM is never used with an image referenced by digest (production)" }}{{ end -}}
{{- if and .Values.hsm.softhsm.enabled (ne .Values.sealer.type "pkcs11") }}{{ fail "hsm.softhsm.enabled needs sealer.type pkcs11" }}{{ end -}}
{{- if eq .Values.sealer.type "attested" }}{{ fail "sealer.type attested is an extension point of the TEE tasks: not built in this chart yet" }}{{ end -}}
{{- if .Values.attestBroker.enabled }}{{ fail "attestBroker.enabled is an extension point of the TEE tasks: not built in this chart yet" }}{{ end -}}
{{- if and (eq .Values.sealer.type "pkcs11") (not .Values.hsm.softhsm.enabled) (not .Values.hsm.module.path) }}{{ fail "hsm.module.path is required for sealer.type pkcs11 (the vendor's PKCS#11 module; the image has none)" }}{{ end -}}
{{- if and (eq .Values.sealer.type "pkcs11") (not .Values.hsm.softhsm.enabled) (not .Values.hsm.module.volume) }}{{ fail "hsm.module.volume is required for sealer.type pkcs11: the volume that holds the vendor's PKCS#11 module" }}{{ end -}}
{{- if and (eq .Values.sealer.type "pkcs11") (not .Values.hsm.softhsm.enabled) (not (hasPrefix "/etc/qv/hsm/" .Values.hsm.module.path)) }}{{ fail "hsm.module.path must lie under /etc/qv/hsm/ (where hsm.module.volume is mounted)" }}{{ end -}}
{{- end -}}

{{/* One Service's type rules: LoadBalancer only as a PRIVATE endpoint (an internal-load-balancer annotation and source ranges). */}}
{{- define "qp.serviceGuard" -}}
{{- $s := .svc -}}
{{- if eq $s.type "LoadBalancer" -}}
{{- if not $s.annotations }}{{ fail (printf "service.%s: type LoadBalancer needs the internal-load-balancer annotations of your cloud in service.%s.annotations" .n .n) }}{{ end -}}
{{- if not $s.sourceRanges }}{{ fail (printf "service.%s: type LoadBalancer needs service.%s.sourceRanges (the parties' addresses)" .n .n) }}{{ end -}}
{{- else if ne $s.type "ClusterIP" }}{{ fail (printf "service.%s.type must be ClusterIP or LoadBalancer (private)" .n) }}{{ end -}}
{{- end -}}
