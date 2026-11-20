{{- define "qab.name" -}}{{ default "qv-attest-broker" .Values.nameOverride }}{{- end -}}

{{/* The party this broker serves. Refuses anything but A, B or C. */}}
{{- define "qab.role" -}}
{{- $r := .Values.party.role | default "" -}}
{{- if not (has $r (list "A" "B" "C")) }}{{ fail (printf "party.role is required and must be A, B or C (got %q)" $r) }}{{ end -}}
{{ $r }}
{{- end -}}

{{- define "qab.fullname" -}}{{ .Release.Name | trunc 52 | trimSuffix "-" }}{{- end -}}
{{- define "qab.child" -}}{{ printf "%s-%s" (include "qab.fullname" .ctx) .c | trunc 63 | trimSuffix "-" }}{{- end -}}

{{- define "qab.labels" -}}
app.kubernetes.io/name: {{ include "qab.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: attest-broker
app.kubernetes.io/part-of: quorum-vault
quorumvault.io/zone: signing
quorumvault.io/party: {{ include "qab.role" . | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "qab.selector" -}}
app.kubernetes.io/name: {{ include "qab.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: attest-broker
{{- end -}}

{{/* The image reference: repository@digest, or repository:tag outside production. A digest wins. The all-zero placeholder is refused. */}}
{{- define "qab.image" -}}
{{- $i := .Values.images.broker -}}
{{- if $i.digest -}}
{{- if regexMatch "^sha256:0+$" $i.digest -}}{{ fail "images.broker.digest is the all-zero placeholder: set the real digest" }}{{- end -}}
{{ $i.repository }}@{{ $i.digest }}
{{- else if $i.tag -}}{{ $i.repository }}:{{ $i.tag }}
{{- else -}}{{ fail "images.broker needs a digest (or, outside production, a tag)" }}{{- end -}}
{{- end -}}

{{- define "qab.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .Values.runAsUser }}
runAsGroup: {{ .Values.runAsUser }}
fsGroup: {{ .Values.runAsUser }}
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "qab.containerSecurityContext" -}}
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

{{/* A Secret volume with group-readable files (0440 = 288 decimal; fsGroup makes them readable by the image uid). */}}
{{- define "qab.secretVolume" -}}
- name: {{ .name }}
  secret:
    secretName: {{ .secret }}
    defaultMode: 288
{{- end -}}

{{- define "qab.tlsSecret" -}}{{ default (printf "qv-attest-broker-%s-tls" (include "qab.role" . | lower)) .Values.tls.secretName }}{{- end -}}
{{- define "qab.token" -}}{{ default (printf "qv-attest-%s" (include "qab.role" . | lower)) .Values.hsm.token }}{{- end -}}

{{- define "qab.pullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets: {{ toJson . }}
{{- end }}
{{- end -}}

{{/* Where the broker reads the PIN. SoftHSM (development): the init container stages a 0400 copy in memory, because the broker refuses a PIN file with a group bit and kubelet adds one under fsGroup. */}}
{{- define "qab.pinPath" -}}{{ if .Values.hsm.softhsm.enabled }}/run/qv/pin/pin{{ else }}/etc/qv/hsm-pin/pin{{ end }}{{- end -}}

{{- define "qab.softhsmConf" -}}
directories.tokendir = /var/lib/qv/broker/softhsm/tokens
objectstore.backend = file
log.level = INFO
{{- end -}}

{{/* Guards: a wrong combination is a failed render, never a bad cluster. */}}
{{- define "qab.guards" -}}
{{- $v := .Values -}}
{{- $_ := include "qab.role" . -}}
{{- if not (has $v.env (list "" "dev" "test")) }}{{ fail "env must be empty (production), dev or test" }}{{ end -}}
{{- if and (not (has $v.env (list "dev" "test"))) (not $v.images.broker.digest) }}{{ fail "images.broker.digest is required in production (env empty): the broker image is referenced by digest, never by tag" }}{{ end -}}
{{- if and $v.simulation (not (has $v.env (list "dev" "test"))) }}{{ fail "simulation (the tee-sim broker, which accepts a TEST ONLY evidence root) is for env dev or test only" }}{{ end -}}
{{- if and $v.simulation $v.images.broker.digest }}{{ fail "simulation needs the tee-sim image referenced by tag: a simulated broker is never run from an image referenced by digest (production)" }}{{ end -}}
{{- if and $v.hsm.softhsm.enabled (not (has $v.env (list "dev" "test"))) }}{{ fail "hsm.softhsm.enabled is for env dev or test only: SoftHSM keeps the wrapping keys in files beside the broker" }}{{ end -}}
{{- if and $v.hsm.softhsm.enabled $v.images.broker.digest }}{{ fail "hsm.softhsm.enabled needs the -dev (or tee-sim) image referenced by tag: SoftHSM is never used with an image referenced by digest (production)" }}{{ end -}}
{{- if and (has $v.env (list "dev" "test")) $v.images.broker.digest }}{{ fail "env dev or test with an image referenced by digest: dev and test run images referenced by tag; production runs digests and env empty" }}{{ end -}}
{{- if and (not $v.hsm.softhsm.enabled) (not $v.hsm.module.path) }}{{ fail "hsm.module.path is required (the vendor's PKCS#11 module; the image has none)" }}{{ end -}}
{{- if and (not $v.hsm.softhsm.enabled) (not $v.hsm.module.volume) }}{{ fail "hsm.module.volume is required: the volume that holds the vendor's PKCS#11 module" }}{{ end -}}
{{- if and (not $v.hsm.softhsm.enabled) (not (hasPrefix "/etc/qv/hsm/" $v.hsm.module.path)) }}{{ fail "hsm.module.path must lie under /etc/qv/hsm/ (where hsm.module.volume is mounted)" }}{{ end -}}
{{- if not $v.party.callerPins }}{{ fail "party.callerPins is required: the pins of this party's certificate for the link to the broker (an empty list would let nobody in; the broker refuses it)" }}{{ end -}}
{{- if lt (len $v.operators.keys) (int $v.operators.minOperators) }}{{ fail "operators.keys must hold at least operators.minOperators public keys" }}{{ end -}}
{{- if lt (int $v.operators.minOperators) 1 }}{{ fail "operators.minOperators must be at least 1" }}{{ end -}}
{{- if not $v.trustRoots.configMap }}{{ fail "trustRoots.configMap is required: the ConfigMap that holds the evidence root certificate(s) (public PEM, made by you)" }}{{ end -}}
{{- if not (regexMatch "-[0-9a-f]{10}$" $v.trustRoots.configMap) }}{{ fail "trustRoots.configMap must be an immutable ConfigMap whose name ends in a 10-hex content hash (the cluster policy qv-pods admits no other ConfigMap): make it with the hash of the file in its name (README)" }}{{ end -}}
{{- if not $v.allowlist.file }}{{ fail "allowlist.file is required: the signed allowlist JSON (--set-file allowlist.file=allowlist.json)" }}{{ end -}}
{{- $al := fromJson $v.allowlist.file -}}
{{- if or (not (kindIs "map" $al)) (hasKey $al "Error") }}{{ fail "allowlist.file must be the JSON object the operators signed (it does not parse)" }}{{ end -}}
{{- if not (has (toString $v.service.type) (list "ClusterIP" "LoadBalancer")) }}{{ fail "service.type must be ClusterIP or LoadBalancer (private)" }}{{ end -}}
{{- if eq $v.service.type "LoadBalancer" -}}
{{- if not $v.service.annotations }}{{ fail "service: type LoadBalancer needs the internal-load-balancer annotations of your cloud in service.annotations" }}{{ end -}}
{{- if not $v.service.sourceRanges }}{{ fail "service: type LoadBalancer needs service.sourceRanges (this party's addresses)" }}{{ end -}}
{{- end -}}
{{- if not $v.network.partyIngress.from }}{{ fail "network.partyIngress.from is required: who may reach the broker (this party's endpoint). An empty list would mean no rule" }}{{ end -}}
{{- end -}}

{{/* The broker's JSON config (internal/attest/broker/config.go). Public data only: the PIN, the TLS key and the HSM module are files. */}}
{{- define "qab.config" -}}
{{- $v := .Values -}}
{{- $role := include "qab.role" . -}}
{{- $ops := dict -}}
{{- range $n, $k := $v.operators.keys }}{{ $_ := set $ops $n (dict "public_key" $k) }}{{ end -}}
{{- $p := dict "token" (include "qab.token" .) "pin_file" (include "qab.pinPath" .) -}}
{{- if $v.hsm.softhsm.enabled }}{{ $_ := set $p "lib" "/usr/lib/softhsm/libsofthsm2.so" }}{{ else }}{{ $_ := set $p "lib" $v.hsm.module.path }}{{ end -}}
{{- $c := dict "listen" (printf "0.0.0.0:%d" (int $v.ports.mtls)) "health_listen" (printf "0.0.0.0:%d" (int $v.ports.health)) "tls_cert" "/etc/qv/tls/tls.crt" "tls_key" "/etc/qv/tls/tls.key" "pkcs11" $p "trust_roots" (printf "/etc/qv/trust/%s" $v.trustRoots.key) "allowlist_file" "/etc/qv/allowlist/allowlist.json" "operators" (dict "keys" $ops "min_operators" (int $v.operators.minOperators)) "parties" (dict $role (dict "caller_pins" $v.party.callerPins)) "audit_log" "/var/lib/qv/broker/audit.log" "nonce_ttl" $v.nonceTTL "reload_interval" $v.reloadInterval "rate_per_minute" (int $v.rate.perMinute) "rate_burst" (int $v.rate.burst) -}}
{{ $c | toPrettyJson }}
{{- end -}}

{{/* The name of an immutable ConfigMap: the base is cut BEFORE the content hash is added, so a long release name cannot cut the hash off. */}}
{{- define "qab.cmName" -}}{{ printf "%s-%s" (printf "%s-%s" (include "qab.fullname" .ctx) .c | trunc 52 | trimSuffix "-") (.data | toJson | sha256sum | trunc 10) }}{{- end -}}
{{- define "qab.configName" -}}{{ include "qab.cmName" (dict "ctx" . "c" "config" "data" (include "qab.config" .)) }}{{- end -}}
{{- define "qab.allowlistName" -}}{{ include "qab.cmName" (dict "ctx" . "c" "allowlist" "data" .Values.allowlist.file) }}{{- end -}}
{{- define "qab.softhsmName" -}}{{ include "qab.cmName" (dict "ctx" . "c" "softhsm" "data" (include "qab.softhsmConf" .)) }}{{- end -}}
