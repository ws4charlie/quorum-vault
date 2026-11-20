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

{{/* A Secret volume with group-readable files (0440 = 288 decimal; fsGroup makes them readable by the image uid; the PIN file rule accepts 0440, no world bit). With `trust` (the name of a trust-bundle ConfigMap of qv-certs, `qv-trust-<zone>-<hash>`) the CA file of the directory is that bundle and not the `ca.crt` cert-manager put in the Secret; the Secret contributes only tls.crt and tls.key. */}}
{{- define "qp.secretVolume" -}}
- name: {{ .name }}
{{- if .trust }}
  projected:
    defaultMode: 288
    sources:
      - secret:
          name: {{ .secret }}
          items: [{ key: tls.crt, path: tls.crt }, { key: tls.key, path: tls.key }]
      - configMap:
          name: {{ .trust }}
          items: [{ key: ca.crt, path: ca.crt }]
{{- else }}
  secret:
    secretName: {{ .secret }}
    defaultMode: 288
{{- end }}
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
{{- if and .Values.metrics.agent.enabled (not .Values.network.metricsRemoteWrite.to) }}{{ fail "network.metricsRemoteWrite.to is required when metrics.agent.enabled: the monitoring endpoint (an empty list would mean no rule at all)" }}{{ end -}}
{{- if and .Values.metrics.agent.enabled (not .Values.metrics.agent.cluster) }}{{ fail "metrics.agent.cluster is required when metrics.agent.enabled: the cluster name sent as the label qv_cluster (the party label comes from role)" }}{{ end -}}
{{- if and .Values.metrics.agent.enabled (not .Values.metrics.agent.remoteWrite.tlsSecret) }}{{ fail "metrics.agent.remoteWrite.tlsSecret is required when metrics.agent.enabled: the client certificate Secret" }}{{ end -}}
{{- if and (eq .Values.sealer.type "pkcs11") (not .Values.hsm.softhsm.enabled) (not .Values.hsm.module.path) }}{{ fail "hsm.module.path is required for sealer.type pkcs11 (the vendor's PKCS#11 module; the image has none)" }}{{ end -}}
{{- if and (eq .Values.sealer.type "pkcs11") (not .Values.hsm.softhsm.enabled) (not .Values.hsm.module.volume) }}{{ fail "hsm.module.volume is required for sealer.type pkcs11: the volume that holds the vendor's PKCS#11 module" }}{{ end -}}
{{- if and (eq .Values.sealer.type "pkcs11") (not .Values.hsm.softhsm.enabled) (not (hasPrefix "/etc/qv/hsm/" .Values.hsm.module.path)) }}{{ fail "hsm.module.path must lie under /etc/qv/hsm/ (where hsm.module.volume is mounted)" }}{{ end -}}
{{- end -}}

{{/* The metrics agent (Grafana Alloy): scrapes the loopback metrics ports of this pod (party; cosigner for B and C) and remote-writes outward with a client certificate. It listens on loopback only. */}}
{{- define "qp.agentConfig" -}}
{{- $a := .Values.metrics.agent -}}
{{- $role := include "qp.role" . -}}
prometheus.scrape "party" {
  targets    = [{"__address__" = {{ printf "127.0.0.1:%d" (int .Values.ports.metrics) | quote }}}]
  job_name   = "mpc-party"
  forward_to = [prometheus.remote_write.out.receiver]
}
{{- if ne $role "A" }}
prometheus.scrape "cosigner" {
  targets    = [{"__address__" = {{ printf "127.0.0.1:%d" (int .Values.ports.cosignerMetrics) | quote }}}]
  job_name   = "qv-cosigner"
  forward_to = [prometheus.remote_write.out.receiver]
}
{{- end }}
prometheus.remote_write "out" {
  endpoint {
    url = {{ required "metrics.agent.remoteWrite.url is required when metrics.agent.enabled" $a.remoteWrite.url | quote }}
    tls_config {
      cert_file = "/etc/qv/remote-write/tls.crt"
      key_file  = "/etc/qv/remote-write/tls.key"
      ca_file   = "/etc/qv/remote-write/ca.crt"
    }
  }
  {{- /* Identity on every series: the party (from role, so B's cosigner and C's differ) and the cluster. They win over externalLabels; an existing party label on a series is kept by the agent and equals the role. */}}
  external_labels = {
    {{- range $k, $v := $a.externalLabels }}
    {{- if and (ne $k "party") (ne $k "qv_cluster") }}
    {{ $k }} = {{ $v | quote }},
    {{- end }}
    {{- end }}
    party      = {{ $role | quote }},
    qv_cluster = {{ required "metrics.agent.cluster is required when metrics.agent.enabled: the name of this cluster, sent as the label qv_cluster" $a.cluster | quote }},
  }
}
{{- end -}}

{{/* One Service's type rules: LoadBalancer only as a PRIVATE endpoint (an internal-load-balancer annotation and source ranges). */}}
{{- define "qp.serviceGuard" -}}
{{- $s := .svc -}}
{{- if eq $s.type "LoadBalancer" -}}
{{- if not $s.annotations }}{{ fail (printf "service.%s: type LoadBalancer needs the internal-load-balancer annotations of your cloud in service.%s.annotations" .n .n) }}{{ end -}}
{{- if not $s.sourceRanges }}{{ fail (printf "service.%s: type LoadBalancer needs service.%s.sourceRanges (the parties' addresses)" .n .n) }}{{ end -}}
{{- else if ne $s.type "ClusterIP" }}{{ fail (printf "service.%s.type must be ClusterIP or LoadBalancer (private)" .n) }}{{ end -}}
{{- end -}}
