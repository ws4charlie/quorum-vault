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

{{/* Labels of the attested-mode Jobs (enrol, migrate): like qp.jobLabels with their own component, so the party's Service and StatefulSet never pick them up. */}}
{{- define "qp.jobLabelsFor" -}}
app.kubernetes.io/name: {{ include "qp.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .c }}
app.kubernetes.io/part-of: quorum-vault
quorumvault.io/zone: signing
quorumvault.io/party: {{ include "qp.role" .ctx | quote }}
app.kubernetes.io/managed-by: {{ .ctx.Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .ctx.Chart.Name .ctx.Chart.Version }}
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
{{/* The cosigner's names are its own per role (catalog cosigner-b|c, cosigner-link-b|c; internal/pki/catalog.go): a certificate of the other cosigner is not accepted. */}}
{{- define "qp.cosignerSecret" -}}{{ default (printf "qv-signing-cosigner-%s-tls" (include "qp.role" . | lower)) .Values.tls.cosigner.secretName }}{{- end -}}
{{- define "qp.cosignerLinkSecret" -}}{{ default (printf "qv-cosigner-link-%s-tls" (include "qp.role" . | lower)) .Values.tls.cosignerLink.secretName }}{{- end -}}
{{- define "qp.cosignerGuard" -}}{{ printf "qv_cosigner_%s_guard" (include "qp.role" . | lower) }}{{- end -}}
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
{{- if not (has .Values.sealer.type (list "pkcs11" "attested")) }}{{ fail "sealer.type must be pkcs11 or attested" }}{{ end -}}
{{- if not (has .Values.env (list "" "dev" "test")) }}{{ fail "env must be empty (production), dev or test" }}{{ end -}}
{{- if and (has .Values.env (list "dev" "test")) .Values.images.party.digest }}{{ fail "env dev or test with an image referenced by digest: dev and test run images referenced by tag; production runs digests and env empty" }}{{ end -}}
{{- if and .Values.hsm.softhsm.enabled (eq .Values.sealer.type "attested") (ne .Values.attested.phase "migrate") }}{{ fail "hsm.softhsm.enabled with sealer.type attested is only for the one-time migration (attested.phase migrate): the attested sealer uses no HSM" }}{{ end -}}
{{- include "qp.attestedGuards" . -}}
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

{{/* ------------------------------------------------------------------------------------------------------------------------------------------------------------
  Attested mode (sealer.type attested; docs/runbooks/tee-broker.md). One place for every name and rule, so the StatefulSet, the Jobs and the tests agree.
------------------------------------------------------------------------------------------------------------------------------------------------------------ */}}
{{/* The phase: run (the StatefulSet), enrol or migrate (only their Job). Always run for the pkcs11 sealer. */}}
{{- define "qp.phase" -}}{{ if eq .Values.sealer.type "attested" }}{{ .Values.attested.phase }}{{ else }}run{{ end }}{{- end -}}
{{- define "qp.sealedTLS" -}}{{ if and (eq .Values.sealer.type "attested") .Values.attested.tlsSealed }}yes{{ end }}{{- end -}}
{{- define "qp.linkSecret" -}}{{ default (printf "mpc-party-%s-broker-link-tls" (include "qp.role" . | lower)) .Values.attested.linkSecret }}{{- end -}}
{{/* The value of QV_ENV the party containers get: dev for SoftHSM, else env; nothing in production. */}}
{{- define "qp.qvEnv" -}}{{ if .Values.hsm.softhsm.enabled }}dev{{ else }}{{ .Values.env }}{{ end }}{{- end -}}

{{/* The sealer block of the party config, as JSON. pkcs11: token, module and the PIN file. attested: the broker, its pins, the link certificate and the attester. Public data only. */}}
{{- define "qp.sealerBlock" -}}
{{- $v := .Values -}}
{{- if eq $v.sealer.type "pkcs11" -}}
{{ dict "type" "pkcs11" "token" (include "qp.token" .) "lib" $v.hsm.module.path "pin_file" "/etc/qv/hsm-pin/pin" | toJson }}
{{- else -}}
{{- $a := $v.attested -}}
{{- $s := dict "type" "attested" "broker_url" $a.broker.url "broker_pins" $a.broker.pins "attester" (dict "type" $a.attester.type "ca_dir" "/etc/qv/attester-ca") -}}
{{- if include "qp.sealedTLS" . -}}
{{- $_ := set $s "broker_cert_file" "/etc/qv/broker-link/tls.crt" -}}
{{- $_ := set $s "broker_key_file" "/etc/qv/broker-link/tls.key" -}}
{{- end -}}
{{ $s | toJson }}
{{- end -}}
{{- end -}}

{{/* The enrolment config (mpc-party tls-init -config): only role, data_dir, tls_sealed and the sealer. It is a different FILE than the running config, so it has its own measurement. */}}
{{- define "qp.enrolConfig" -}}
{{- $c := dict "role" (include "qp.role" .) "data_dir" "/var/lib/qv/party/data" "tls_sealed" true "sealer" (include "qp.sealerBlock" . | fromJson) -}}
{{ $c | toPrettyJson }}
{{- end -}}
{{- define "qp.enrolConfigName" -}}{{ printf "%s-%s" (printf "%s-enrol-config" (include "qp.fullname" .) | trunc 52 | trimSuffix "-") (include "qp.enrolConfig" . | sha256sum | trunc 10) }}{{- end -}}

{{/* The config the party ran with BEFORE the migration (sealer pkcs11, the file TLS certificate): the -from of mpc-party migrate-seal. The -to is the running config itself. */}}
{{- define "qp.fromConfig" -}}
{{- $c := include "qp.partyConfig" . | fromJson -}}
{{- $_ := unset $c "tls_sealed" -}}
{{- $_ := set $c "cert_file" "/etc/qv/party-tls/tls.crt" -}}
{{- $_ := set $c "key_file" "/etc/qv/party-tls/tls.key" -}}
{{- $_ := set $c "sealer" (dict "type" "pkcs11" "token" (include "qp.token" .) "lib" .Values.hsm.module.path "pin_file" "/etc/qv/hsm-pin/pin") -}}
{{ $c | toPrettyJson }}
{{- end -}}
{{- define "qp.fromConfigName" -}}{{ printf "%s-%s" (printf "%s-from-config" (include "qp.fullname" .) | trunc 52 | trimSuffix "-") (include "qp.fromConfig" . | sha256sum | trunc 10) }}{{- end -}}

{{- define "qp.attestedGuards" -}}
{{- if eq .Values.sealer.type "attested" -}}
{{- $a := .Values.attested -}}
{{- if not (has $a.phase (list "run" "enrol" "migrate")) }}{{ fail "attested.phase must be run, enrol or migrate" }}{{ end -}}
{{- if not $a.broker.url }}{{ fail "attested.broker.url is required: https://<the attestation broker>:8443" }}{{ end -}}
{{- if not (hasPrefix "https://" $a.broker.url) }}{{ fail "attested.broker.url must start with https://" }}{{ end -}}
{{- if not $a.broker.pins }}{{ fail "attested.broker.pins is required: the pins of the broker's certificate public key" }}{{ end -}}
{{- if not .Values.network.broker.to }}{{ fail "network.broker.to is required in attested mode: the attestation broker (an empty list would mean no rule at all, and the party could not reach it)" }}{{ end -}}
{{- if not $a.attester.type }}{{ fail "attested.attester.type is required. Only mock exists (a SIMULATED enclave); the Nitro attester is not built yet, so a production attested party cannot start" }}{{ end -}}
{{- if ne $a.attester.type "mock" }}{{ fail (printf "attested.attester.type %q: only mock exists (a SIMULATED enclave). There is no production attester yet" $a.attester.type) }}{{ end -}}
{{- if not (has .Values.env (list "dev" "test")) }}{{ fail "attested.attester.type mock (the simulated attester) is for env dev or test only, as SoftHSM is; it needs the tee-sim image referenced by tag. Production has no attester yet" }}{{ end -}}
{{- if not $a.attester.mock.caSecret }}{{ fail "attested.attester.mock.caSecret is required for the mock attester: the Secret with the TEST CA (root.crt, intermediate.crt, intermediate.key)" }}{{ end -}}
{{- if and (ne $a.phase "run") (not $a.stopPartyAck) }}{{ fail (printf "attested.phase %s renders no StatefulSet: the release stops the party on purpose (the data volume has one user). Set attested.stopPartyAck=true to confirm" $a.phase) }}{{ end -}}
{{- if and (eq $a.phase "enrol") (not $a.tlsSealed) }}{{ fail "attested.phase enrol needs attested.tlsSealed (enrolment makes the sealed TLS key)" }}{{ end -}}
{{- if and (eq $a.phase "enrol") (lookup "apps/v1" "StatefulSet" .Release.Namespace (include "qp.fullname" .)) }}{{ fail "attested.phase enrol is for the first install only: this party's StatefulSet already exists and the upgrade would delete it. Enrolment is done once; a party that runs is never enrolled again" }}{{ end -}}
{{- if eq $a.phase "migrate" -}}
{{- /* Two steps, enforced: the party is stopped FIRST (kubectl scale statefulset --replicas=0, wait until the pod is gone), then this phase. Otherwise the upgrade removes the StatefulSet and starts the Job at once, and the Job can lose the data-directory lock to the old pod. lookup sees the cluster only at a real install or upgrade. */ -}}
{{- if not $a.migrate.partyStopped }}{{ fail "attested.phase migrate needs attested.migrate.partyStopped=true: stop the party first (kubectl scale statefulset <release> --replicas=0), wait until its pod is gone, then upgrade (runbook, Migration)" }}{{ end -}}
{{- $sts := lookup "apps/v1" "StatefulSet" .Release.Namespace (include "qp.fullname" .) -}}
{{- if and $sts (gt (int (dig "spec" "replicas" 0 $sts)) 0) }}{{ fail "attested.phase migrate: the party is still running (StatefulSet replicas > 0). Stop it first: kubectl scale statefulset <release> --replicas=0, wait until its pod is gone, then run this upgrade (runbook, Migration)" }}{{ end -}}
{{- if lookup "v1" "Pod" .Release.Namespace (printf "%s-0" (include "qp.fullname" .)) }}{{ fail "attested.phase migrate: the party pod still exists. Wait until it is gone before the migration (it holds the data volume and its lock)" }}{{ end -}}
{{- if not .Values.hsm.softhsm.enabled -}}
{{- if or (not .Values.hsm.module.path) (not .Values.hsm.module.volume) }}{{ fail "attested.phase migrate needs hsm.module.path and hsm.module.volume: the migration opens the old shares through the PKCS#11 sealer" }}{{ end -}}
{{- if not (hasPrefix "/etc/qv/hsm/" .Values.hsm.module.path) }}{{ fail "hsm.module.path must lie under /etc/qv/hsm/ (where hsm.module.volume is mounted)" }}{{ end -}}
{{- end -}}
{{- if $a.tlsSealed }}{{ fail "attested.phase migrate runs with attested.tlsSealed=false: the migration keeps the party's TLS certificate (its pin does not change). Move to a sealed TLS key later, as its own step (README)" }}{{ end -}}
{{- end -}}
{{- if .Values.backup.job.enabled }}{{ fail "backup.job.enabled is not supported with sealer.type attested: the backup export needs the attester. Run `mpc-party backup export` with kubectl exec in the running party pod (README)" }}{{ end -}}
{{- end -}}
{{- end -}}
