{{/*
The Secret name of an identity (dict "zone" "name"). The ONE rule every chart uses; it mirrors pki.SecretName in internal/pki/catalog.go, and the chart
fails when catalog.json (generated from the Go rule) disagrees:
  business zone  qv-<name>-tls          signing zone  qv-signing-<name>-tls
*/}}
{{- define "qv-certs.secretName" -}}
{{- if eq .zone "signing" -}}qv-signing-{{ .name }}-tls{{- else -}}qv-{{ .name }}-tls{{- end -}}
{{- end -}}

{{/* The catalog entries this release makes, as a JSON list: the entries naming .Values.cluster (all of them for `all`), without operator identities unless asked. */}}
{{- define "qv-certs.selected" -}}
{{- $c := .Values.cluster -}}
{{- if not $c -}}{{ fail "cluster is required: business, signing-core, party-b, party-c or broker (all: kind only)" }}{{- end -}}
{{- if and (eq $c "all") (ne .Values.issuers.mode "ca") -}}{{ fail "cluster: all puts every zone in one cluster and is for kind and CI only: it needs issuers.mode: ca" }}{{- end -}}
{{- $cat := .Files.Get "catalog.json" | fromJson -}}
{{- $out := list -}}
{{- range $e := $cat.entries -}}
{{- if and (or (eq $c "all") (has $c $e.clusters)) (or (not $e.operator) $.Values.operatorCertificates) -}}
{{- if ne $e.secretName (include "qv-certs.secretName" (dict "zone" $e.zone "name" $e.name)) -}}{{ fail (printf "catalog.json says %s for %s/%s but the chart's rule says otherwise: run go generate ./internal/pki" $e.secretName $e.zone $e.name) }}{{- end -}}
{{- $out = append $out $e -}}
{{- end -}}
{{- end -}}
{{- if not $out -}}{{ fail (printf "no catalog identity belongs to cluster %q" $c) }}{{- end -}}
{{- $out | toJson -}}
{{- end -}}

{{/* The issuer of an identity (dict "cluster" "zone"): qv-<zone>, except a business-zone name in a signing cluster, which is a link certificate: qv-business-link. */}}
{{- define "qv-certs.issuer" -}}
{{- if and (eq .zone "business") (ne .cluster "business") (ne .cluster "all") -}}qv-business-link{{- else -}}qv-{{ .zone }}{{- end -}}
{{- end -}}

{{/* The issuers this release needs, as a JSON list of names, sorted. */}}
{{- define "qv-certs.issuerNames" -}}
{{- $names := dict -}}
{{- range $e := (include "qv-certs.selected" . | fromJsonArray) -}}
{{- $_ := set $names (include "qv-certs.issuer" (dict "cluster" $.Values.cluster "zone" $e.zone)) true -}}
{{- end -}}
{{- keys $names | sortAlpha | toJson -}}
{{- end -}}

{{/* The zones this release holds identities of, as a JSON list (the trust bundles it needs). */}}
{{- define "qv-certs.zones" -}}
{{- $z := dict -}}
{{- range $e := (include "qv-certs.selected" . | fromJsonArray) -}}{{- $_ := set $z $e.zone true -}}{{- end -}}
{{- keys $z | sortAlpha | toJson -}}
{{- end -}}

{{- define "qv-certs.labels" -}}
app.kubernetes.io/name: qv-certs
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: quorum-vault
quorumvault.io/cluster: {{ .Values.cluster }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}
