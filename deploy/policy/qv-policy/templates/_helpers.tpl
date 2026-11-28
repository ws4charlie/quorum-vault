{{/* Names and checks shared by every template. Every refusal here is a rule of the design (docs/deployment.md), not a convenience. */}}
{{- define "qvp.signing" -}}{{ if ne .Values.clusterKind "business" }}true{{ end }}{{- end -}}
{{- define "qvp.prod" -}}{{ if eq .Values.environment "production" }}true{{ end }}{{- end -}}
{{- define "qvp.actions" -}}{{ if eq .Values.enforcement "Deny" }}[Deny, Audit]{{ else }}[Warn, Audit]{{ end }}{{- end -}}
{{- define "qvp.labels" -}}
app.kubernetes.io/name: qv-policy
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: quorum-vault
app.kubernetes.io/managed-by: {{ .Release.Service }}
quorumvault.io/cluster-kind: {{ .Values.clusterKind }}
{{- end -}}
{{/* A ConfigMap our pods may use has a name that ends in a 10-character content hash (the charts' immutable ConfigMaps). */}}
{{- define "qvp.hashName" -}}^.+-[0-9a-f]{10}$
{{- end -}}
{{/* One binding per policy: Deny (or Warn) in every namespace this chart labels. */}}
{{- define "qvp.binding" -}}
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: {{ .name }}
  labels: {{- include "qvp.labels" .ctx | nindent 4 }}
spec:
  policyName: {{ .name }}
  validationActions: {{ include "qvp.actions" .ctx }}
  matchResources:
    namespaceSelector:
      matchLabels:
        quorumvault.io/policy: enforced
{{- end -}}
{{/* A CEL string literal. The inputs are checked by values.schema.json (registry) or are fixed names; toJson gives a valid CEL string for those. */}}
{{- define "qvp.lit" -}}{{ . | toJson }}{{- end -}}
{{- define "qvp.list" -}}[{{ range $i, $s := . }}{{ if $i }}, {{ end }}{{ include "qvp.lit" $s }}{{ end }}]{{- end -}}

{{- define "qvp.check" -}}
{{- $v := .Values -}}
{{- if not $v.clusterKind }}{{ fail "clusterKind is required: business, signing-core, party or broker" }}{{ end -}}
{{- if not $v.namespaces }}{{ fail "namespaces is required: the namespaces that hold QuorumVault workloads" }}{{ end -}}
{{- if not $v.registry }}{{ fail "registry is required: the registry prefix every image must come from, e.g. ghcr.io/<owner>/quorum-vault" }}{{ end -}}
{{- if and (or (eq $v.clusterKind "party") (eq $v.clusterKind "broker")) (ne (len $v.namespaces) 1) }}{{ fail "a party or broker cluster has exactly one namespace: no role may span two party namespaces" }}{{ end -}}
{{- if eq (include "qvp.prod" .) "true" -}}
{{- if ne $v.enforcement "Deny" }}{{ fail "production needs enforcement: Deny" }}{{ end -}}
{{- if not $v.requireDigest }}{{ fail "production needs requireDigest: true" }}{{ end -}}
{{- if not $v.signature.enabled }}{{ fail "production needs signature.enabled: true (images are signed by the publish job; unsigned images must be refused)" }}{{ end -}}
{{- if and (eq (include "qvp.signing" .) "true") (not (or $v.configWriters.users $v.configWriters.groups)) }}{{ fail "production signing clusters need configWriters (users or groups): who may create ConfigMaps" }}{{ end -}}
{{- end -}}
{{- if and $v.signature.enabled (eq $v.signature.mode "key") (not $v.signature.key.publicKey) }}{{ fail "signature.mode key needs signature.key.publicKey" }}{{ end -}}
{{- end -}}
