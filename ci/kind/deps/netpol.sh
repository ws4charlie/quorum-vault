#!/usr/bin/env bash
# Network policies of the DEPENDENCY pods in the kind lane (the charts' own policies cover only their own pods). Every namespace is default-deny (the charts render that), and in
# production the dependencies are not pods of the chart's namespace. Here they are, so each needs the rules its own traffic uses, narrowed to that traffic, so that the
# isolation tests (an unlisted pod cannot reach Postgres) still mean something. $1 $2: the API server's node address and port, $3: the in-cluster `kubernetes` Service address.
set -euo pipefail
API_IP="$1"; API_PORT="$2"; SVC_IP="$3"
cat <<Y
# --- CloudNativePG instance pods, every namespace that has a database: the operator talks to the instance (status port 8000, 5432), the instance talks to the API server and DNS
Y
for ns in qv qv-signing qv-party-b qv-party-c; do cat <<Y
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: kind-cnpg, namespace: $ns }
spec:
  podSelector: { matchLabels: { cnpg.io/podRole: instance } }
  policyTypes: [Ingress, Egress]
  ingress:
    - from: [{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: cnpg-system } } }]
    - from: [{ podSelector: { matchLabels: { cnpg.io/podRole: instance } } }]
  egress:
    - to: [{ ipBlock: { cidr: $API_IP/32 } }]
      ports: [{ port: $API_PORT, protocol: TCP }]
    - to: [{ ipBlock: { cidr: $SVC_IP/32 } }]
      ports: [{ port: 443, protocol: TCP }]
    - to: [{ podSelector: { matchLabels: { cnpg.io/podRole: instance } } }]
    - to: [{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } } }]
      ports: [{ port: 53, protocol: UDP }, { port: 53, protocol: TCP }]
Y
done
cat <<Y
---
# --- business namespace: the stand-ins for what is external in production
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: kind-chain-idp-archive-in, namespace: qv }
spec:
  podSelector: { matchExpressions: [{ key: app, operator: In, values: [chain-stub, keycloak, seaweedfs] }] }
  policyTypes: [Ingress, Egress]
  ingress:
    - from: [{ podSelector: { matchLabels: { app.kubernetes.io/instance: qv-business } } }]
  egress:
    - to: [{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } } }]
      ports: [{ port: 53, protocol: UDP }, { port: 53, protocol: TCP }]
---
# Temporal: the server takes the gate (and its own schema job), talks to its database, DNS, and itself (history, matching: pod IP)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: kind-temporal, namespace: qv }
spec:
  podSelector: { matchExpressions: [{ key: app, operator: In, values: [temporal, temporal-schema, temporal-gate] }] }
  policyTypes: [Ingress, Egress]
  ingress:
    - from: [{ podSelector: { matchLabels: { app: temporal-gate } } }, { podSelector: { matchLabels: { app: temporal } } }]
      ports: [{ port: 7233, protocol: TCP }, { port: 7234, protocol: TCP }, { port: 7235, protocol: TCP }, { port: 7239, protocol: TCP }, { port: 6933, protocol: TCP }, { port: 6934, protocol: TCP }, { port: 6935, protocol: TCP }, { port: 6939, protocol: TCP }, { port: 7236, protocol: TCP }]
  egress:
    - to: [{ podSelector: { matchLabels: { cnpg.io/cluster: qv-temporal-db } } }]
      ports: [{ port: 5432, protocol: TCP }]
    - to: [{ podSelector: { matchLabels: { app: temporal } } }]
    - to: [{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } } }]
      ports: [{ port: 53, protocol: UDP }, { port: 53, protocol: TCP }]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: kind-temporal-db-in, namespace: qv }
spec:
  podSelector: { matchLabels: { cnpg.io/cluster: qv-temporal-db } }
  policyTypes: [Ingress]
  ingress:
    - from: [{ podSelector: { matchExpressions: [{ key: app, operator: In, values: [temporal, temporal-schema] }] } }]
      ports: [{ port: 5432, protocol: TCP }]
---
# Redpanda: DNS and its own address (the ACL step dials the Service)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: kind-redpanda, namespace: qv }
spec:
  podSelector: { matchLabels: { app: redpanda } }
  policyTypes: [Egress, Ingress]
  ingress:
    - from: [{ podSelector: { matchLabels: { app: redpanda } } }]
  egress:
    - to: [{ podSelector: { matchLabels: { app: redpanda } } }]
    - to: [{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } } }]
      ports: [{ port: 53, protocol: UDP }, { port: 53, protocol: TCP }]
Y

for ns in qv-signing qv-party-b qv-party-c; do cat <<Y
---
# the guard database takes its own namespace's gateway and party pods on 5432 (the signing-core chart renders the same for the gateway; the party chart renders egress only)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: kind-guard-db-in, namespace: $ns }
spec:
  podSelector: { matchLabels: { cnpg.io/cluster: qv-guard } }
  policyTypes: [Ingress]
  ingress:
    - from: [{ podSelector: { matchExpressions: [{ key: app.kubernetes.io/name, operator: In, values: [qv-party, qv-signing-core, qv-gateway] }] } }]
      ports: [{ port: 5432, protocol: TCP }]
Y
done
