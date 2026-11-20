#!/usr/bin/env bash
# Case: the cluster policies (deploy/policy/qv-policy, installed by policy.sh in kind mode) are live in the API server and refuse what they say they refuse. Each denied example is sent to the
# real API server (server-side dry run) and must be refused WITH the policy's own message, so a refusal from RBAC or a typo does not pass; each control is admitted.
# Production-only rules (digest, signature by Kyverno, development switches, the ConfigMap writer list) need production mode, which needs Kyverno: not here (README "Not done").
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"; set +e
rc=0; bad() { echo "FAIL: $*"; rc=1; }
VAP=qv-ptest-vap      # labelled for the policies only, NOT for Pod Security: otherwise Pod Security refuses a privileged pod first and the policy's own message is never seen
trap 'k delete namespace "$VAP" --wait=false >/dev/null 2>&1' EXIT
k get namespace "$NS_PTEST" >/dev/null 2>&1 || { echo "FAIL: $NS_PTEST does not exist (ci/kind/policy.sh)"; exit 1; }
k create namespace "$VAP" --dry-run=client -o yaml | k apply -f - >/dev/null
k label namespace "$VAP" quorumvault.io/policy=enforced --overwrite >/dev/null
IMG=qv-image/qv-core:local
# a pod that stays up for the exec checks: the node's own pause image under a name the registry rule accepts (the full docker.io name: containerd does not normalise a short one, and every new pod then fails to start)
docker exec "$QV_KIND_NAME-control-plane" ctr -n k8s.io images tag --force registry.k8s.io/pause:3.10 docker.io/qv-image/pause:local >/dev/null 2>&1 || bad "could not name the node's pause image"

# 1. every policy has its binding and no type-checking warning (the API server type-checks the expressions; the offline tests cannot)
for i in $(seq 30); do
  n="$(k get validatingadmissionpolicy -l app.kubernetes.io/name=qv-policy -o json | jq '[.items[] | select(.status.typeChecking != null)] | length')"
  t="$(k get validatingadmissionpolicy -l app.kubernetes.io/name=qv-policy -o json | jq '.items | length')"
  [ "$t" -gt 0 ] && [ "$n" = "$t" ] && break; sleep 2
done
[ "$t" -ge 5 ] || bad "only $t policies installed"
warn="$(k get validatingadmissionpolicy -l app.kubernetes.io/name=qv-policy -o json | jq -r '.items[] | select((.status.typeChecking.expressionWarnings // []) | length > 0) | .metadata.name')"
[ -z "$warn" ] || bad "type-checking warnings: $warn"
b="$(k get validatingadmissionpolicybinding -l app.kubernetes.io/name=qv-policy -o json | jq '.items | length')"
[ "$b" = "$t" ] || bad "$t policies, $b bindings"
echo "policies: $t, bindings: $b, type-checking warnings: none"

good_pod() { # ns name
  cat <<Y
apiVersion: v1
kind: Pod
metadata: { name: $2, namespace: $1 }
spec:
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 10001, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: c
      image: $IMG
      securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] }, readOnlyRootFilesystem: true }
Y
}
# admit: the manifest on stdin must be accepted. deny: it must be refused with a message that contains $1.
admit() { local what="$1" out; out="$(k apply --dry-run=server -f - 2>&1)" || bad "$what: refused: $out"; }
deny() { local want="$1" what="$2" out; out="$(k apply --dry-run=server -f - 2>&1)" && { bad "$what: ADMITTED"; return; }
  grep -qF -- "$want" <<< "$out" && echo "refused: $what" || bad "$what: refused for another reason: $out"; }

# the API server learns the new namespace label a moment later: wait until a pod that must be refused is refused
for i in $(seq 30); do good_pod "$VAP" probe | sed 's|^spec:|spec:\n  hostNetwork: true|' | k apply --dry-run=server -f - >/dev/null 2>&1 || break; sleep 1; done
admit "control: a conforming pod" < <(good_pod "$VAP" ok)
good_pod "$VAP" ok | sed 's|image: .*|image: docker.io/library/busybox:1|' | deny "images must come from qv-image" "image from another registry"
good_pod "$VAP" ok | sed 's|^spec:|spec:\n  hostNetwork: true|' | deny "hostNetwork, hostPID and hostIPC are not allowed" "hostNetwork"
good_pod "$VAP" ok | sed 's|^spec:|spec:\n  volumes: [{ name: h, hostPath: { path: /etc } }]|' | deny "hostPath volumes are not allowed" "hostPath volume"
good_pod "$VAP" ok | sed 's|allowPrivilegeEscalation: false,|privileged: true,|' | deny "privileged containers are not allowed" "privileged container"
good_pod "$VAP" ok | sed 's|capabilities: { drop: \[ALL\] }|capabilities: { drop: [ALL], add: [NET_ADMIN] }|' | deny "added Linux capabilities are not allowed" "added capability"
good_pod "$VAP" ok | sed 's|runAsNonRoot: true, runAsUser: 10001|runAsUser: 0|' | deny "must run as non-root" "root user"
good_pod "$VAP" ok | sed 's|allowPrivilegeEscalation: false|allowPrivilegeEscalation: true|' | deny "allowPrivilegeEscalation: false" "privilege escalation allowed"
good_pod "$VAP" ok | sed 's|automountServiceAccountToken: false|automountServiceAccountToken: true|' | deny "gets no ServiceAccount token" "automounted ServiceAccount token"
# Pod Security (the namespace of the policy chart itself): the API server's own check refuses a privileged pod there too
good_pod "$NS_PTEST" ok | sed 's|allowPrivilegeEscalation: false,|privileged: true,|' | deny "violates PodSecurity" "Pod Security restricted refuses a privileged pod"

# ConfigMaps of a signing cluster are immutable (kind mode has no writer list: that rule is production's)
deny "must be immutable" "a mutable ConfigMap" <<Y
apiVersion: v1
kind: ConfigMap
metadata: { name: mutable-0123456789, namespace: $NS_PTEST }
data: { a: b }
Y
admit "control: an immutable ConfigMap" <<Y
apiVersion: v1
kind: ConfigMap
metadata: { name: fixed-0123456789, namespace: $NS_PTEST }
immutable: true
data: { a: b }
Y

# Services and Ingress
svc() { cat <<Y
apiVersion: v1
kind: Service
metadata: { name: s, namespace: $NS_PTEST$2 }
spec: { type: $1, ports: [{ port: 80 }], selector: { a: b }$3 }
Y
}
svc NodePort "" "" | deny "NodePort are not allowed" "a NodePort Service"
svc LoadBalancer "" "" | deny "internal-load-balancer annotations" "a public LoadBalancer Service"
svc ClusterIP "" ", externalIPs: [192.0.2.1]" | deny "externalIPs are not allowed" "externalIPs"
admit "control: a private LoadBalancer Service" < <(svc LoadBalancer ", labels: {}, annotations: { quorumvault.io/endpoint: private, service.beta.kubernetes.io/aws-load-balancer-type: external, service.beta.kubernetes.io/aws-load-balancer-scheme: internal }" "")
deny "no Ingress or Gateway API route" "an Ingress in a signing namespace" <<Y
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: { name: i, namespace: $NS_PTEST }
spec: { rules: [{ host: example.test, http: { paths: [{ path: /, pathType: Prefix, backend: { service: { name: s, port: { number: 80 } } } }] } }] }
Y

# exec, attach, port-forward and debug into a pod: refused for an identity outside the break-glass group (here: an administrator by group, so RBAC allows it and only the policy says no),
# not refused for a member. The pod is a real one (the image is not a shell; the verdict is the admission's, a later "container not found" is the kubelet's).
good_pod "$NS_PTEST" victim | sed "s|image: .*|image: qv-image/pause:local|" | k apply -f - >/dev/null
kn "$NS_PTEST" wait --for=condition=Ready pod/victim --timeout=90s >/dev/null || bad "the victim pod is not running"
GROUP=qv:break-glass; ADMIN=(--as=lane-tester --as-group=system:masters); MEMBER=("${ADMIN[@]}" "--as-group=$GROUP")
MSG="for the break-glass group only"
out="$(k "${ADMIN[@]}" -n "$NS_PTEST" exec victim -- true 2>&1)";            grep -qF "$MSG" <<< "$out" && echo "refused: exec" || bad "exec by a non-member: $out"
out="$(k "${MEMBER[@]}" -n "$NS_PTEST" exec victim -- true 2>&1)";           grep -qF "$MSG" <<< "$out" && bad "exec by a member refused by the policy: $out" || echo "admitted: exec by a member (later: ${out:0:70})"
out="$(timeout 20 kubectl --context "$CTX" "${ADMIN[@]}" -n "$NS_PTEST" port-forward victim 18080:8080 2>&1)"; grep -qF "$MSG" <<< "$out" && echo "refused: port-forward" || bad "port-forward by a non-member: $out"
out="$(timeout 20 kubectl --context "$CTX" "${MEMBER[@]}" -n "$NS_PTEST" port-forward victim 18080:8080 2>&1)"; grep -qF "$MSG" <<< "$out" && bad "port-forward by a member refused by the policy: $out" || echo "admitted: port-forward by a member"
out="$(k "${ADMIN[@]}" -n "$NS_PTEST" debug victim --image=qv-image/pause:local --profile=restricted --attach=false -- true 2>&1)";  grep -qF "$MSG" <<< "$out" && echo "refused: debug (ephemeral container)" || bad "debug by a non-member: $out"
k -n "$NS_PTEST" delete pod victim --wait=false >/dev/null 2>&1
exit $rc
