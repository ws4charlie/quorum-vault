# qv-monitoring: metrics, rules and routing on Kubernetes

Design: `research/K8s-deployment.md` §10 and decision D12. One chart, one `clusterKind` per release.

| `clusterKind` | Renders | Where |
|---|---|---|
| `central` | one `PrometheusRule` per file of `monitoring/*.rules.yml`; the Alertmanager routing example if `alertmanager.enabled` | central monitoring, **outside every signing cluster** |
| `business` | `ServiceMonitor` for core, relay, archiver | the business cluster |
| `signing` | **nothing** | signing-core, party B, party C |

## Metrics: two paths, never a scrape into a signing cluster

- **Business cluster (scrape).** Set `metrics.enabled` in `qv-business`: core, relay and archiver bind the pod address (`QV_METRICS_ALLOW_NON_LOOPBACK=1`), each gets a `<release>-<component>-metrics` Service, and one NetworkPolicy admits the namespace `metrics.monitoringNamespace` on the metrics port and nothing else. The worker has no metrics port (it has no `-metrics-listen`); see the report. Install this chart with `clusterKind: business` for the `ServiceMonitor` objects. It needs the Prometheus Operator CRDs; without them, scrape the Services labelled `quorumvault.io/metrics=true` with `kubernetes_sd_configs` (role `endpoints`).
- **Signing clusters (push).** The charts `qv-signing-core` and `qv-party` have the same optional sidecar (`metrics.agent.enabled`, off by default): Grafana Alloy, image pinned by digest in `deploy/images/contract.json` (`externalImages.alloy`; a test compares both charts with it). It reads loopback metrics and the gateway's text files **inside the pod** and remote-writes **outward** to `metrics.agent.remoteWrite.url` with a client certificate (`remoteWrite.tlsSecret`: `tls.crt`, `tls.key`, `ca.crt`; no token, no password). It has the pod hardening of every container, no environment, no port, no data or socket mount. Egress: one rule to the endpoint you name (`network.metricsRemoteWrite`), port 443. A NetworkPolicy applies to the pod, so that path is open to the other container of the pod too; the rule names one address and one port. Verified: the rendered configuration passes `alloy validate` (v1.10.2). Not run in a cluster: the first real remote-write is for the kind lane.

The receiving end (central) is yours: a Prometheus or Mimir remote-write receiver that requires and checks client certificates, issued per cluster. Every agent labels all its series itself: `qv_cluster` from the required value `metrics.agent.cluster`, and in `qv-party` also `party` from `role` (so B's cosigner and C's cosigner, which have the same metric names and zone, stay apart, and the Alertmanager example can route a party's alerts to its operators on the `party` label). A render without a cluster name fails; `externalLabels` adds more labels but cannot replace these two.

## Rules

`monitoring/*.rules.yml` stay the source and keep their `promtool` tests (`go test ./monitoring/`). The chart reads its own copies in `rules/`; after changing a rule run `ci/helm/sync-monitoring-rules.sh` and commit both. `ci/helm` fails on a copy that differs, and on a rendered `PrometheusRule` that differs from its file. `monitoring/metrics_test.go` fails when a rule reads a metric no program emits, unless `monitoring/pending-metrics.txt` lists it (those rules and tests exist; they wait for the metric).

Set `rules.labels` to what your Prometheus `ruleSelector` matches.

## Alert routing

`alertmanager.enabled` renders one `AlertmanagerConfig`: alerts with `party="A"|"B"|"C"` go to that party's operators, everything else to `defaultReceiver`. Receivers name Secrets that hold the webhook URL; no URL or key is in values. The Prometheus Operator adds a namespace matcher to the routes of an `AlertmanagerConfig`; if the alerts come from another namespace, set `alertmanagerConfigMatcherStrategy: None` on the Alertmanager, or copy the routes into your own configuration. Alerts without a `party` label (certificates, archive) go to the default receiver.

## Logs

Every program writes JSON logs; important events carry `ALERT` in the message. Ship stderr to the central store per cluster (never across a signing boundary inbound) and alert on the lines. Examples:

```logql
# Loki: any refused drain in the last 10 minutes, per cluster
sum by (cluster) (count_over_time({app=~"qv-gateway|qv-cosigner"} |= "ALERT drain refused" [10m])) > 0
# Loki: any ALERT line from a party, by pod
sum by (pod) (count_over_time({app="qv-party"} |~ "ALERT" [5m])) > 0
```

```
# OpenSearch / Kibana query string: message:"ALERT" AND kubernetes.labels.app:(qv-gateway OR qv-cosigner OR qv-party)
```

Log-based alerts cover what has no counter yet (the drain refusal until `qv_drain_refusals_total` exists). Logs carry no secrets; keep it that way when adding lines.

## Checks

`ci/helm/monitoring-check.sh` (lint, render, kubeconform with the Prometheus Operator CRD schemas) and `ci/helm/monitoring_test.go`, both in `make helm-check`.
