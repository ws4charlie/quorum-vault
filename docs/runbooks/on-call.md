# Runbook: on call, what to look at first

Alerts are rules in `monitoring/`, evaluated centrally (chart `deploy/helm/qv-monitoring`). A party's alerts go to that party's operators. Each row: what it means, the first command, the runbook. Commands use `kubectl -n <ns>`; in a signing cluster only that domain's operators have access.

| # | Alert | Means | First command | Runbook |
|---|---|---|---|---|
| 1 | `QVMpcPartyUnhealthy`, `QVMpcRouteDiffersFromPreferred` | the gateway's health checks fail for a party; signing runs on another pair | `kubectl logs sts/<party> -c mpc-party --tail=100` and `kubectl get pods` in the party's cluster | [mpc-signing-pair.md](mpc-signing-pair.md) |
| 2 | `QVMpcHealthMetricsStale`, `QVMpcBlameMetricsMissing` | the gateway's metrics are missing: the agent sidecar or the gateway is down | `kubectl logs deploy/<gateway> -c metrics-agent --tail=50` | [mpc-signing-pair.md](mpc-signing-pair.md) |
| 3 | `QVMpcPeerCryptographicFailures` (and the other `QVMpcPeer*`) | sessions fail with one suspected peer; cryptographic ones freeze the keyset | `kubectl logs sts/<party> -c mpc-party \| grep ALERT` | [mpc-failures.md](mpc-failures.md), [mpc-keyset-freeze.md](mpc-keyset-freeze.md) |
| 4 | `QVMpcPartySealerNotReady`, `QVMpcPartyAllowlistRefused` | an attested party has no data keys: the broker says no or is unreachable | `kubectl logs sts/<party> -c mpc-party \| grep -i "attest\|ALERT"` | [tee-broker.md](tee-broker.md) |
| 5 | `QVAttestBrokerRefusals`, `QVAttestBrokerReloadRefused` | the broker refused a party or a new allowlist file | `qv-attest-broker audit verify -file <audit.log>` on the broker host, then read the last audit records | [tee-broker.md](tee-broker.md) |
| 6 | `QVDrainRefused` (pending metric; use the log) | the zone refused a key-replacement drain | `kubectl logs deploy/<gateway> \| grep "ALERT drain refused"` | [key-replacement.md](key-replacement.md) |
| 7 | `QVTLSCertExpiringSoon`, `QVTLSCertExpired`, `QVTLSCertReloadFailing` | a certificate is not renewed or cannot be loaded | `kubectl get certificate -A` and `kubectl describe certificate <name>` | [certificates.md](certificates.md) |
| 8 | `QVPinnedCertExpiringSoon`, `QVAttestBrokerCertExpiringSoon` (pending), `QVTLSCAExpiringSoon` | a pinned certificate or a CA runs out in 30 days; renewal is by hand | `kubectl get secret <name> -o json \| jq -r '.data["tls.crt"]' \| base64 -d \| openssl x509 -noout -enddate` | [certificates.md](certificates.md) |
| 9 | `QVAuditArchiveLagging`, `QVAuditArchiveStoreErrors`, `QVAuditArchiveBadRecords`, `QVAuditArchiveSourceSilent` | audit heads are not reaching the archive, or a record is bad | `kubectl logs deploy/<release>-archiver --tail=100` | [audit-archive.md](audit-archive.md) |
| 10 | `QVMpcGatewayPair*Failures`, `QVMpcLinkUnhealthy` | the gateway cannot sign with a pair, or a party link is down | `kubectl logs deploy/<gateway> -c gateway \| grep ALERT` | [mpc-failures.md](mpc-failures.md) |
| 11 | `QVDepositsHeldTooLong`, `QVSweepHeldMetricsError` | credited deposits wait below the sweep threshold for over a day, or the metric cannot be read | `curl` `GET /v2/reconcile` as an operator and read `unswept` | [unswept-deposits.md](unswept-deposits.md) |

## Rules of thumb

- A **page** is a signing or key-safety problem: act now. A **ticket** is a thing to fix this week.
- Missing metrics are an alert (rows 2 and 9), not good news. In a signing cluster they come only from the agent sidecar; if it is down, look at its log and at the egress policy before anything else.
- Nothing in a signing cluster is reached from outside to fix a metrics problem. Do not open a scrape path.
- Alerts that need a log (row 6, and anything with `ALERT` in a program's log) are in the log store; example queries are in the `qv-monitoring` README.
- To change a rule: edit `monitoring/`, add a `promtool` test, run `ci/helm/sync-monitoring-rules.sh`, commit both.
