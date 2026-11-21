# Runbook: deposits that are credited but not swept

A customer's deposit is credited as soon as the scan has it. It is moved from the deposit address to the hot wallet (swept) only when it is worth more than `k` times the fee of the sweep (`sweep.k`, default 20) and at least `sweep.min_sweep_wei`. Below that line a sweep would lose money, so the funds stay where they are. When fees are high, small deposits wait at their deposit addresses. This is by design, and it ends by itself. The planner looks at every such address again every `sweep.plan_interval`, with the fee of that moment: it sweeps when the fee falls or when the address receives more. Nothing here changes the rule.

## See it

`GET /v2/reconcile` (operators) returns, next to the checks, an `unswept` section: one group per asset and reason, and the addresses (up to 200). Each address has a `reason`:

| Reason | Means | Tell it apart by |
|---|---|---|
| `below_sweep_threshold` | worth less than `max(min_sweep, k x fee)` now | `cause` says why: `fee` (value reached `min_sweep`, the fee alone holds it: `value`, `fee` and `threshold` are given; clears when the fee falls), `min_sweep` (under the floor: clears only when more arrives), `fee_cap` (Bitcoin: the chain offers no sweep of it now, because the fee rate is over a cap or its outputs cost more than they carry: only `value`; clears when the fee falls); `since` is when it was first held |
| `sweep_pending` | a sweep is planned, signing or broadcast | `sweep_id` and `detail` (its status); look at the sweep as for any sweep |
| `sweep_failed` | the last sweep failed; the planner tries again after a wait that doubles up to one hour | `detail` is the reason; `sweep_id` names the sweep |
| `parked` | a sweep needs a person | `detail` starts with `parked:` and says why |
| `awaiting_plan` | worth sweeping and no sweep yet: credited since the last planner pass, or waiting for room (the open-sweep limit, free nonce accounts) | it should be gone within a few `plan_interval`; if it stays, the planner is not running or has no room (see below) |

Every address that holds credited, unswept funds is listed, once, with one reason. These funds are not a difference for reconcile: the books and the chain both say they are at the deposit address, so the checks stay clean.

Metrics, from the worker (`qv-worker -metrics-listen`), per `chain`, `asset` and `cause` (`fee` or `min_sweep`):

- `qv_sweep_held_addresses`: how many addresses are held below the line
- `qv_sweep_held_amount`: their total, in the asset's base units
- `qv_sweep_held_oldest_seconds`: the age of the oldest

The alert `QVDepositsHeldTooLong` (ticket) is on `qv_sweep_held_oldest_seconds{cause=~"fee|fee_cap"}`: funds held for the fee alone for more than a day (86400 seconds, written in `monitoring/deposits.rules.yml`; a long fee spike is normal for hours). To change the wait, edit that number, run `ci/helm/sync-monitoring-rules.sh` and commit both. The `min_sweep` cause has no alert: funds under the floor wait for more. `QVSweepHeldMetricsError` says the worker cannot read the table, so the age alert is blind.

## What to do

- **`below_sweep_threshold`: wait.** Check the fee on the chain. If the age alert fires, the fee has been high for the whole time, or the planner is not running: look at the next two rows.
- **`sweep_pending` for long, `sweep_failed`, `parked`:** a sweep problem, not a fee problem. Read the sweep's workflow and the log of `qv-worker`; for Bitcoin see [a send does not confirm](btc-stuck.md), for a refused sweep the gateway's log. A parked sweep is decided by a person.
- **`awaiting_plan` that stays, or a planner that does not run:** the watchdog should have raised an alert (see [on call](on-call.md)); the `sweep-planner:<chain>` workflow and the `qv_worker_*` metrics show it. With many open sweeps the planner makes no new ones until some finish.
- **Sweeping by hand at a loss** is not possible: there is no command for it, and none is added. If the business wants small deposits moved at any fee, lower `sweep.k` or `sweep.min_sweep_wei` in the core's config and restart the workers; the rule then applies to every address.

## How this runs on Kubernetes

Nothing new is deployed. The planner is the existing `sweep-planner` workflow in `qv-worker`; the state is the table `sweep_holds` (migration 0035: `qv_worker` writes it, `qv_core` reads it); the section is in the core's answer to `GET /v2/reconcile`; the metrics are on the worker's metrics port already scraped by `qv-monitoring`, whose rules file `deposits.rules.yml` holds the two alerts.
