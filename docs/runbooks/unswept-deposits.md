# Runbook: deposits that are credited but not swept

A customer's deposit is credited as soon as the scan has it. It is moved from the deposit address to the hot wallet (swept) only when it is worth more than `k` times the fee of the sweep (`sweep.k`, default 20) and at least `sweep.min_sweep_wei`. Below that line a sweep would lose money, so the funds stay where they are. When fees are high, small deposits wait at their deposit addresses. This is by design, and it ends by itself. The planner looks at every such address again every `sweep.plan_interval`, with the fee of that moment: it sweeps when the fee falls or when the address receives more. Nothing here changes the rule.

## See it

`GET /v2/reconcile` (operators) returns, next to the checks, an `unswept` section: one group per asset and reason, and the addresses (up to 200). Each address has a `reason`:

| Reason | Means | Tell it apart by |
|---|---|---|
| `below_sweep_threshold` | worth less than `max(min_sweep, k x fee)` now | `value`, `fee` and `threshold` are given; `by_fee: true` means the fee alone holds it (it clears when the fee falls), `false` means it is under `min_sweep` (it clears only when more arrives); `since` is when it was first held |
| `sweep_pending` | a sweep is planned, signing or broadcast | `sweep_id` and `detail` (its status); look at the sweep as for any sweep |
| `sweep_failed` | the last sweep failed; the planner tries again after a wait that doubles up to one hour | `detail` is the reason; `sweep_id` names the sweep |
| `parked` | a sweep needs a person | `detail` starts with `parked:` and says why |

An address credited since the last planner pass is not listed yet: it is new, not waiting or stuck. These funds are not a difference for reconcile: the books and the chain both say they are at the deposit address, so the checks stay clean.

Metrics, from the worker (`qv-worker -metrics-listen`), per `chain`, `asset` and `cause` (`fee` or `min_sweep`):

- `qv_sweep_held_addresses`: how many addresses are held below the line
- `qv_sweep_held_amount`: their total, in the asset's base units
- `qv_sweep_held_oldest_seconds`: the age of the oldest

The alert for age is on `qv_sweep_held_oldest_seconds{cause="fee"}`: funds held for the fee alone for longer than the configured time (a day by default; a long fee spike is normal for hours). The `min_sweep` cause has no alert: funds under the floor wait for more.

## What to do

- **`below_sweep_threshold`: wait.** Check the fee on the chain. If the age alert fires, the fee has been high for the whole time, or the planner is not running: look at the next two rows.
- **`sweep_pending` for long, `sweep_failed`, `parked`:** a sweep problem, not a fee problem. Read the sweep's workflow and the log of `qv-worker`; for Bitcoin see [a send does not confirm](btc-stuck.md), for a refused sweep the gateway's log. A parked sweep is decided by a person.
- **Planner not running:** no row changes `updated_at`, and the watchdog should have raised an alert (see [on call](on-call.md)). `qv_worker_*` metrics and the `sweep-planner:<chain>` workflow show it.
- **Sweeping by hand at a loss** is not possible: there is no command for it, and none is added. If the business wants small deposits moved at any fee, lower `sweep.k` or `sweep.min_sweep_wei` in the core's config and restart the workers; the rule then applies to every address.

## How this runs on Kubernetes

Nothing new is deployed. The planner is the existing `sweep-planner` workflow in `qv-worker`; the state is the table `sweep_holds` (migration 0035: `qv_worker` writes it, `qv_core` reads it); the section is in the core's answer to `GET /v2/reconcile`; the metrics are on the worker's metrics port already scraped by `qv-monitoring`.
