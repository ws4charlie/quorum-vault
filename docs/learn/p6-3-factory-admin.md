# P6-3 — The cold key administers the factory

In P6-2 the cold key could move funds back to hot. Here it also **owns the forwarder factory**: the one contract every deposit address pays through, and
therefore the one place where "where do customer deposits go?" is decided. Changing that is what you do after a hot key is stolen, and until now nothing in
the system could do it.

## The contract

[ForwarderFactory.sol](../../contracts/src/ForwarderFactory.sol) has one `destination` that every forwarder pays to, an `admin` (the cold key), a `guardian` (an online operations key) and a pending admin:

| Call | Who | Does |
|---|---|---|
| `setDestination(a)` | admin | changes where deposits go; also **unfreezes** after a freeze |
| `freeze()` | guardian or admin | destination becomes zero: sweeping stops, deposits still arrive and wait |
| `setGuardian(a)` | admin | rotates the guardian |
| `transferAdmin(a)` / `acceptAdmin()` | admin / the nominee | two-step hand-over; nothing changes until the nominee accepts |

## What was built

| Piece | Where |
|---|---|
| Request kinds `set-destination`, `freeze`, `set-guardian`, `transfer-admin`, `accept-admin`: calldata built **offline**, readable summary ("destination: old -> new"), pinned values in the offline config | [internal/coldsign](../../internal/coldsign/request.go), [sign.go](../../internal/coldsign/sign.go) |
| Online request, export, import, broadcast, tracking: the refill path with a `kind` ([migration 0008](../../migrations/0008_cold_actions.sql)) | [internal/custody/refills.go](../../internal/custody/refills.go) |
| Guardian freeze command | [cmd/qv-guardian](../../cmd/qv-guardian/main.go) |
| Sweeps wait when the factory's destination differs from the configured one | [sweeps.go](../../internal/custody/sweeps.go) |
| Operator spends from cold booked; a parked request closed through the API | `POST /v2/cold/spends`, `POST /v2/refills/{id}/close` |
| Runbook | [stolen-hot-key.md](../runbooks/stolen-hot-key.md) |

## The same ceremony, more kinds

`qv-cold` is the one offline tool. A request now has a `kind`; everything else is as in P6-2: M distinct operator approvals over the request hash, the durable record per
nonce (a second request with different content at one nonce is refused), the transaction built from the request's fields. For a factory call the tool also checks:

| Rule | Refusal |
|---|---|
| the kind is listed in the config's `actions` | `action kind "…" is not allowed by this signer's config` |
| the call targets the configured `factory` | `the call targets contract …, this signer administers the factory …` |
| a destination, guardian or new admin is in the matching pinned list (`new_destinations`, `new_guardians`, `new_admins`); `freeze` and `accept-admin` take no argument | `… is not one of the pinned destinations for set-destination` |
| gas and fee within limits; no asset or amount rides along | `gas … is above the limit`, `a factory call carries no asset or amount` |

The request also carries `current`: what the online side says the value is now, so the operator reads "destination: OLD -> NEW". The offline tool cannot check
`current` (it has no network); it is for the human, and it says so.

## The window after a destination change

The destination lives in three places that must agree: the factory (on chain), and the gateway's and cosigner's `sweep_destination` (the verifier refuses a sweep to anything else). The
business config's copy builds the sweep. After the ceremony the factory says NEW and the configs say OLD, so the planner sees the mismatch, logs one `ALERT`, and **plans nothing**: the
deposits wait on their forwarders. When the operators have updated the three configs and restarted, the waiting deposits and later ones go to NEW. Old deposit addresses keep working: a forwarder's address does
not depend on the destination.

## Fees and the books

A ceremony's fee is paid by the cold address, so it is booked `fee -> cold` and `Reconcile` stays exact. The new admin's `accept-admin` is paid by *its* address, which the books do not track, so that fee is an operator
expense (`fee -> opfund`). The guardian's gas is also an operator expense, booked by `qv-guardian` through `POST /v2/guardian/freezes`. Anything the operator does to the cold address outside the system is booked with
`POST /v2/cold/fundings` (money in) or `POST /v2/cold/spends` (money out).

## Tests

| Test | Shows |
|---|---|
| `TestFactoryAdminRotationCeremony` (hsm, mpc) | factory deployed frozen with the cold key as admin; ceremony sets the destination and sweeps start; a second ceremony moves it to a new hot shard; sweeps wait with one ALERT and lose nothing; configs updated, funds reach the new address; the old deposit address still works; spends booked, `Reconcile` clean |
| `TestGuardianFreezeAndCeremonyUnfreeze` (hsm, mpc) | a stranger's key is refused by the command; the guardian freezes (gas booked against the fee account); it cannot unfreeze; a ceremony does, and the waiting deposit is swept |
| `TestAdminRoleTransferTwoSteps` (hsm, mpc) | nominate; set the guardian; the new key accepts from its own config; the old admin's call reverts on chain; the new admin works |
| `TestParkedRefillIsClosedByAnOperator` | close needs an actor and a reason, only a parked request, and then a new one opens |
| [coldsign admin tests](../../internal/coldsign/admin_test.go) | every offline refusal above, the calldata selectors, the readable summary |

## Quiz

1. Why does the factory, not the hot key, decide where deposits go?
2. What can the guardian do, and what can it not?
3. Which two steps make an admin transfer, and why two?
4. Why can `freeze` be signed without a pinned value but `set-destination` cannot?
5. After a destination change, what happens to a deposit that arrives before the configs are updated?
6. Why does the planner log one ALERT and not one per pass?
7. Whose address pays for `accept-admin`, and how is that fee booked?
8. Why does the request carry `current` if the offline tool cannot verify it?
9. What does the offline tool refuse if a request names another contract?
10. What protects customers' deposits in the window between a hot-key theft and the freeze?

<details><summary>Answers</summary>

1. Forwarders pay to the factory's destination, which only its admin (the cold key) can change; a stolen hot key cannot redirect deposits.
2. It can call `freeze()`; it cannot change the destination, unfreeze, or touch funds (the contract reverts).
3. `transferAdmin(new)` then the nominee's `acceptAdmin()`. So a wrong address cannot take the role: the nominee must prove it can sign.
4. Freeze only stops things (destination to zero); setting a destination chooses where money goes, so it must be one of the pinned addresses.
5. It waits on its forwarder. Nothing is swept to the old or the new address until the gateway, cosigner and business config agree with the factory.
6. A flag in the service holds the alert until the mismatch has cleared, so a long wait does not flood the log.
7. The new admin's own address; the books do not track it, so it is an operator expense (fee -> opfund).
8. It is for the operator's eyes ("OLD -> NEW"); the rules that protect against a wrong value are the pinned lists, not `current`.
9. `the call targets contract …, this signer administers the factory …`.
10. Nothing in the hot wallet itself; deposits are protected because forwarders pay only to the factory's destination, which the hot key cannot change. The loss in that window is what the hot wallet holds.

</details>
