# Runbook: a hot key may be stolen

A hot key signs withdrawals and sweeps all day, so it is the one most likely to be attacked. The design assumes it can be lost, and limits
what that costs: **the hot wallet holds little** (the excess goes to cold, see P6-1), **the forwarder factory pays only to its destination**, and the
destination can be changed **only by the cold key**, in an offline ceremony. This runbook is the response. Read it before you need it; the
steps marked **prepare** must exist before an incident.

## What can and cannot happen with a stolen hot key

| | The attacker with the hot key can | The attacker cannot |
|---|---|---|
| Hot wallet | sign transfers out of the hot address, up to what it holds | touch the cold address |
| Deposits | nothing at the forwarders: they pay to the factory's destination | change the destination (only the admin, the cold key, can) |
| After the destination is moved | still sign with the old key, but nothing new arrives there | pull new deposits towards themselves |

## Roles and what you need ready (prepare)

| What | Where |
|---|---|
| Guardian key, online, one per chain, can only `freeze()` | `qv-guardian`, key file on the operations host |
| Cold key (the factory's admin), M-of-N operators | `qv-cold` on the offline machine, config with **pinned `new_destinations`** |
| A spare hot address already listed in `new_destinations` | **prepare**: generate the next hot key *now* (HSM key or a derived MPC key), put its address in the offline config. Adding an address to the offline config during an incident is possible but is a config change on the offline machine that all operators must witness |
| Cold address funded with gas | for the ceremony fees; book it with `POST /v2/cold/fundings` |
| The signing-zone configs and who may edit them | gateway and cosigner: `sweep_destination`, `hot_addresses`, signers |

## Step by step

| # | Who | Step | What it protects | What is lost in the window |
|---|---|---|---|---|
| 1 | on-call | **Freeze the factory.** `qv-guardian freeze -rpc … -factory … -key-file guardian.key -core http://…` (it checks the key is the guardian, sends `freeze()`, waits for the receipt, books the gas against the fee account) | new deposits stop being swept to the possibly stolen address; they stay in their forwarders, safe, and can be swept later | sweeping stops for **every** deposit address of the chain until step 5; customers' deposits are credited but not yet in hot. Withdrawals are **not** stopped by this step |
| 2 | on-call | **Stop the stolen key from signing.** Stop the gateway for that partition (or the whole gateway) and the withdrawal workflow; for an MPC key also stop party A. Do not delete anything | the attacker's requests cannot be signed through *our* path | funds already in the hot wallet are exposed to the attacker's own copy of the key: **the window between the theft and this step is lost money, bounded by the hot balance and the daily caps**. Withdrawals wait |
| 3 | security | **Investigate.** `GET /v2/reconcile`; look for `nonce consumed` ALERTs (a transaction we did not make); compare the chain history of the hot address with the ledger | tells you what was taken and whether more keys are involved | nothing moves meanwhile |
| 4 | key custodian | **Use the next hot key** (prepared). Add it as a shard: business config `hot_shards`, gateway `signers` and `hot_addresses`, cosigner config; restart the worker. For MPC: derive a new index from the keyset, or run a new DKG if the keyset itself is suspect (a Refresh does not help if both shares were taken together) | a clean key that the attacker has never seen | none |
| 5 | operators (M of N) | **Cold ceremony: set the destination to the new hot address.** `POST /v2/cold/actions {"kind":"set-destination","param":"<new hot address>"}`, export, `qv-cold inspect/approve/sign` (read: *destination: <old> -> <new>*), import | the destination can only be changed by the cold key; this is also the **unfreeze** | the ceremony takes as long as it takes (hours); sweeping stays frozen |
| 6 | config owners | **Update the signing-zone and business config by hand**: `sweep_destination` in the gateway, the cosigner and the business config; restart them. Until then sweeps are refused and wait (an `ALERT`), nothing is lost | the gateway and the cosigner never learn the destination from the business side | sweeping waits until this step is done |
| 7 | on-call | **Watch sweeps reach the new address**; `GET /v2/reconcile` must be clean; old deposit addresses still work (their address does not depend on the destination) | | |
| 8 | key custodian | **Retire the stolen key**: move what is left in the old hot wallet to the new one if you still can, then retire/destroy the key; rotate the guardian too if its key may have been seen: ceremony `set-guardian` | | |

## If the guardian key is the one that leaked

It can freeze and nothing else, so the damage is a denial of sweeping. Rotate it with the ceremony `set-guardian` (the new address must be in the offline
config's `new_guardians`). Until then any freeze is undone by `set-destination`.

## If the cold key is in doubt

Move the admin role to another cold key: ceremony `transfer-admin` (the new address pinned in `new_admins`), then **the new key** runs `accept-admin` from its own offline machine. After
that the old key's calls revert on chain. Then update the cold address in the signing-zone config and the business config. This is the slowest path; practise it.

## Drill

Once a quarter, on the test chain: freeze with the guardian, run the destination ceremony to a spare address, update the configs, check that a deposit sent before the change reaches the new
address, and that sweeps waited in between. `TestFactoryAdminRotationCeremony` and `TestGuardianFreezeAndCeremonyUnfreeze` do exactly this against anvil.
