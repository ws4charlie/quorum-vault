# Runbook: replacing a cold key (cold-to-cold ceremony)

A cold key is replaced when its custodians change, its HSM reaches end of life, or the policy says so. The funds move from the old cold address to a new one **by a ceremony of the old key**, never through the hot wallet. Concept: [Hot and cold](../tiers.md), [Key replacement](../key-replacement.md). A stolen cold key is a different case: see "Emergency" below.

> **What SoftHSM changes.** As in the [refill runbook](cold-refill.md), M-of-N is enforced **in software** by `qv-cold` with operator signatures. A hardware HSM would enforce it with cards. The steps are the ones a hardware HSM would follow.

## What the tool will and will not sign

The **old** key's offline config gets a `cold_move` section. It is the only trust root for the move; the request file cannot widen it.

| Field | Meaning |
|---|---|
| `new_cold` | The only address a cold-to-cold move may pay. Never read from the request. Must not be the old address, a hot address or the factory. |
| `max_amount` | Cap of one move, per asset (EVM, Solana: base units; Bitcoin: satoshis). It is the treasury's size, not a refill's. |
| `min_approvals` | Optional. At least the config's `threshold`. Moving everything may ask for more people than a refill. |

`qv-cold` refuses, with the reason in words: a destination that is not `new_cold` (a hot address, a stranger, the old address), an amount of zero or above the cap, an asset that is not configured, another chain or pool, a request not from this cold address, a fee above the cap, a Bitcoin move with a change output or more than one output, too few distinct approvals, a request file whose hash does not match, a config without `cold_move`, and a second request for a nonce (EVM) or an outpoint (Bitcoin) or a nonce value (Solana) that was already signed for different content. Asking for the same request again returns the same signed file; nothing is signed twice.

## The order, and why

The order never leaves money without a watcher or an owner. Every step can be repeated.

| # | Step | Who | Money moves? |
|---|---|---|---|
| 1 | Make the new key (`qv-cold keygen`, with `-network` for Bitcoin, `-curve ed25519` for Solana) and its offline config. Custodians read the new address aloud from the new machine's screen. | Custodians of both keys | No |
| 2 | Add `cold_move.new_cold` to the **old** key's config. Each custodian compares it with the address on the new machine **by eye, character by character**. | Custodians | No |
| 3 | **The switch.** Pin the new address in the signing zone and in the business config; list the old address as retiring (below). | Config owners, two people | No |
| 4 | From now on hot-to-cold moves pay the new address. The old address stays in Reconcile. | Automatic | Yes, to the new address |
| 5 | **Cold-to-cold moves**, one request at a time, until the old address is empty. | Requester and old-key custodians | Yes |
| 6 | Check: the old address is empty on the chain, `GET /v2/reconcile` is clean. | Requester | No |
| 7 | Wait the **watch window** (30 days by default). The old address stays in `cold.retiring`. | - | No |
| 8 | Remove `cold.retiring`; **destroy the old key** by ceremony. | Custodians | No |

### 3. The switch

| Where | What changes | Restart |
|---|---|---|
| Signing zone: gateway and every cosigner config | `cold_addresses` gets the **new** address | gateway and cosigners |
| Business config (core and worker) | `cold.addresses` gets the **new** address; `cold.retiring` gets the **old** address under the same key | core and worker |

Change the zone first. Between the two changes a hot-to-cold move is refused (the zone pins one address and the core builds to the other) and tried again; nothing can reach a wrong address. The pins are plain configuration read at start, not a signed setting: the change is a deployment, reviewed by two people. A signed setting would need a new operator-signed record, a table in the zone and a check in the gateway and each cosigner, as the BTC fee caps have; that is a task of its own.

The books keep **the same cold ledger account**, with a new address behind it. The books count value per pool, and a move between two cold addresses of one pool changes who owns nothing. A second account would need a move between accounts for every transfer and a reconcile check per address. With `cold.retiring` set, Reconcile adds the old address's balance to the new one's: the cold check stays exact before, during and after the move. A cold move books nothing at broadcast, and only its network fee at settlement (old cold to fee account).

### 5. The moves, per chain

On EVM and Bitcoin, open the next request with `POST /v2/cold/moves` (an admin, fresh login). It returns the open request, or `{"done": true}` when the old address holds nothing. Then run the ceremony of the [refill runbook](cold-refill.md) with the **old key's** custodians: export (`POST /v2/refills/{id}/export`), `qv-cold inspect`, `approve`, `sign`, import, watch it confirm. Read the **destination**: it must be the new address you checked in step 2.

| Chain | What one request moves | Notes |
|---|---|---|
| EVM | One asset: tokens first, the native coin last (it pays the gas of the rest). | Everything the old address holds of that asset. The native request sets the tip equal to the fee cap, so the price paid is exactly the cap and the address ends at zero. Each request takes the next nonce of the old address. |
| Bitcoin | The oldest available outputs, up to `max_inputs`, into **one** output at the new address. No change: the whole amount moves, less the fee at the node's rate. | An address with more outputs takes several rounds; ask again after each confirms. A move has no change, so it is not fee-bumped: a move that does not confirm waits, and the fee cap should be generous. |
| Solana | A step at a time, found again from the chain on every call: **each token** (everything, on the old address's durable nonce; the old token account is closed and the new address's is opened if missing), then **the SOL** (all but a small reserve that keeps the account above the rent minimum), then **the last step**: the old address's nonce accounts are closed (eight to a request, up to 64), their rent goes to the new address, and the **last** request also sends the reserve less its own fee, so the old address ends at **exactly zero** (an earlier request keeps the reserve, which pays the fees of the rest). A token account that holds no tokens is closed on its own, first, so its rent comes back too. | Use `POST /v2/cold-move/export` with `{"pool": "omnibus"}` (it returns `{"done": true}` at the end) and `POST /v2/cold-move/submit` with the request and the signed file; the submit waits until the transaction is final and books its cost. Run the **cold setup of the new address** (`/v2/cold-setup/export`) first. Prices are zero in these requests so the fee is exactly 5000 lamports. The nonce-closing step signs on a recent blockhash and must finish within its short life. |

### A request that must be rebuilt

An open cold-to-cold move **keeps its exported request**: asking for the export again returns the same file with the same hash, so a stray export cannot waste a ceremony (custodians may be signing it now). Rebuild only on purpose, for example when the fee rate moved so far that the request will not confirm and **nothing was signed for it**, or the signed file was destroyed:

1. Check that no signed file of the old request exists. If one does, import that file instead (a signed file whose request was replaced can no longer be imported).
2. On the **offline machine**, with at least M custodians present, remove the offline record of the old request from `record_dir`, because the signer refuses a different request where it remembers one: EVM, the directory `<chain>-<old address, lower case>-<nonce>`; Bitcoin, `btc/outpoints/<txid>-<vout>.json` for each input of the old request and `btc/signed/<request hash>.json`; Solana, `sol/nonces/<nonce account>-<nonce value>.json` and `sol/signed/<request hash>.json`. Write it in the minutes.
3. Online, an admin calls `POST /v2/refills/{id}/rebuild` with a reason and `"offline_record_cleared": true`. It is refused for a move that was imported, and audited (`cold_move.rebuilt`, with the old request hash). The next export is a new revision with a new hash.

Solana steps are not stored: each export is read from the chain and gives the same request while the chain has not changed. Ordinary refills are different on purpose: a re-export raises their fee, so a signed refill file of an older export cannot be imported (the import says so); the lost ceremony is the cost, and the runbook for refills tells operators to run the ceremony for the newest request.

### EVM: the factory admin and the guardian

If the old key is the **admin of the forwarder factory** (the production arrangement), moving its coins does not move that role. Run the existing ceremonies before the old key is destroyed: the old key signs `transfer-admin` to the new address (listed in its `new_admins`), then the new key signs `accept-admin` ([refill runbook](cold-refill.md) style, `POST /v2/cold/actions`). A guardian is a separate key and is replaced with `set-guardian` only if it is being replaced too.

### 7. Late arrivals

Who sends to a cold address? Operators (treasury top-ups) and the system's own hot-to-cold moves, which go to the new address from the switch. After the switch the old address appears only in old treasury templates, exchange whitelists and bookmarks: the operator must update them in step 3. A payment that still arrives is not lost while the old key lives: run step 5 again. That is why the old key is destroyed only after the watch window, and only if the old address was empty at the end of it.

### 8. What is destroyed

The old key in its HSM token, the old operators' key files and cards, the old offline config's `cold_move` section, and the old machine's records of signed nonces and outpoints **after** they were archived with the ceremony's minutes. Keep: the minutes, the signed files, the final Reconcile report, the address list. Destroy only after step 6 was repeated on the last day of the window.

## Who is in the room

Two groups, at least M custodians of each: the **old** key's custodians (they sign the moves) and the **new** key's (they make and check the new key). They may be the same people. One person is the requester online; the requester never approves. Nobody carries a phone or a network device into the offline room. Carried across the air gap: request files (in) and signed files (out), on removable media; nothing else.

## Emergency: a cold key suspected stolen

A cold signature needs M custodians **and** the HSM. Nothing online can stop a valid cold signature, and the signing zone's pins only limit hot-to-cold moves. The realistic cases:

| Case | What it means | What can be done |
|---|---|---|
| Fewer than M custodian keys leaked, HSM safe | The thief cannot sign | Replace the key as planned, faster. |
| HSM stolen with its PIN, fewer than M custodian keys | With a hardware HSM and cards: cannot sign. With **SoftHSM in this repository**: the thief can sign directly with the token, because M-of-N is simulated in software. | Treat as a full theft. |
| M custodian keys and the HSM | The thief can sign anything the key may sign | **Race**: the honest quorum moves everything to a new key at once, as in the planned order with the checks done fast. |

Steps, in this order:
1. **Stop adding money to the old address**: set `to_cold_per_hour` to 0 for the chain in the zone (restart), or switch the pin (step 3) if the new key already exists. Pause refills from it.
2. On EVM, if the old key is the factory admin: the guardian freezes the factory ([stolen hot key runbook](stolen-hot-key.md)); then `transfer-admin` to the new key by the same race.
3. Make the new key and run steps 2 to 5 without waiting for the watch window.
4. What the thief moves first cannot be taken back. There is no mechanism to disable a cold address; the zone cannot refuse a transaction it never sees.

## What is not built

- The pins are configuration with a restart, not a signed setting (see step 3).
- **Solana**: a SOL or token payment that arrives at the old address after its last step has no nonce account left to sign on. It needs a new cold setup of the old address first (its nonce accounts), then another run of the steps. Keep the old key until the watch window ends for this reason.
- The ceremony is simulated in software, as for refills.

## How this runs on Kubernetes

| What changes | Where | How |
|---|---|---|
| `cold_addresses` of the zone | `qv-signing-core` chart: the gateway and cosigner config (values or the ConfigMap they render) in the **signing** cluster | Change, then roll the gateway and cosigner Deployments. |
| `cold.addresses` and `cold.retiring` | `qv-business` chart: the config of `qv-core` and `qv-worker` in the **business** cluster | Change values, then roll both. |
| New migration `0034_cold_move.sql` (the `refills` amount rule for kind `cold-move`, and a `credit` column on `sol_cold_ops`) | Applied by the migration Job of `qv-business` before the new release | Needs no new grant: both tables have theirs. |
| New routes `POST /v2/cold/moves`, `POST /v2/cold-move/export`, `POST /v2/cold-move/submit` | `qv-core` | Admin role; the first and the last with step-up and a human, like `/v2/cold/actions`. No chart change. |
| The offline machine | Outside any cluster | `qv-cold` and its config files; nothing runs there from a chart. |
