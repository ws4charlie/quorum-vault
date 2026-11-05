# Runbook: refilling a hot wallet from cold storage

When a hot wallet falls below its low-water mark, the system opens a **refill request** and logs an `ALERT` that names it. Cold funds
come back only through an offline ceremony that several people complete. Nothing online can move them.

> **What SoftHSM changes.** A hardware HSM enforces "M of N operators" itself, with cards. SoftHSM cannot, so `qv-cold` enforces it
> **in software**, with operator signatures. Every output of the tool says so. Treat it as a stand-in: the procedure below is the one a
> hardware HSM would follow, with the cards replacing the signature files.

## Roles

| Role | Does | Must not |
|---|---|---|
| **Requester** (online operator) | exports the request file, carries files across the air gap, imports the signed file, watches the refill | sign or approve |
| **Operators** (N people, M of them per ceremony; here 2 of 3) | each reads the request, checks it against what they expect, approves with their own key | approve something they did not read, or share their key |
| **Offline machine** | holds the `qv-cold` token and the config; no network at all | ever be connected |

## Before the first ceremony (once)

1. On the offline machine: `scripts/setup-softhsm.sh` creates the `qv-cold` token; `qv-cold keygen` creates the cold key and prints its address and public key.
   The **cold address** goes into the **signing zone's** `cold_addresses` (gateway and cosigner) and the business config.
2. Each operator makes a key on their own machine: `qv-cold operator-key -key operator.key` prints the public key; they hand over the public key, never the file.
3. Write the offline config (`internal/coldsign.Config`): chain and chain id, pool, operators and `threshold`, the **pinned hot addresses** (`destinations`),
   per asset the per-ceremony cap (`max_amount`) and token address, `max_fee_wei`, the HSM token/PIN variable/key id, `record_dir`.
   The PIN is in an environment variable, never in the file.
4. Fund the cold address as the treasury process says, then **book** it online: `POST /v2/cold/fundings` (`{"id","asset","shard","amount"}`). Outside funding that is not booked
   makes `Reconcile` fail its `cold` check, on purpose.

## The ceremony

| # | Who | Step |
|---|---|---|
| 1 | Requester | `GET /v2/refills` finds the request (`requested`); the `ALERT` in the worker log names it. |
| 2 | Requester | `POST /v2/refills/{id}/export` (header `X-Actor`) returns the request file. Nonce and fees are read from the node now; the fee cap is generous. Save it to removable media. |
| 3 | Requester | Carry the media to the offline machine. Files only: no QR code, no cable. |
| 4 | Each operator | `qv-cold inspect -config cfg.json -request request.json` and **read it**: the **destination** is one of your hot addresses, the **asset and amount** are what the alert said, the **chain** is right, the **fee** is plausible. If any of it is wrong: **stop** (see "On a mismatch"). |
| 5 | Each approving operator | `qv-cold approve -operator NAME -key operator.key -request request.json -out NAME.approval.json`. The tool prints what you are approving first. |
| 6 | Any operator | `qv-cold sign -config cfg.json -request request.json -approval a.json -approval b.json -out signed.json`. It checks the request, counts M distinct configured operators, signs in the HSM and writes the signed file. |
| 7 | Requester | Carry `signed.json` back. `POST /v2/refills/{id}/import` with its content. The system checks it is the **current** export, that the transaction is exactly the request, signed by the cold address. |
| 8 | Requester | Watch: `signed` → `broadcast` → `confirmed`. Confirm the hot balance and that `GET /v2/reconcile` is clean. |

The workflow waits for the signed file as long as it takes, and survives restarts. Importing the same file twice changes nothing.

## What `qv-cold sign` refuses, and what it prints

It refuses, with the reason in words: too few approvals (and which approvals did not count, and why), the same operator twice, an unknown operator or a signature that
does not verify, an approval of another request, a destination that is not pinned, an amount above the cap, another chain or chain id or pool, a request not from the cold address,
a fee above the cap, a token that is not the configured one, a request file whose hash does not match its content, and **a nonce that was already signed for different content** (a durable record
in `record_dir` survives restarts; a re-export with only higher fees is the same content and is allowed).

## On a mismatch

- **The request does not match what you expected** (destination, asset, amount, chain): do not approve. Tell the requester and the on-call; treat it as a possible compromise of the online side. The offline tool will not sign a destination outside its pinned list anyway, so the worst case is a *wrong amount* up to the cap: that is why operators read it.
- **The tool says the file is damaged**: the media or the file was changed. Do not approve; export again.
- **Import says "re-exported, or this is another request"**: a newer export exists. Run the ceremony for the newest request file.
- **The cold nonce moved** (someone spent from the cold address): export again. The new revision has the new nonce; the old signed file cannot be imported.
- **A signed file was imported and broadcast, but does not confirm**: you get one `ALERT`. The system **never** retries with a new nonce. Look at the transaction on the node. If the transaction is still in the pool, wait or raise its fee with a *replacement of the same content* (the offline tool allows a higher-fee signature of the same payment at the same nonce); if the nonce was used by another transaction, the refill is parked and needs an operator.
- **The refill is parked** (`failure_reason` starts with `parked:`): its nonce was used by another transaction. Nothing was lost, and nothing else will move through that cold address until an operator closes it: `POST /v2/refills/{id}/close` with `X-Actor` and a reason (only a parked request that was never broadcast can be closed; the planner then opens a fresh one).

## Drill

Do the ceremony on the test chain every quarter with the same people, including one deliberate wrong request that the operators must catch.
