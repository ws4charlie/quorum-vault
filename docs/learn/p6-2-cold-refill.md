# P6-2 — Cold to hot: the offline signer and the refill

P6-1 moves excess funds from hot to cold by itself, because that can only make them safer. The way back is the opposite: it
makes funds *more* exposed, so it needs people, an offline machine, and a signature that nothing online can produce.

## The pieces

| Piece | Where |
|---|---|
| Request, approval and signed-file formats; the signing rules; the durable nonce record | [internal/coldsign](../../internal/coldsign/sign.go) |
| The offline tool (`keygen`, `operator-key`, `inspect`, `approve`, `sign`) | [cmd/qv-cold](../../cmd/qv-cold/main.go) |
| Refill request, export, import, booking | [internal/custody/refills.go](../../internal/custody/refills.go), [migration 0007](../../migrations/0007_refills.sql) |
| Cold nonce, fees, raw broadcast, receipt | [internal/chain/evm/refill.go](../../internal/chain/evm/refill.go) |
| The workflow that waits days and tracks the transaction | [RefillWorkflow](../../internal/workflow/workflows.go) |
| Runbook | [docs/runbooks/cold-refill.md](../runbooks/cold-refill.md) |

## The flow

```
planner: hot below L -> refill request (amount = target - free), ALERT names it
operator: POST /v2/refills/{id}/export  -> request file (nonce and fees read online now)
 ---- files across the air gap ----
offline:  inspect (read it) -> each operator approves with their own key -> sign: checks, M approvals, HSM signs
 ---- file back ----
operator: POST /v2/refills/{id}/import -> checked against the current request
workflow: broadcast -> follow to confirmation -> book
```

The offline tool builds the transaction **itself from the request's fields**; it never takes a transaction from the online side. So what the
operators read in `inspect` (destination, asset, amount, nonce, worst-case fee) is exactly what gets signed.

## What makes the online side untrusted

The offline config is the only trust root. A request is checked against it whatever the online side says: destination in the **pinned list of
hot addresses**, asset known and its token address the configured one, amount ≤ a per-ceremony cap, chain, chain id, pool, `from` = the cold key's
address, fee ≤ a cap, a hash that matches the file (damage on the way is noticed), and M distinct configured operators with valid signatures over the request hash.
A durable record per nonce stops a second, different payment at a nonce that was already signed (a re-export with only higher fees is the same payment).

**M-of-N is software here.** A hardware HSM enforces it with cards; SoftHSM cannot. The tool says so in every run. Do not mistake it for the real thing.

**No network.** The offline tool opens no connection because it contains no network client at all. A test lists the import graph of `cmd/qv-cold` and
`internal/coldsign` and fails if `net`, `net/http`, gRPC, an Ethereum RPC client, a database driver or the Temporal and Kafka clients appear
([TestOfflineToolHasNoNetworkClient](../../internal/coldsign/sign_test.go)).

## Failure cases

| Case | What happens |
|---|---|
| Signed file imported twice | the second import is a no-op; one transaction |
| Fees too low or the cold nonce moved | export again: a new **revision** with a new hash. The old signed file no longer matches and is refused at import; both share a nonce, so they could not both mine anyway |
| A tampered signed file, or one for another request | refused at import with the reason |
| Broadcast but never confirms | one `ALERT`, and it keeps waiting. **Never** a new nonce automatically: a new nonce is a new ceremony |
| The cold nonce used by someone else | the broadcast says "nonce too low": the refill is **parked** with an `ALERT` |
| Only one open refill per cold address | a unique index; the cold address has one nonce |

## Booking

```
broadcast   refill -> cold   cold's on-chain balance is going down
confirmed   hot -> refill    the hot wallet has it; fee -> cold (the cold address paid the fee)
reverted    cold -> refill   undo; only the fee stays
funding     cold -> opfund   the operator's own deposit into cold, booked explicitly
```

P6-1 left `Reconcile` unable to cope with outside funding of the cold address. `POST /v2/cold/fundings` books it, so the `cold` check stays exact.

## Tests

| Test | Shows |
|---|---|
| `TestRefillCeremonyEndToEnd` (hsm, mpc) | the whole thing with the real `qv-cold` binary on files: request, export, 2-of-3, offline sign, import, mined, ledger and Reconcile clean, a second import is a no-op |
| `TestRefillImportAndReexportAttacks` | tampered file, file for another request, stale revision, cold nonce moved then re-exported, the old ceremony's file after confirmation, same nonce with other content refused offline |
| `TestRefillNotConfirmingAlertsOnceAndIsNeverRetried` | one ALERT, no second transaction, completes when it mines |
| `TestRefillCrashAtEveryBoundary` | worker killed after the send, after the record, after the confirm, after the settle; one transfer each |
| [coldsign tests](../../internal/coldsign/sign_test.go) | every offline refusal with its reason; import checks; no network client |
| [CLI test](../../cmd/qv-cold/main_test.go) | the same through the command line with a real key in the `qv-cold` token |

## Quiz

1. Why can hot to cold run without people but cold to hot cannot?
2. Why does the offline tool build the transaction itself instead of signing one it was sent?
3. What does the operator read in `inspect`, and why exactly those fields?
4. What is the difference between "content" and "request hash", and why does the nonce record use content?
5. What stops an old signed file from being broadcast after a re-export?
6. Why is there only one open refill per cold address?
7. What happens when a broadcast refill does not confirm, and what never happens?
8. How is "the offline tool has no network" tested, and what does the test not prove?
9. Why does an outside deposit into the cold address have to be booked?
10. What does software M-of-N not give you that a hardware HSM would?

<details><summary>Answers</summary>

1. Moving to cold can only make funds safer, so a pinned destination is enough. Moving to hot exposes them, so it needs people and a key nothing online can use.
2. So what the operators read is what gets signed. A transaction from the online side could differ from its description.
3. Destination, asset, amount, chain, nonce and the worst-case fee: those are the things an attacker would change, and the only ones the offline config cannot fix for them (the amount is bounded by a cap, not decided).
4. Content is what the payment moves (chain, from, to, asset, amount, nonce), without fees; the hash covers everything, including fees and revision. The record uses content so a fee bump of the same payment is allowed but a different payment at the same nonce is not.
5. The signed file names the old request hash; the current request has a new one, so import refuses it. Both would also share a nonce, so only one could ever mine.
6. The cold address has one nonce. Two signed transactions at one nonce would be two chances to pay.
7. One ALERT, and the workflow keeps waiting. It never signs or sends a new transaction with a new nonce by itself.
8. By checking the import graph of the tool and its rules package for any network client. It does not prove the machine is offline, or that a library has no hidden socket use; the air gap itself is the control.
9. The ledger mirrors the chain. Money that appears in the cold address without an entry makes the `cold` Reconcile check fail.
10. Enforcement by the device itself: here the software can be changed or bypassed by whoever controls the offline machine, while cards cannot be copied.

</details>
