# T4 — The sign path: request -> policy -> approval -> sign -> verify -> audit

T4 joins the pieces from T1–T3 into one path a transaction travels, and puts
an HTTP API in front of it. At the end of the path is a signed Ethereum
Sepolia transaction whose recovered sender is the wallet's address, produced
either by the HSM or by the 2-of-3 / 3-of-3 MPC cluster.

## What was built

| Piece | Where | Job |
|---|---|---|
| Chain adapter | [internal/chain/eth/eth.go](../../internal/chain/eth/eth.go) | Build EIP-1559 tx + digest, attach (r,s) with the right recovery id, verify sender, optional RPC fill/broadcast |
| Orchestrator | [internal/signing/service.go](../../internal/signing/service.go) | `Submit`, `Vote`, `sign`: the state machine, tiering, audit events |
| Request store | [internal/signing/store.go](../../internal/signing/store.go) | The only writer of `sign_requests`; conditional status updates |
| MPC generator | [internal/signing/mpcgen.go](../../internal/signing/mpcgen.go) | MPC keygen that also audits `mpc.keygen` with ceremony stats |
| HTTP API | [internal/api/api.go](../../internal/api/api.go) | Routes, `X-Actor`, JSON errors, hex views |
| Wiring | [cmd/quorumvault/main.go](../../cmd/quorumvault/main.go) | DB, HSM token, MPC cluster, everything above; `verify-tx` subcommand |
| Demo | [scripts/demo-sepolia.sh](../../scripts/demo-sepolia.sh) | curl walkthrough; results in [docs/measurements/e2e.md](../measurements/e2e.md) |

## The request state machine

```
                 Submit (policy.Evaluate)
        +-------------+--------------+------------------+
        | deny        | needs_approval                  | allow
        v             v                                 v
     denied     pending_approval --any reject--> rejected
                      |
                      | enough distinct approvals (Vote)
                      v
                   approved  <---------------------------+
                      |
                      | sign(): approved -> signing  (compare-and-set)
                      v
                   signing --error--> failed
                      |
                      | signature verified, stored
                      v
                    signed   (-> tx.broadcast event if an RPC node is set)
```

- An allowed request is stored directly as `approved` ("cleared to sign"),
  so the same `approved -> signing` step serves both paths. `approved`
  also counts toward the 24h spend, so an allowed request uses up budget at
  once ([service.go:131](../../internal/signing/service.go#L131)).
- `denied`, `rejected`, `signed` and `failed` are terminal.
- Event sequence for one request (asserted in tests):
  - allow: `request.created, policy.decision, sign.started, sign.completed`
  - approval: `request.created, policy.decision, approval.voted (xN), request.approved, sign.started, sign.completed`
  - reject: `... approval.voted, request.rejected`
  - retired key: `... request.approved, sign.failed` (no `sign.started`: the
    lifecycle check runs before the ceremony)

## Where double-signing is prevented

Signing the same request twice would be harmless for one fixed nonce, but in
general it means two valid signatures for something approved once. Three
layers stop it:

1. **Compare-and-set on status.** Every move is
   `UPDATE sign_requests SET status = $to WHERE id = $1 AND status = ANY($from)`
   ([store.go:113](../../internal/signing/store.go#L113)). Postgres row locks
   make this atomic: of N callers racing `approved -> signing`, exactly one
   gets a row back; the others get "no rows" and stop. Only the winner calls
   a signer.
2. **One winner per vote completion.** Two approvers voting at the same time
   can both see `Done`. Both then try `pending_approval -> approved`; one
   wins and signs, the other just reports the current state
   ([service.go:261](../../internal/signing/service.go#L261)).
3. **Store only from `signing`.** The final write is `... WHERE status =
   'signing'` ([store.go:130](../../internal/signing/store.go#L130)).

Tests: `TestConcurrentApprovalsSignOnce` (6 approvers at once, signer called
once) and `TestConcurrentSignCallsSignOnce` (8 goroutines call `sign` on one
approved request).

The signing step runs detached from the HTTP request's cancellation
(`context.WithoutCancel` + its own timeout), so a client that hangs up during
a 500 ms MPC ceremony cannot leave the request stuck in `signing`.

## Binding a request to a key

`insert` picks the key in the same SQL statement that stores the row
(`INSERT ... SELECT k.id FROM keys k WHERE wallet_id = $2 AND state =
'active'`, [store.go:85](../../internal/signing/store.go#L85)), so a
rotation cannot land between "look up active key" and "insert". At sign time
`keys.AuthorizeSign` applies the lifecycle rule: an `active` key signs; a
`sign_only` key signs only requests created before its rotation; a `retired`
key signs nothing (the request goes to `failed`).

## Tiering

`Quorum(tier)`: hot -> 0 (MPC threshold set {1,2}), cold -> 3 (all three
parties). The policy engine already forces `needs_approval` for every cold
request, and cold policies default to 2 approvals. HSM wallets ignore the
quorum; for them tier only changes policy.

## EIP-1559 signing hash and the recovery id

- The digest is `keccak256(0x02 || rlp([chainId, nonce, maxPriorityFee,
  maxFee, gas, to, value, data, accessList]))`, from
  `types.LatestSignerForChainID(chainID).Hash(tx)`
  ([eth.go:91](../../internal/chain/eth/eth.go#L91)). Chain id is inside the
  hash, so a Sepolia signature cannot be replayed on mainnet.
- An ECDSA signature is `(r, s)`. From `(r, s, digest)` there are up to two
  public keys that verify; Ethereum stores no public key and no `from`
  field, it *recovers* the sender, so it needs one more bit `v` (0 or 1, the
  y-parity of the nonce point R) to pick the right one.
- HSMs and tss-lib return only `(r, s)`. `Assemble` tries `v = 0` and `v =
  1`, runs `ecrecover`, and keeps the one that returns the key's public key
  ([eth.go:142](../../internal/chain/eth/eth.go#L142)).
- Low-S first. EIP-2 rejects `s > N/2`. `(r, s)` and `(r, N-s)` are both
  valid, but flipping `s` flips `v`, so S is normalized before the search.
  `TestAssembleHighS` feeds a high-S signature and checks the result equals
  the low-S one.

## Why verify before store

`sign` checks the signature against the key, finds `v`, rebuilds the signed
tx and recovers its sender, and requires sender == the key's stored address
**before** writing anything ([service.go:387](../../internal/signing/service.go#L387)).
If any check fails the request goes to `failed` and no signature is stored.
Reasons:
- A bad signature in the DB looks like success to every later reader (and
  to the audit log's `sign.completed`), but the network rejects it, or worse,
  it recovers to a different address.
- It catches a signer that used the wrong key (wrong CKA_ID, wrong MPC key
  ref, a mixed-up share) at the one place that knows the expected address.
- It is cheap (~0.1 ms) next to the ceremony.

The demo adds a second, independent check: `quorumvault verify-tx <raw>
<address>` decodes the raw bytes offline and recovers the sender again.

## Audit after commit

`domain.Auditor` has no transaction parameter (PLAN decision), so each event
is appended after its state change commits. If an append fails, the change
stands and the service logs `AUDIT APPEND FAILED` at error level instead of
failing the call. A production system would use a transactional outbox.

## Concurrency inside Submit

Policy evaluation and the insert are serialized per wallet with an
in-process mutex ([service.go:151](../../internal/signing/service.go#L151)).
Without it, two concurrent requests could both pass a velocity or daily
limit because neither sees the other. This holds for one server process; a
multi-instance deployment would need a per-wallet database lock.

## Gotchas hit

- `domain.SignRequest` has its own `MarshalJSON`; embedding it in an API view
  struct promotes that method, so "shadowing" fields did nothing. The view
  re-marshals through a map instead.
- Go 1.22 `ServeMux` 404/405 replies are plain text; the API wraps them as
  JSON. A catch-all `/` route would have turned every 405 into a 404.
- Velocity/spend counting needs the request row and the decision to agree,
  so the status is decided before the insert and stored with it.

## Quiz

1. Why does the API store an allowed request as `approved` instead of
   signing it in a separate state?
2. Two approvers vote on a 1-of-1 request at the same instant. Walk through
   what stops a double signature.
3. A request was created at 10:00, the wallet rotated at 10:05, and the
   request is approved at 10:10. Which key signs, and why is it allowed?
4. Same, but the old key was retired at 10:08. What status and audit events
   does the request end with?
5. What is in the EIP-1559 signing hash that prevents replay on another chain?
6. Why does an Ethereum signature need `v`, and how does T4 find it when the
   HSM returns only `(r, s)`?
7. Why must S be normalized before searching for `v`?
8. Give two failures that "verify before store" catches.
9. Why does `sign` use `context.WithoutCancel`?
10. Why is the active key chosen inside the INSERT statement?
11. What does a cold MPC wallet change compared with a hot one, at policy and
    at ceremony level?
12. What happens if an audit append fails after a request is signed?

<details>
<summary>Answers</summary>

1. Both paths (allow and approval) then share one `approved -> signing`
   compare-and-set, and `approved` counts toward the 24h spend immediately.
2. Both votes are stored and both see `Done`; both try `pending_approval ->
   approved` with a conditional UPDATE; only one gets a row back and calls
   `sign`. Inside `sign`, `approved -> signing` is again conditional.
3. The old key (v1), now `sign_only`: the request is bound to v1 and was
   created before v1's `sign_only_at`, which is the drain rule.
4. `failed`; events `... request.approved, sign.failed` with stage
   `authorize`. The signer is never called.
5. The chain id (11155111 for Sepolia) is the first field hashed.
6. Ethereum recovers the sender from the signature; `(r, s)` fits two public
   keys and `v` selects one. T4 tries v=0 and v=1 with `ecrecover` and keeps
   the one returning the key's public key.
7. EIP-2 rejects high S, and replacing S by N-S flips the parity, so `v`
   found for the high-S form would be wrong for the low-S form.
8. A signature from the wrong key/share (sender != wallet address); an
   invalid or corrupted signature; a wrong recovery id.
9. So a client hanging up mid-ceremony cannot leave the request in
   `signing` forever; the step still ends in `signed` or `failed`.
10. So a rotation cannot commit between reading the active key and storing
    the request.
11. Policy: every request needs approval (default 2 approvers). Ceremony:
    quorum 3, all parties sign instead of the 2-party threshold set.
12. The request stays `signed`; the service logs `AUDIT APPEND FAILED`; the
    chain stays valid but is missing that event (the gap an outbox closes).

</details>
