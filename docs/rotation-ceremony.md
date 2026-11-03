# Key rotation ceremony (drill)

A step-by-step rotation of one wallet's signing key: generate key version
N+1, drain version N, then retire it (for HSM keys, destroy the private key
object in the token). Every command below runs against a local server and
was executed end to end on the base commit.

The registry enforces the states; people enforce the rest. Read the
[dual control](#roles-and-dual-control) section before running this on
anything that matters. This repo is testnet only.

## What the system guarantees

```
            POST /wallets/{id}/rotate        POST /keys/{id}/retire
   active ----------------------------> sign_only ----------------> retired
  (v N)        v N+1 inserted active      (drain)        HSM: C_DestroyObject
```

| Rule | Enforced by |
|---|---|
| At most one `active` key per wallet | partial unique index `keys_one_active_per_wallet` |
| Only `active -> sign_only -> retired` | `checkTransition` in [internal/keys/keys.go](../internal/keys/keys.go) |
| Rotation is atomic: new key `active` and old key `sign_only` in one DB transaction | `Registry.Rotate` |
| A request is bound to the wallet's active key when it is created | `INSERT ... SELECT` in [internal/signing/store.go](../internal/signing/store.go) |
| A `sign_only` key signs only requests created before its `sign_only_at` | `Registry.AuthorizeSign` |
| A `retired` key signs nothing; for HSM keys the private key object is destroyed before the state change commits | `Registry.Retire` + `hsmsigner.DestroyKey` |
| Every step is in the hash-chained audit log | `key.generated`, `key.state_changed`, `key.rotated`, `key.destroyed` |

What it does **not** guarantee (do these by procedure):
- Rotate and retire accept a single `X-Actor`. Dual control for key admin is
  procedural here; production would put key-admin calls behind the same
  M-of-N approval queue as spending (see [DESIGN_SCALE.md](../DESIGN_SCALE.md)).
- Ethereum is an account model: a new key is a **new address**. Funds on
  the old address do not move by themselves. A new request always binds to
  the *active* key, so after rotation you cannot create a new sweep from the
  old address. Create any sweep **before** rotating (see step 1).
- For MPC keys, retire changes the state only. The sealed share files stay on
  disk under `data/mpc/keys/<keyRef>/`; delete them by hand after a verified
  retire if the drill requires it.

## Roles and dual control

| Role | Who in the drill | Does |
|---|---|---|
| Ceremony lead (custodian A) | `custodian-a` | runs rotate; reads the script aloud |
| Second custodian (custodian B) | `custodian-b` | verifies every output independently; runs retire |
| Payment approver | `bob` | approves in-flight payments during the drain |
| Requester | `alice` | in-flight payments (cannot approve her own: HTTP 403) |
| Witness / auditor | anyone not above | checks the audit trail at the end, signs the ceremony record |

Rules:
1. Two named people are present for every step; neither runs a step alone.
   The person who runs a step is not the person who verifies it.
2. Custodian A rotates, custodian B retires. Both actors appear in the audit
   log, so the record shows two people.
3. Every output below is pasted into the ceremony record (change ticket),
   with the time, and initialled by both custodians.

## Setup

```bash
./scripts/setup-softhsm.sh
make db-up                      # Postgres 16 on localhost:55432 (skip if already running)
go run ./cmd/quorumvault &      # listens on :8080
export QV=http://localhost:8080
```

`h` keeps the commands short:

```bash
h() { local m=$1 p=$2 a=$3; shift 3; curl -sS -X "$m" "$QV$p" -H "X-Actor: $a" -H 'Content-Type: application/json' "$@"; }
```

### Drill fixture (skip in a real rotation)

A hot HSM wallet with a policy, one allowlisted destination, and two
payments in flight on key v1 (both over the approval threshold, so they wait
for an approver):

```bash
DEST=0x000000000000000000000000000000000000dEaD
W=$(h POST /wallets admin -d "{\"name\":\"rot-drill-$(date +%s)\",\"tier\":\"hot\",\"backend\":\"hsm\"}" | jq -r .wallet.id)
h PUT /wallets/$W/policy admin -d '{"daily_limit_wei":"1000000000000000000","per_tx_limit_wei":"500000000000000000","approval_threshold_wei":"10000000000000000","velocity_max_tx":10,"velocity_window_seconds":3600,"required_approvals":1}' >/dev/null
h POST /wallets/$W/allowlist admin -d "{\"address\":\"$DEST\",\"label\":\"burn\"}" >/dev/null
R1=$(h POST /sign-requests alice -d "{\"wallet_id\":\"$W\",\"to\":\"$DEST\",\"value_wei\":\"20000000000000000\",\"nonce\":0}" | jq -r .request.id)
R2=$(h POST /sign-requests alice -d "{\"wallet_id\":\"$W\",\"to\":\"$DEST\",\"value_wei\":\"20000000000000000\",\"nonce\":1}" | jq -r .request.id)
echo "wallet=$W in-flight=$R1 $R2"
```

R1 is drained normally; R2 is left pending on purpose to show what retiring
too early does (step 7).

## The ceremony

### 1. Pre-flight (custodian B runs, custodian A verifies)

```bash
curl -sS $QV/healthz                      # {"ok":true,"db":{"ok":true},"hsm":{"ok":true,"token":"quorumvault"}}
curl -sS $QV/audit/verify                 # {"ok":true}  -- never rotate on a broken chain
h GET /wallets/$W x | jq '{wallet: .wallet.name, keys: [.keys[] | {version, state, address}]}'
OLD=$(h GET /wallets/$W x | jq -r '.keys[] | select(.state=="active") | .id')
OLD_ADDR=$(h GET /wallets/$W x | jq -r '.keys[] | select(.state=="active") | .address')
h GET "/sign-requests?wallet_id=$W" x | jq -c --arg k "$OLD" '[.[] | select(.key_id==$k) | {id, status}]'
```

Record: the active key id, version and address; the list of requests bound
to it; the wallet's latest audit event (`h GET "/audit?wallet_id=$W" x | jq '.[-1] | {seq, hash}'`;
the list is ordered by `seq`, oldest first). If the old address holds
funds, create the sweep request **now** (destination: the treasury or the
new address agreed out of band), because after step 2 a new request binds
to the new key.

### 2. Rotate (custodian A runs)

```bash
h POST /wallets/$W/rotate custodian-a | tee rotate.json | jq '{new: {version: .key.version, state: .key.state, address: .key.address}, previous: {version: .previous_key.version, state: .previous_key.state, sign_only_at: .previous_key.sign_only_at}}'
NEW=$(jq -r .key.id rotate.json); NEW_ADDR=$(jq -r .key.address rotate.json)
```

Expected: HTTP 201; new key `version` N+1, `state: "active"`; previous key
`state: "sign_only"` with a `sign_only_at`. The key pair was generated inside
the `quorumvault` token (`CKA_TOKEN`, `CKA_SENSITIVE`, `!CKA_EXTRACTABLE`)
before the DB transaction. For an MPC wallet the same call runs a new
distributed keygen (~3 s measured).

### 3. Verify the rotation (custodian B runs)

```bash
h GET "/keys?wallet_id=$W" x | jq -c '[.[] | {version, state, address, sign_only_at}]'
h GET "/audit?wallet_id=$W" x | jq -r '.[] | select(.type|startswith("key.")) | "#\(.seq) \(.type) by \(.actor)"'
curl -sS $QV/audit/verify
```

Expected: exactly one `active` key (v N+1) and v N `sign_only`; audit shows
`key.generated`, `key.state_changed`, `key.rotated` by `custodian-a`; chain
ok.

Prove new requests bind to the new key: a small payment signs from the new
address.

```bash
h POST /sign-requests alice -d "{\"wallet_id\":\"$W\",\"to\":\"$DEST\",\"value_wei\":\"1000\",\"nonce\":0}" \
  | jq -c --arg new "$NEW" '{status: .request.status, bound_to_new_key: (.request.key_id==$new), from}'
echo "new address: $NEW_ADDR"
```

Expected: `status: "signed"`, `bound_to_new_key: true`, `from` equals the
new address. Publish the new address to whoever deposits into this wallet
(outside this system).

### 4. Drain (approver runs, custodians watch)

In-flight requests bound to v N still sign with v N:

```bash
h POST /sign-requests/$R1/approve bob -d '{"comment":"drain"}' | jq -c --arg old "$OLD_ADDR" '{status: .request.status, from, from_old_key: (.from==$old)}'
```

Expected: `status: "signed"`, `from` is the **old** address. Repeat for every
request on the list from step 1, or reject the ones that should not go out
(`POST /sign-requests/{id}/reject`).

Drain is done when nothing bound to the old key can still sign:

```bash
h GET "/sign-requests?wallet_id=$W" x | jq -c --arg k "$OLD" '[.[] | select(.key_id==$k and (.status=="pending_approval" or .status=="approved" or .status=="signing")) | .id]'
```

Expected in a real rotation: `[]`. In the drill it lists R2 on purpose. If
the old address had funds, confirm on chain that its balance is zero (or
dust below the sweep fee) before going on: step 5 is the point of no return.

### 5. Retire (custodian B runs, custodian A verifies)

```bash
h POST /keys/$OLD/retire custodian-b | jq -c '{version, state, retired_at}'
```

Expected: HTTP 200, `state: "retired"`. For an HSM key the private key object
(`CKA_ID` = `hsm_key_id`) was destroyed with `C_DestroyObject` inside the
same DB transaction; the public key and metadata stay so old signatures can
still be verified. A second retire returns HTTP 409 (invalid transition).

### 6. Verify the retire (custodian A runs)

```bash
h GET "/keys?wallet_id=$W" x | jq -c '[.[] | {version, state}]'
h GET "/audit?wallet_id=$W" x | jq -r '.[] | select(.type|startswith("key.")) | "#\(.seq) \(.type) by \(.actor) \(.payload|tostring)"' | tail -2
curl -sS $QV/audit/verify
```

Expected: v N `retired`, v N+1 `active`; the last two key events are
`key.state_changed` (`sign_only -> retired`) and `key.destroyed`
(`object: private_key`), both by `custodian-b`; chain ok.

### 7. Negative check (drill only): what retiring too early does

R2 was still pending when v N was retired. Approving it now cannot sign:

```bash
h POST /sign-requests/$R2/approve bob -d '{}' | jq -c '{status: .request.status, sign_error}'
h GET "/audit?request_id=$R2" x | jq -r '.[] | "\(.type) \(.payload.stage // "")"'
```

Expected: `status: "failed"`, `sign_error` says the key is `retired`; the
audit trail ends `request.approved`, `sign.failed authorize` and has no
`sign.started`: the signer was never called. In a real ceremony this request
would have been drained or rejected in step 4.

### 8. Close the record

```bash
h GET "/audit?wallet_id=$W" x > audit-$W.json
curl -sS $QV/audit/verify
```

Attach `rotate.json` and the audit export to the change ticket. Both
custodians and the witness sign it.

## Rollback

| Failure point | State | Rollback |
|---|---|---|
| Step 2 fails (HSM error, DB error) | Nothing changed: an HSM key generated before a failed DB transaction is destroyed by the registry (`discard`) | Fix the cause, rerun step 1–2 |
| Step 3 shows a problem with v N+1 (wrong address published, downstream rejects it) | v N is `sign_only` and its private key still exists | There is no `sign_only -> active` transition. Roll **forward**: rotate again to v N+2. v N keeps draining. Do not retire anything until the new key is accepted. |
| Step 4: an in-flight request should not go out | — | `POST /sign-requests/{id}/reject` (any one reject ends it) |
| Step 5 ran too early (requests or funds still on v N) | v N private key destroyed | **No rollback by design.** In-flight requests fail (step 7); funds left on the old address are unreachable for an HSM key. This is why step 4 ends with an on-chain balance check, and why production keeps a verified backup of every key before it is activated. |

Reasons for the design: a key that can come back from `sign_only` to
`active` makes "rotated" a promise instead of a fact; destroying the object
makes "retired" a property of the HSM, not of the database.
