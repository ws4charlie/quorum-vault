# Gate setting: Gate-governed wallets, Gate keys, fast lane

The Gate setting says which hot wallets pay only with a Gate credential ([spec](../gate-credential.md)), which Gate public keys sign credentials, the deployment's `audience`, the clock limits, and each wallet's fast-lane limits. Whoever can change it can mint payments, so it is signed by the same **operators** as approver changes ([approvers](approvers.md)): `min_operators` distinct operators sign one version of the whole setting, and it is applied to the guard database of the gateway and of every cosigner. It applies to the next decision, with no restart. Without an `operators` section no version can be applied and no wallet is Gate-governed.

## What is fixed
- The config file holds only the **bootstrap key set**, in the zone config of the gateway and every cosigner (the same file):

```json
"gate": {"bootstrap_keys": [{"kid": "gate-2026-11", "public_key": "<32-byte Ed25519 key, base64url, no padding>"}]}
```

  A node with an empty list, a bad `kid` or a wrong key length refuses to start. Leave the section out until Gate has a key.
- The credential rule is part of every decision of qv-gateway and qv-cosigner. There is no flag to turn it off.

## Write a version
A version is the whole setting, as a JSON file (every field below; maps sorted, so every operator signs the same bytes):

```json
{
  "audience": "qv-staging",
  "keys": [{"kid": "gate-2027-01", "public_key": "<base64url>", "not_before": 0, "not_after": 0}],
  "retired": [],
  "skew_seconds": 30,
  "max_ttl_seconds": 600,
  "wallets": [{"wallet_id": "<lower-case UUID, as Gate names it>", "partition": "<hot partition id>",
               "limits": {"USDC": {"per_payment": "1000000", "per_hour": "5000000", "per_day": "20000000"}}}]
}
```

- `keys` are added to the bootstrap keys. `not_after` 0 is no end. `retired` lists kids retired for good: a retired kid or public key is never accepted again, under any kid.
- A wallet is named by one hot partition id; the zone governs its whole hot shard (every asset, every key generation). The partition must be a hot partition of an EVM chain in the zone config. One wallet per shard.
- `limits` are per asset symbol of that chain, in base units. An asset not listed has all limits at 0: it pays nothing.
- `skew_seconds` (0 = 30, at most 300) and `max_ttl_seconds` (0 = 600, 1 to 3600).

## Sign and apply
1. `qv-approvers gate-show -config zone.json -guard-dsn gateway=… -guard-dsn cosigner-b=… -guard-dsn cosigner-c=…` shows the version in force (the next one uses it plus one). All databases should show the same.
2. The first operator signs: `qv-approvers gate-sign -operator op1 -key op1.key -setting gate.json -version N -out gate-vN.json`. Read what it prints: that is what you sign.
3. Other operators add their signature: `qv-approvers gate-sign -operator op2 -key op2.key -join gate-vN.json -out gate-vN.json`. Finish within `max_change_age`.
4. Apply to **every** guard database: `qv-approvers gate-apply -config zone.json -guard-dsn gateway=… -guard-dsn cosigner-b=… -guard-dsn cosigner-c=… gate-vN.json`. Safe to run again.

## Order of a rollout
1. Apply the version to the gateway **and every cosigner**, and check with `gate-show` that all show it.
2. Only then point Gate at the wallet (give Gate the `wallet_id` and the `audience`).

A checker on an older version refuses what it does not know yet (an unknown key: `kid_unknown`; a wallet it does not govern: `wallet_not_gate_governed`), so a two-party signature is not made until all agree. A wallet governed by a newer version is refused without a credential at once at that checker.

## Rotate a Gate key
1. Version N+1 adds the new key. Gate starts signing with it.
2. Version N+2 retires the old kid (or sets its `not_after`), no sooner than the old key's last credential's expiry: `max_ttl_seconds` + `skew_seconds` after Gate stopped using it. A compromised key: retire it at once.

## Records and pruning
Each checker keeps the credentials it accepted in `gate_credentials_used` (its own guard database): the replay record and the fast-lane counts. qv-gateway and qv-cosigner prune rows every hour once `expires_at` + skew + 1 day has passed (never sooner than a day after signing). Every accept and refusal is in the checker's audit log, event `sign.allowed` or `sign.refused`, field `gate`; a version applied is event `gate.setting_changed`.

## What you see when something is wrong
| Symptom | Cause | Action |
|:---|:---|:---|
| `ALERT gate setting: rows of the gate_setting_changes table do not carry valid operator signatures…` | a row written directly into the guard database, or the `operators` section changed since | rows are ignored; investigate the write |
| jobs refused `credential_missing` | a payment from a Gate-governed wallet without a credential (approvals do not replace it) | send it through the signing API with a credential, or remove the wallet from the setting |
| `kid_unknown` at a cosigner only | the cosigner is on an older version | run `gate-apply` again for it |
| `fast_lane_cap` | above a per-payment, hourly or daily limit | wait, or sign a new version with other limits |
| `policy_gate_rebalance` | a rebalance from a Gate-governed wallet to a wallet that is not Gate-governed in this checker's setting | none needed if expected; the core plans none from a Gate wallet to a non-Gate one, and after such a refusal (its `gate.wallets` and the signed setting differ) plans none from that shard for an hour, with an `ALERT gate` log line: make the two equal |
| `wallet_not_gate_governed` | a credential, or an EIP-3009 authorization, for a wallet that is not in this checker's setting | check the version on every checker and the partition named |
