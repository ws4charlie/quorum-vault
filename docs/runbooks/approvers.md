# Approvers: enrol, disable, revoke, lost key

Approvers are the people whose signatures release money. They are changed by **operators**, a different small key set in the signing-zone config, never by approvers and never by a config edit. A change needs `min_operators` distinct operators (default 2), is audited, and applies to the next decision of the gateway and of every cosigner, with no restart.

## What is fixed
The zone config (gateway and every cosigner) has an `operators` section. It is the root of trust, so it stays in the config file:

```json
"operators": {"keys": {"op1": {"public_key": "<ed25519, hex>"}, "op2": {"public_key": "..."}, "op3": {"public_key": "..."}}, "min_operators": 2, "max_change_age": "10m"}
```

- With one operator, `min_operators` is 1; with several it is at least 2.
- An operator key must not be an approver key (the zone refuses to start).
- The approvers in the config are the **bootstrap set**. A signed `revoke`, `disable` or `enable` may name a bootstrap approver, so a compromised bootstrap key can be removed without a restart. A revoked name and its key are never used again. Without an `operators` section the config is the whole set and nothing here applies.
- A change cannot leave fewer enabled approvers (distinct people) than the highest approval tier asks for, or fewer with an Ed25519 key than a route or fee-cap change asks for. The change is refused with the reason.
- Each operator keeps their private key as hex (32-byte seed) in a file on their own machine.

## Enrol an approver
1. `qv-approvers show -config zone.json -guard-dsn gateway=… -guard-dsn cosigner-b=…` shows the sequence number (the next change uses it plus one). All databases should show the same.
2. The first operator signs: `qv-approvers sign -operator op1 -key op1.key -seq N -action enrol -name erin -public-key <hex> [-identity erin@example.com] -out change.json`. For a passkey, write the entry as a JSON file (`scheme`, `alg`, `public_key`, `credential_id`, `rp_id`, `origins`, see [passkey approver](webauthn-approver.md)) and pass `-approver-file`. Check what the command prints: the identity and key you are about to sign for.
3. Other operators add their signature to the same file: `qv-approvers sign -operator op2 -key op2.key -join change.json -out change.json`. Everyone signs the same time, so finish within `max_change_age`.
4. Apply to **every** guard database: `qv-approvers apply -config zone.json -guard-dsn gateway=… -guard-dsn cosigner-b=… change.json`. It is safe to run again; a database that has the change skips it.

## Disable, enable, revoke
Same steps with `-action disable|enable|revoke -name <approver>` and no key.
- **Disable** is temporary (leave, suspicion). **Enable** undoes it.
- **Revoke** is permanent. Use it for a leaver or a lost or stolen key.

## Lost or stolen key
Revoke the key's approver at once. Signatures from it stop counting for every decision after the apply, including jobs already queued. Enrol the person again with a new name and new key. If the key could also sign Bitcoin fee-cap changes, remove it from `fee_caps_change.approvers` of the core config too (see below).

## While the databases differ
The gateway and each cosigner judge by their own verified log. Until a change reaches all of them:
- A job approved by someone this zone does not know yet (or has disabled) is **not refused**. It waits and is decided again, with an `ALERT approver registry: a job waits…` log line, until its own `not_after`. Nothing fails.
- A job approved by a revoked approver is refused: it needs new approvals.
- Run `apply` again to finish. `show` warns when the sequence numbers differ.

## What you see when something is wrong
- `ALERT approver registry: rows of the approver_changes table do not carry valid operator signatures…`: someone wrote to the guard database directly, or the `operators` section changed after the rows were written (raising `min_operators` or removing an operator can make old changes invalid). The rows are ignored.
- `apply` says `1 valid signatures of distinct configured operators, 2 needed`: too few operators, the same operator twice, or a signature by an approver.
- `sequence N is not higher than the current`: someone applied a change first; run `show` and sign again with the next number.

## Limits
Route changes and Bitcoin fee-cap changes in the zone use the effective approver set. The **core** keeps a static copy of the approver keys for fee caps (`fee_caps_change.approvers` in the core config) and does not read the log. So a newly enrolled approver cannot sign a fee-cap change until the core config lists them, and a revoked one must be removed from it by hand.
