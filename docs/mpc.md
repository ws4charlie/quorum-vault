# MPC signing

[中文](zh/mpc.md)

No machine here holds a whole key. Each key is cut into shares held by different parties, and a signature is made by the parties together, like a vault door that needs several keyholders at once.

<p align="center"><img src="images/mpc.png" width="60%" alt="Three parties each seal a key share in their own HSM token. Any two sign EVM and Solana hot wallets. Parties A and B together sign Bitcoin and deposit-address keys."></p>

## Two kinds of keys

| Kind | Who signs | Used for |
|---|---|---|
| Two-party key tree | A and B, both needed | Bitcoin, and Solana deposit addresses |
| Two-of-three key | Any two of A, B, C | EVM and Solana hot wallets |

A customer address needs a key tree, where one parent key yields a child key per customer from public data. Only the two-party kind can do that.

## When a party is down

| Down | Effect |
|---|---|
| One of A, B, C, on a two-of-three key | Another pair signs; nobody notices |
| A or B, on a two-party key | Signing waits, the job is retried, one alert is raised |
| C only | Everything on two-party keys goes on |

A restarted party must be checked against the others before it signs. When A is down, B and C can check each other only if both are on the same generation and no refresh is half done, since only A knows whether one was decided. Otherwise they wait for A.

## Which pair signs
Operators choose which two parties sign by default (A and B, A and C, or B and C), for example to take one out for maintenance. Approvers sign the choice with the keys they already use, it is recorded in the zone's audit log, and it applies from the next job ([runbook](runbooks/mpc-signing-pair.md)).

The gateway also checks the parties itself. It changes pair only after several failed checks in a short time, and changes back only after several good ones, so a party that flaps does not make the route flap. A route can only make signing slower or unavailable: every pair includes B or C, whose own checker reads every job.

## A failed check freezes the key
If a proof does not verify, a message cannot be read, or a final signature is wrong, a party may be bad. The key is then frozen on every party that holds it. Withdrawals wait with their holds, and only an operator's signed unfreeze lifts it. A party that is merely slow or offline is not a freeze ([runbook](runbooks/mpc-keyset-freeze.md)).

## Failures are counted per suspect
Each party counts failed sessions by the other party involved and the kind of failure; the gateway counts failed sign calls by pair. A monitoring system outside the signing zone alerts a person when one party keeps showing up. The named party is only a suspect, since the protocol cannot say who caused a failure, and only people act on the counts ([runbook](runbooks/mpc-failures.md)).

## Shares are sealed, backed up and refreshed
Each share is encrypted under a key that never leaves the party's own HSM token, so a stolen disk gives nothing. A refresh gives every party new shares for the same public key. A lost party is rebuilt from its backup ([runbook](runbooks/mpc-backup-restore.md)). An [enclave](enclaves.md) can later keep even a host administrator from opening the shares. When a key itself must go, see [Key replacement](key-replacement.md).
