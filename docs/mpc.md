# MPC signing

[中文](zh/mpc.md)

No machine here holds a whole key. Each key is cut into shares held by different parties, and a signature is made by the parties together, like a vault door that needs several keyholders at once, where each keyholder holds only a piece of the key and no one can copy the whole.

<p align="center"><img src="images/mpc.png" width="60%" alt="Three parties each seal a key share in their own HSM token. Any two sign EVM and Solana hot wallets. Parties A and B together sign Bitcoin and deposit-address keys."></p>

## Two kinds of keys
| Kind | Who signs | Used for |
|---|---|---|
| Two-party key tree | A and B, both needed | Bitcoin, and Solana deposit addresses |
| Two-of-three key | Any two of A, B, C | EVM and Solana hot wallets |

A customer address needs a key tree, where one parent key yields a child key for each customer from public data. The two-party kind can do that; the two-of-three kind cannot, so it serves only the hot wallets.

## When a party is down
| Down | Effect |
|---|---|
| One of A, B, C, on a two-of-three key | Another pair signs; nobody notices |
| A or B, on a two-party key | Signing waits, the job is retried, one alert is raised |
| C only | Everything on two-party keys goes on |

A restarted party must be checked against the others before it signs. When A is down, B and C check each other, but only if both are on the same generation and no refresh is half done, since only A knows whether one was decided. Otherwise they wait for A, and A checks all three when it is back.

## Which pair signs
Operators choose which two parties sign by default: A and B, A and C, or B and C. The choice is signed by approvers with the keys they already use for approvals, and it is recorded in the signing zone's audit log. It takes effect on the next job, with no restart; a job already signing finishes with the pair it started with. Use it to take one party out for maintenance ([runbook](runbooks/mpc-signing-pair.md)).

The gateway also checks the parties itself. It moves to another pair only after several failed checks in a short time, and returns to the chosen pair only after several good checks in a row, so a party that flaps does not make the route flap with it. One failed signature never moves the route. Waiting is the price: a party that has just died is still tried for a few seconds, and one that has just come back is trusted only after it has stayed up.

A route can only make signing slower or unavailable. Every pair still includes B or C, and that party's own checker still reads every job, so no choice of pair, signed or not, lets a signature skip a check.

## A failed check freezes the key
If a proof does not verify, a message cannot be read, or a final signature is wrong, the parties may be talking to a bad peer. The key is then frozen on every party that holds it. Nothing is deleted, withdrawals wait with their holds, and only an operator's signed unfreeze lifts it. A party that is merely slow or offline is not a freeze. See the [freeze runbook](runbooks/mpc-keyset-freeze.md).

## Shares are sealed, backed up and refreshed
Each share is encrypted under a key that never leaves the party's own HSM token, so a stolen disk gives nothing. A refresh gives every party new shares for the same public key, and a crash during it ends on one working generation. A lost party is rebuilt from its backup ([runbook](runbooks/mpc-backup-restore.md)).
