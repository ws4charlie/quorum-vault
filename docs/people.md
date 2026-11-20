# People

[中文](zh/people.md)

QuorumVault moves money only when everyone required has agreed. The person who requests a payment cannot approve it, and a different group decides who may approve.

## Roles and duties

| Role | Duties | Usually held by |
|:---|:---|:---|
| Requester | Opens customers, creates deposit addresses, requests withdrawals | The exchange's backend or support staff |
| Approver | Approves or rejects each withdrawal with a personal key | Treasury or finance officers |
| Operator | Daily operations: refilling hot wallets from cold storage, batching payments, reconciling the books with the chain | The operations team on shift |
| Zone operator | Signs the signing zone's settings: the approver list, the keys in use, the fee caps | Security officers |
| Cold signer | Signs transfers out of cold storage on an offline machine | Senior custodians |
| Contract admin | Changes how the deposit contracts behave; rarely needed | The platform lead |

## How many people each action needs

- **Withdrawal**: set in tiers by amount, with at least one approver per tier and never fewer for a larger amount; the requester cannot be one of them.
- **Signing-zone settings change**: several zone operators sign together.
- **Cold transfer**: M of N cold signers, in a key ceremony.

One person can hold several roles, but the system counts people, not keys: two keys held by the same person are one vote.

Example: at a small exchange, the trading backend is the requester, two finance officers are approvers, three security officers are zone operators, and those three plus the CFO are cold signers.

## How each person proves who they are

- **Login**: signing in at the company's identity provider gives the role for the core API; important actions require logging in again ([Identity](identity.md)).
- **Personal key**: an approval must be signed with a personal key. The [signing zone](signing-zone.md) checks the signature against its own list and does not rely on the login alone. The key can be a hardware security key, used on a web page or in a command-line tool.
- **Offline key**: used to sign zone settings and cold transfers, and never touches the online system ([Hot and cold](tiers.md)).
