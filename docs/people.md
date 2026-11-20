# People

[中文](zh/people.md)

QuorumVault moves money only when the right people agree. Nobody can both ask for a payment and approve it, and the people who decide who may approve are a different group again.

## Who does what

| Who | Does | Typically |
|---|---|---|
| **Requester** | Opens customers and deposit addresses, asks for withdrawals | The exchange's own backend, or support staff |
| **Approver** | Approves or rejects each withdrawal with a personal key | Treasury or finance officers; two or more per payment |
| **Operator** | Runs daily operations: cold refills, batches, checking the books against the chain | The operations team on shift |
| **Zone operator** | Signs the signing zone's own settings: who the approvers are, which keys are in use, the fee limits | Security officers; several must sign each change |
| **Cold signer** | Signs moves out of cold storage on an offline machine | Senior custodians; M of N, in a ceremony |
| **Admin** | Changes what the deposit contracts do | The platform lead, rarely |

For example, at a small exchange: the trading backend is the requester, two finance officers are approvers, three security officers are zone operators, and the same three plus the CFO are cold signers.

## How each one proves who they are

- **A login** at the company's identity provider gives the role for the core API, and big actions need a fresh one ([Identity](identity.md)).
- **A personal key** makes an approval count: the [signing zone](signing-zone.md) checks the signature against its own list and does not trust the login alone. The key can be a hardware security key, used on a web page or in a small terminal tool.
- **An offline key** signs zone settings and cold moves. These never touch the online system ([Hot and cold](tiers.md)).

One person can hold more than one role, but the system counts people, not keys: two keys of the same person are one approval.
