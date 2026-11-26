# Signing zone

[中文](zh/signing-zone.md)

The signing zone is the only part of QuorumVault that can move money. It works like a bank teller who reads every slip before paying: even when the slip comes from the manager's office, the teller checks the signatures and the amount.

<p align="center"><img src="images/signing-zone.png" width="60%" alt="The business side can only queue jobs. The gateway and two independent cosigners each check a job before any key signs."></p>

## The business side can only ask

The core writes a job with three parts: what the approvers agreed to in plain words (who gets how much of which asset), the transaction to sign, and the approvers' signatures. The zone fetches jobs itself; nothing outside can push one in.

## Every job is checked before any key signs

1. Enough different people approved it, and the requester is not one of them. The requester's name is part of what the approvers sign, so the zone checks this itself.
2. Read back, the transaction does exactly what the approvers agreed to, and nothing else.
3. The destination is allowed by the zone's own rules.
4. The same job has never been signed with different content.

Jobs that nobody requests, such as sweeps and moves to cold, have no requester and follow the zone's own rules. Approvals in the older format no longer count ([runbook](runbooks/intent-v2-upgrade.md)).

## Approvals come only from keys the zone knows

An approver signs with a software key or a passkey (WebAuthn). The zone verifies a passkey's response itself: it was made for this exact job, by a key in the zone's own settings, with the person present ([runbook](runbooks/webauthn-approver.md)). A person with several keys counts once. Logging in is a separate step ([Identity](identity.md)).

The approver list is more than a settings file. Enrolling, disabling or revoking an approver needs signatures from several zone operators, who hold a different set of keys from the approvers. Each change is audited and written to a log that the gateway and every cosigner keep separately, and it applies to the next decision without a restart ([runbook](runbooks/approvers.md)).

Each hot key also has a state (new, active, draining, retired). The zone learns it only from records that zone operators have signed, never from the business side. The state decides what the key may sign. A key that is being replaced can only move its funds to its successor, and the zone operators' signatures that start the move count as its approval ([Key replacement](key-replacement.md)). A key marked as stolen may also cancel its own pending payment, so that a payment refused around the moment of the mark cannot block the move of its funds.

## Payments that AgentGate approves

Some hot wallets pay only what AgentGate approved. For such a wallet, every payment needs a short-lived credential that Gate signed for exactly that payment, and approvers cannot replace it. Which wallets these are, which Gate keys count, and how much may go out per payment, per hour and per day is a setting that several zone operators sign. The gateway and every cosigner each check the credential against the transaction they are about to sign, record it so it is used once, and count it against the limits. Money in such a wallet can be rebalanced only to another wallet of the same kind ([Gate credential](gate-credential.md), [runbook](runbooks/gate-setting.md)).

## Two cosigners that do not trust each other

Parties B and C each have their own cosigner: an independent checker that reads every job, with its own rules and records. Even if someone takes over the gateway, party A or the business database, they still cannot get a payment that nobody approved.

Each party and its cosigner also prove their identity to each other, so a process that merely owns the socket path cannot pose as the cosigner, and no other party can query it.

## What the zone does when something goes wrong

| What happened | What the zone does |
|:---|:---|
| A check fails | Signs nothing; the job states why |
| A party sends bad data during signing | Freezes the key on every party until a party administrator unlocks it |
| The same job arrives twice | Returns the first signature; refuses the job if its content changed |
