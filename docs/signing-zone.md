# Signing zone

[中文](zh/signing-zone.md)

The signing zone is the only part of QuorumVault that can move money. Think of a bank teller who reads every slip before paying: even from the manager's office, the teller checks the signatures and the amount.

<p align="center"><img src="images/signing-zone.png" width="60%" alt="The business side only queues jobs. The gateway and two independent cosigners each check a job before any key signs."></p>

## The business side can only ask
The core writes a job: what the approvers agreed to in plain words (who gets how much of what), the transaction to sign, and the signatures. The zone fetches jobs itself; nothing can push one in.

## Every job is checked before any key signs
1. Enough different people approved it, and none of them is the person who asked. The requester's name is part of what approvers sign, so the zone checks this itself.
2. The transaction, read back, does exactly what the approvers agreed to, and nothing more.
3. The destination is one the zone's own rules allow.
4. The same job was never signed with different content.

Jobs nobody requests, such as sweeps and moves to cold, carry no requester and follow the zone's own rules. Approvals in the older format no longer count ([runbook](runbooks/intent-v2-upgrade.md)).

## Approvals come from keys the zone knows
An approver signs with a software key or a passkey (WebAuthn). The zone checks a passkey's answer itself: made for this exact job, by a key in its own config, with the person present ([runbook](runbooks/webauthn-approver.md)). A person with several keys counts once. Logging in is a separate step ([Identity](identity.md)).

## Two checkers that don't trust each other
Parties B and C each have their own checker, rules and records. Taking over the gateway, party A or the business database still can't get a payment nobody approved.

## When something goes wrong

| What happened | What the zone does |
|---|---|
| A check fails | Nothing is signed, and the job says why |
| A party sends bad data during signing | The key is frozen everywhere until operators lift the freeze |
| The same job arrives twice | The first signature is returned; a changed job is refused |
