# Signing zone

[中文](zh/signing-zone.md)

The signing zone is the only part of QuorumVault that can move money. Think of it as a bank teller who reads every slip before paying: the slip may come from the manager's office, but the teller still checks the signatures and the amount.

<p align="center"><img src="images/signing-zone.png" width="60%" alt="The business side only queues jobs. The gateway and two independent cosigners each check a job before any key signs."></p>

## The business side can only ask
The core writes a job: what the approvers agreed to, in plain words (who gets how much of what), the transaction to sign, and the approvers' signatures. The zone fetches jobs itself; nothing outside can push one in.

## Every job is checked before any key signs
1. Enough approvers signed it, and none of them is the person who asked.
2. The transaction, read back, does exactly what the approvers agreed to, and nothing more.
3. The destination is one the zone's own rules allow.
4. The same job was never signed with different content.

## Two checkers that don't trust each other
Parties B and C each have their own checker, with their own rules and their own records. Someone who takes over the gateway, party A or the business database still can't get a payment nobody approved.

## When something goes wrong

| What happened | What the zone does |
|---|---|
| A check fails | Nothing is signed, and the job says why |
| A party is down before signing starts | Another pair of parties signs |
| A party sends bad data during signing | The key is frozen everywhere until operators lift the freeze |
| The same job arrives twice | The first signature is returned; a changed job is refused |
