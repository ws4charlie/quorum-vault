# Audit trail

[中文](zh/audit.md)

The audit trail records every decision so it can't be quietly changed later. Each line carries a fingerprint of the line above, like a numbered ledger with each page stamped from the last: tear one out and the stamps stop matching.

<p align="center"><img src="images/audit.png" width="60%" alt="Each trust zone keeps its own hash chain. Each chain publishes its head to Kafka, and an archiver copies it into write-once storage, so a shortened or rewritten chain no longer matches."></p>

## One chain per trust zone
The core, the gateway and the cosigner each keep their own chain in their own database, which refuses edits, deletes and truncation. The gateway and cosigner write each decision in the same transaction as the decision itself: if the record can't be written, nothing is signed. Their chains keep working while the core is down.

## Heads are published
Each chain sends its head, the count and the last fingerprint, to Kafka whenever it changes and at set intervals. Someone who switches the database rules off could cut a chain short, but not without leaving out an entry that was already published. If Kafka is down, signing goes on and the heads catch up.

Kafka alone does not last: topics expire, and whoever runs the brokers can delete one. So an archiver outside the signing zones also copies every head into write-once storage, one object per head. The storage refuses to delete or overwrite an object, or to shorten its retention, even for its own administrator, and the archiver refuses a bucket that does not promise this ([runbook](runbooks/audit-archive.md), [why this store](spikes/audit-worm.md)). This proves a head existed and was not changed afterwards, not that the chain is complete.

## Checking compares the chain with the heads

| What was done | What the check finds |
|---|---|
| A row was edited | Its fingerprint no longer matches |
| A row was removed from the middle | The chain breaks |
| The end was cut off | The published head is not in the chain |
| The whole chain was rewritten | Its head differs from the published one |
| The Kafka topic was deleted | The check reads the heads from the write-once copy |

Each chain has a verify command that checks it against the heads, from a topic dump, the write-once copy, or both.
