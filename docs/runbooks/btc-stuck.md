# Runbook: a Bitcoin send does not confirm

A withdrawal, a hot-to-cold move or a batch is raised by replacement first, then, if CPFP is on, pulled in by a child (see [Bitcoin](../bitcoin.md)). This page is for when that is not enough.

## What the alerts mean

| Alert | Meaning | What to do |
|---|---|---|
| replacements exhausted | The send used all its replacements. With CPFP on, a child follows after `cpfp_after`; otherwise it keeps waiting | Wait for the child, raise `max_replacements`, or cancel |
| replacement could not be built | The next fee is over the caps, or the change cannot pay it | Same as above. Raising the caps is a change in the core, the gateway and each cosigner at once ([fee caps](btc-fee-caps.md)) |
| a CPFP child could not be built | There is no room under the caps (the send already pays the rate ceiling), no change, or a cancel is running | Nothing a child can do. Raise the caps, or cancel |

A transaction that waits is never voided because of a cap.

## Turn CPFP on
In the core's config, `withdrawal.cpfp_after` is how long a send that cannot be raised any more waits before its child is built (for example `30m`). Empty or `0` turns it off. The signing zone needs no setting: it signs a child under the caps it already has. Restart the workers to apply it; a send already in flight keeps the setting it started with.

## See the child
The child is an attempt of the same withdrawal or batch with kind `cpfp` in `btc_attempts`; its input is the send's change. The withdrawal's transaction hash stays the send's. When both confirm, the withdrawal's fee is the two fees together.

## Cancel when a child exists
Cancel the batch as usual. The cancel replaces the send and evicts the child, so it pays more than both. If that is over the caps the cancel cannot be built; the batch is parked with an alert and keeps waiting.
