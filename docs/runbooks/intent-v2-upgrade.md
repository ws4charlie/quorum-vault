# Upgrading to intent v2 (the requester is signed)

Do this once, when the zone first runs a build with `qv-intent-v2`. It applies to a zone with withdrawals in flight; with none, there is nothing to do.

## What changes
The signed statement now ends with the requester, and its version prefix is `qv-intent-v2`. An approval made over the old statement (`qv-intent-v1`) does not verify, so the zone does not count it. The core builds the new statement from the withdrawal's `requested_by`.

## Before the upgrade
1. Stop requesting withdrawals and let the open ones finish (none in `requested` or `approved` status).
2. Check that no batch is waiting to be signed.

## After the upgrade
A withdrawal still open from before is refused by the zone with `approval_invalid` (its approvals are over the old statement) and shows that reason. It can not be approved again: the core keeps the first approval of each approver. Reject it (`POST /v2/withdrawals/{id}/rejections`) and have the person request it again.

## Approver config
An approver may now have `"identity"`: the person the key belongs to, in the same form as the requester. It defaults to the approver's name. Give two keys of one person the same identity: they count as one approver, and none of them may approve that person's withdrawals.
