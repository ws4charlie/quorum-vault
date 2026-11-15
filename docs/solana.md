# Solana

[中文](zh/solana.md)

Solana works differently from the other chains in three ways: an account must hold a minimum balance to exist, tokens live in separate token accounts, and a transaction's recent-block reference expires within a minute.

<p align="center"><img src="images/solana.png" width="60%" alt="Addresses come from a public key. Deposits are read at finality. Withdrawals sign a durable nonce instead of a blockhash. A sweep batches several addresses."></p>

## Addresses come from public data
Customer addresses derive from a two-party Ed25519 key tree, offline, from a public account node. Hot wallets are two-of-three keys.

## Tokens and rent
A token balance sits in the address's own token account, which is the only one the books credit. Tokens sent to any other account are not credited, and Reconcile raises an alert. A payment smaller than the minimum balance to a new address fails on the chain, so there is nothing to credit.

## Only finalized payments count
A confirmed transaction can still be dropped with its fork. The scan reads only finalized data, so it credits only what cannot be undone.

## Withdrawals sign a durable nonce
The reference to a recent block would expire before the signers finish. So a withdrawal signs the value of a nonce account instead; whichever version lands first uses it up, and every other version is refused by the network. The signing zone reads the whole message and accepts only a few approved shapes.

| Situation | Result |
|---|---|
| Not landed | The same transaction is sent again, later with a higher priority fee |
| Landed and failed | The fee is booked and the hold released |
| The nonce moved without us | The withdrawal is parked with an alert |
| Cancelled | A message that only advances the nonce takes its place |

## Nonce accounts can be given back
Each nonce account holds rent. An operator retires one, so nothing new uses it, and closes it once it is idle: the hot wallet withdraws the whole balance back to itself, signed by the signing zone under an approval. The rent lowers the cost in the books. The zone accepts only this shape, for an account of the wallet's own pool and paid to the wallet itself, and still refuses to change who controls a nonce account. The cold address's accounts close the same way, in an offline ceremony.

## Sweeps take several addresses at once
A sweep moves several deposit addresses into the hot wallet in one transaction, and the planner always leaves one nonce account for withdrawals. An empty token account is closed after a while and its rent returns to the hot wallet. Deposit keys need parties A and B, so sweeps wait if either is down.
