# Solana

A customer gets a Solana address, pays it in SOL or in one SPL token, and is credited once, after the payment is final, through the same
ledger as EVM and Bitcoin. Family `sol`, package [internal/chain/sol](../../internal/chain/sol). Customers withdraw SOL and the token from the hot shards, each
withdrawal on a durable nonce (see "Withdrawals sign a nonce, not a blockhash"), and credited deposits are swept to the hot shard in batches (see "Sweeps take several addresses at once").

```mermaid
flowchart LR
  A["mpc-party A + B<br/>Ed25519 HD keyset"] -- "account node (public)" --> C["core: derives addresses offline"]
  C -- "one address per customer" --> D(["customer pays"])
  V["validator"] -- "finalized signatures + transactions" --> S["scan"] --> L["ledger"]
  L <-- "Reconcile: finalized balances" --> V
```

## Addresses come from public data

Each customer's address is an Ed25519 public key derived below an account node of the two-party HD keyset (parties A and B). The two parties
walk the hardened part of the path together once and hand out a public key and a chain code, the account node. From then on anyone holding the
node derives every child public key alone, with no MPC and no secret, the way Bitcoin does from an xpub. cb-mpc applies the BIP32 rule to
Edwards points (SLIP-0010, the other common Ed25519 scheme, has no public derivation), and a test on real mpc-party proves that the address
derived offline is the key the parties derive. The path mirrors Bitcoin's: a hardened account level, then the external branch, then the
customer's index. The hot shards will use the other branch. The core's config holds only the node.

## Tokens live in the associated token account

A token balance is not kept on the address but in a token account. The address's associated token account (ATA) is the one account every
wallet pays by default, and the only one the books credit. Tokens sent to any other token account the address owns are on the chain and not in
the ledger: they are not credited, and Reconcile raises an alert that names the account, so an operator decides. Tokens of a mint nobody
configured, and Token-2022 tokens, are never credited. The ATA does not exist until someone creates it; wallets do that in the same transaction
as the payment.

## Rent can make a small payment fail

An account must hold a minimum balance to exist. A payment to an address that does not exist yet fails on the chain when it is smaller than
that minimum, and a failed transaction moves nothing, so there is nothing to credit and the scanner skips it. The configured minimum deposit
is a separate, business rule: a payment above the rent minimum and below the configured one lands on the chain and goes to suspense.

## Finality is rooting

A transaction that is confirmed can still be dropped with its fork. The scanner reads at the finalized commitment, which means rooted, a few
dozen slots later, and credits only what it finds there. It does not use the node's idea of "seen" for anything that moves money. Heights in the
cursor are slots.

## How the scan works

The node lists transactions per account, not per block, so the scanner asks for the finalized signatures of every deposit address and of its
token account for each configured mint, newest first, back to the cursor. It reads each transaction once, parsed, and walks its instructions,
inner ones included, so a payment made through another program counts. A deposit's identity is the signature plus the instruction's position.
The cost grows with the number of addresses; a very large customer base would want a different feed.

## Reconcile has no history to read

A Solana node keeps no balances of the past, so Reconcile cannot pin its comparison to a height. It reads each address's finalized balances,
puts them beside the books, and waits when the cell reports finalized activity the scan has not covered yet, or when the books changed
during the read. If that keeps happening the comparison is skipped and the report says so and is not clean. Anything left after that is a real
difference, in lamports or token base units.

## How signing is checked

Ed25519 signs the whole message, so the signing zone does not see a digest of a transaction: it sees the transaction. The gateway and the
cosigner of each of parties B and C decode every message themselves, from their own config, and accept it only if it is exactly one of a few
shapes built from the approved intent. Nothing else can be in it: no other program, no extra signer, no extra account, no instruction that
changes who owns or may spend a token account. Each judges alone, so a refusal does not depend on the others being up.

| What | The message must be |
|---|---|
| SOL withdrawal | the nonce advance, then a transfer from the hot shard to the approved destination, the approved amount |
| Token withdrawal | the nonce advance, then a checked transfer from the hot shard's token account to the destination's, with the configured mint and decimals, and optionally the creation of the destination's account, paid by the hot shard |
| Cancel | the nonce advance alone |
| Nonce setup | pairs of "create" and "initialize" for accounts of the shard's own pool, rent from the shard; needs an operator's approval |
| Sweep of SOL | the nonce advance, then one transfer per deposit address to the hot shard, which pays the fee |
| Sweep of a token | the nonce advance, then per deposit address a checked transfer from its token account to the hot shard's, and optionally closing that deposit account with its rent going to the hot shard |

A message may begin with a compute-budget limit (required) and price (optional), both under caps in the zone's config. Versioned messages
are refused, because the tables they use hide who is paid.

**Keys and jobs.** A withdrawal has one signature, the hot shard's, made by the 2-of-3 keyset on A, B and C. A sweep has one more for each deposit address it takes: the hot shard pays the fee, and each deposit key signs as the owner of its own address only. Deposit keys come from the two-party HD keyset; the zone derives their public keys from its own copy of the account node and requires each signer to be exactly the key at the index the sweep names. The replay guard keeps one record per message and signer, so the jobs of one sweep do not collide.

**Versions of one intent.** A withdrawal or a sweep may get more than one message, under the nonce rule below; anything else about it is fixed by the intent. A retry of the same job returns the stored signature.

**Rent on a sweep.** The zone checks the amount the intent names, not what the account keeps: it cannot see balances. The core decides the
amount, and the chain refuses a transfer that would leave a system account between zero and the minimum.

**Why a second signature does not matter.** The randomized signing of the two-party and three-party Ed25519 means a job that failed on one
coordinator and was signed through another could produce two different valid signatures of one message. The validator runs one: its
duplicate check keys on the hash of the message, not on the signature, so the second is refused as already processed, also when both are sent
at once. This is tested on the local validator and does not depend on the gateway. The gateway still never hands out a second signature for a
job, and a coordinator that failed after signing began keeps the job.

## Withdrawals sign a nonce, not a blockhash

A blockhash expires in about a minute, and the signing zone cannot check its age. So a withdrawal signs the value held by a nonce account
instead, an account of the system program whose authority is the hot shard, and its first instruction advances that nonce. Whichever version
of the withdrawal lands first uses the value up; every other version, signed or not, is refused by the network from then on. This is the
Solana form of an EVM nonce, and the outcomes are the same.

Each hot shard owns a small pool of these accounts, and one account carries one withdrawal at a time. Their addresses are not random keys: each
is made from the shard's address and a fixed seed, so the creation needs no signature but the shard's, there is no key to keep or lose, and
the zone knows every address of every pool from its own config. An operator command creates the pool through the signing zone, which signs it
only under an operator's approval and only for the pool's own addresses with the configured rent. The rent leaves the shard and is booked as a
cost. Closing a nonce account or changing its authority is not signed at all.

A withdrawal takes a free account when it is built, in the transaction that enqueues its signing, and reads the nonce at finalized
commitment: the account was freed only after its last user finalized, so the value cannot change under a fork. With every account busy, the
withdrawal waits, as it does for hot liquidity.

| What happens | Result |
|---|---|
| Not landed | the stored signed transaction is sent again; after the stuck time a version with a higher priority price, same nonce |
| Landed and succeeded | settled at finalized |
| Landed and failed | the nonce still advanced and the fee was paid: the hold is released, the fee booked as a cost, the account free |
| The nonce moved and none of our versions landed | the withdrawal is parked with one alert, as an EVM nonce used by a stranger |
| Cancelled | a message that advances the nonce alone; once it is final no version can ever land, and the hold is released |
| Refused by the zone before anything was signed | the account is given back unused |

**What the zone enforces.** The replay guard holds one claim per intent: the nonce account and its value. A second message for the intent is
signed only if it has the same claim, the same compute-unit limit and a higher price; a different account, a different value, a lower price or
anything else is refused, whatever the business zone says. The cosigners of B and C apply the same rule from their own records. A cancel is
signed only for a nonce that a signed intent of the same shard holds, and after it that intent gets no further version.

**What Reconcile does with it.** The hot shards are compared with the books too. A withdrawal that has finalized and is not settled yet has
already left the chain, so it is explained from the cell's own records of the transaction, and the comparison is repeated if those, or the
books, change while it runs.

## Sweeps take several addresses at once

A sweep moves the credited funds of up to a few deposit addresses of one asset into the hot shard in a single transaction. It signs a nonce of the shard's pool like a withdrawal, because the signatures of several parties would otherwise race a blockhash that lives for about a minute, and so at most one version of a sweep can land. Each sweep holds a pool account until it is final, so the planner never lets sweeps take the last account: one stays for withdrawals.

- **What is swept.** Only credited deposits, and only when an address is worth it: its funds must cover several times the fee of sweeping it alone and pass a configured floor. Smaller amounts stay where they are. A SOL address is swept to zero; an address may not be left between zero and the rent minimum.
- **How many fit.** A transaction is at most 1232 bytes and every deposit owner adds a signature and accounts. In the worst case, with the hot token account opened and every deposit account closed, five token addresses fit; eight SOL addresses fit. The configured batch is checked against the token limit at start.
- **Closing the token account.** When an address has had no credited deposit of the token for a configured time, its sweep also closes the empty token account and the rent goes to the hot shard. The customer keeps the same address; the next deposit makes the sender create the account again, and it is credited as before. If a deposit lands between the planning and the transaction, the close fails with the whole transaction, and the sweep is planned again.
- **Books.** A sweep is booked as on the other chains: out of the deposits when it is broadcast, into the hot shard when it is final, from what the chain says moved. The rent of a closed account is a cost reduction, not income: the fee account is the operator's own money in the native asset, and rent the operator paid to open accounts comes back to it. A sweep whose network fee is more than recovered rent still books a cost.
- **Reconcile in flight.** Deposit addresses, the hot shard and the sweep clearing account are each compared with the chain at every stage. A sweep that has moved funds the books do not yet know is explained from the chain's record of the transaction; one the books have booked and the chain has not moved is added back.
- **Failure.** A sweep that lands and fails moves nothing and pays its fee; the books record only the fee, and the planner tries again after a delay. The usual cause is funds that arrived after planning and would leave a system account below the rent minimum.
- **A deposit key needs A and B.** The two-party key cannot sign with either down. A sweep then fails after its signing retry, and the planner sweeps again after the party returns. Nothing is lost while it waits; with C down alone, sweeps go on.

## Limits

- **Withdrawals and sweeps, to and from the first hot shard.** Cold storage, refills and rebalancing for Solana come later; the zone refuses those intents on this chain, and sweeps all go to shard 0.
- **Hot funding is booked by an operator call**, not found by the scan.
- **The pool has a fixed size** set in config; a shard that needs more accounts than that waits for a free one.
- **Rent paid for nonce accounts and for token accounts opened for customers is booked as a cost** and is not recovered.
- **"Something else advanced the nonce" is tested by changing the books' record of the nonce**, since only the shard's key can advance it on a local validator.
- **One token program.** The classic SPL Token program only.
- **A token's decimals are checked at start** against the mint; a mismatch refuses to start.
- **The account node is fetched with a small helper** (`sol.AccountNode`); there is no operator command for it yet.
- **The validator in the tests is Agave 3.0**, pinned by checksum; the newer line cannot start under Docker's emulation on Apple silicon.
