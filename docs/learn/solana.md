# Solana

A customer gets a Solana address, pays it in SOL or in one SPL token, and is credited once, after the payment is final, through the same
ledger as EVM and Bitcoin. Family `sol`, package [internal/chain/sol](../../internal/chain/sol). The signing zone can sign Solana
transactions (see "How signing is checked"); nothing in the product sends one yet.

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
| SOL withdrawal | a transfer from the hot shard to the approved destination, the approved amount |
| Token withdrawal | a checked transfer from the hot shard's token account to the destination's, with the configured mint and decimals, and optionally the creation of the destination's account, paid by the hot shard |
| Sweep of SOL | a transfer from the deposit address to the hot shard, which pays the fee |
| Sweep of a token | a checked transfer from the deposit address's token account to the hot shard's, and optionally closing the deposit account with its rent going to the hot shard |

A message may begin with a compute-budget limit (required) and price (optional), both under caps in the zone's config. Versioned messages
are refused, because the tables they use hide who is paid.

**Two keys, two jobs.** A withdrawal has one signature, the hot shard's, made by the 2-of-3 keyset on A, B and C. A sweep has two over the
same message: the hot shard pays the fee, and the deposit key signs as owner. The deposit key comes from the two-party HD keyset; the zone
derives its public key from its own copy of the account node and requires the signer to be that key. The replay guard keeps one record per
message and signer, so the two jobs of one sweep do not collide.

**One message per intent.** A second message for an intent already signed, say with a fresher blockhash, is refused. The zone cannot tell
that the first one is dead, and both could land. A retry of the same job returns the stored signature. When a withdrawal may be signed again
after its blockhash expired is a rule for the withdrawal task, which has to prove the old message dead first.

**The blockhash.** Its age cannot be checked offline, and the zone does not try. A stale blockhash only makes the network refuse the
transaction. What keeps a message from meaning something else is the shape list: there is no way to ask for a durable-nonce advance.

**Rent on a sweep.** The zone checks the amount the intent names, not what the account keeps: it cannot see balances. The core decides the
amount, and the chain refuses a transfer that would leave a system account between zero and the minimum.

**Why a second signature does not matter.** The randomized signing of the two-party and three-party Ed25519 means a job that failed on one
coordinator and was signed through another could produce two different valid signatures of one message. The validator runs one: its
duplicate check keys on the hash of the message, not on the signature, so the second is refused as already processed, also when both are sent
at once. This is tested on the local validator and does not depend on the gateway. The gateway still never hands out a second signature for a
job, and a coordinator that failed after signing began keeps the job.

## Limits

- **Deposits and signing only.** Building and sending Solana transactions come later; so do sweeps, withdrawals and cold storage. Cold, to-cold and rebalance intents are refused by the signing zone on this chain.
- **One token program.** The classic SPL Token program only.
- **A token's decimals are checked at start** against the mint; a mismatch refuses to start.
- **The account node is fetched with a small helper** (`sol.AccountNode`); there is no operator command for it yet.
- **The validator in the tests is Agave 3.0**, pinned by checksum; the newer line cannot start under Docker's emulation on Apple silicon.
