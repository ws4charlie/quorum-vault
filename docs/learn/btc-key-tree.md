# The Bitcoin hot key tree

All Bitcoin hot addresses, customer deposits and hot shards alike, grow from one MPC keyset. This page shows the shape of that tree and why it is safe for online services to hold the xpub.

## The tree

```text
MPC keyset                       no one holds this key; party A and party B each hold a share
│
└── Account  (84 / coin / 0)     hardened: needs both parties
    │                            its public half is the xpub, held by core, gateway and cosigner
    │
    ├── Branch 0: deposits       non-hardened: derived from the xpub alone
    │   ├── 0/0  deposit address
    │   ├── 0/1  deposit address
    │   └── ...  one per customer
    │
    └── Branch 1: hot shards     non-hardened: derived from the xpub alone
        ├── 1/0  hot shard of one pool
        ├── 1/1  hot shard of another pool
        └── ...  one per pool
```

The coin number is 0 on mainnet and 1 on test networks, so a test address can never be a mainnet address. Cold addresses are not in this tree. They belong to offline keys that the MPC parties never see.

## Why the tree has this shape

Above the account, each step is hardened. Computing it takes a secret that both parties hold in shares, so nothing can walk up or across that part of the tree without both of them.

Below the account, each step is ordinary public derivation. That is what lets the core give a customer a new address without waking the signers, and lets the gateway and cosigner check that an address really is ours. Both branches come from the same xpub, but they never overlap, so a deposit address can never also be a hot shard.

Spending is the expensive direction. Each input is signed by the two parties together, under the key at that input's path.

## The xpub risk

In plain BIP32, the difference between a parent key and its non-hardened child is computed from public data, and the xpub contains that data. So anyone holding the xpub and one child private key can subtract and recover the parent private key, and from there every sibling. That is the well-known reason not to expose an xpub next to a child key.

**The attack does not apply here, because no child private key ever exists.** A child key is only ever two shares used in a joint signature, and it is never assembled anywhere. The parties return public keys, and the signing services can ask for signatures but never for a key. To get a child private key an attacker would have to steal both parties' shares, and with those they already have the keyset, so the xpub gives them nothing more. The same goes for the offline backups: both parties' backups plus the recovery key already equal the whole signing key.

One party's share is not enough either. Combining it with the xpub moves that share up the tree, but it is still half a key.

## What is still true

- **The xpub is private, though not secret.** It cannot move money, but whoever holds it can list every deposit and hot address we have and watch them on chain. Keep it out of logs and public places.
- **The account is the blast radius.** If both shares were ever stolen, every deposit address and hot shard in this tree falls together. This is why hot shards hold little and the excess goes to cold.
- **Never export a child key.** If an emergency tool ever turned a child key into a real private key, for example to move one output by hand, that key together with the xpub would open the whole account. Any such tool must be treated as exposing the account, not one address.
