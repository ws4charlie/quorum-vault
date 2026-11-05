# End-to-end sign path measurements

> **History.** This document describes the repository as it was when it was written, including the GG20 / tss-lib MPC backend that P5b-6 removed. Read GG20 mentions as history.

Produced by [scripts/demo-sepolia.sh](../../scripts/demo-sepolia.sh) against a
locally running `quorumvault` server (no `SEPOLIA_RPC_URL`: sign + verify
locally only, no broadcast). Output below is from one run, trimmed: the
offline `quorumvault verify-tx` JSON is cut to its sender lines.

- Date: 2026-11-02 (CST)
- Machine: Apple M3 Pro, 12 logical CPUs, 36 GiB, macOS 27.2, darwin/arm64
- Go go1.27.3, SoftHSM 2.7.0 (Homebrew), Postgres 16 (Docker, localhost:55432)
- Server and client on the same machine; client times are curl `time_total`

## Results

| Step | Latency |
|---|---:|
| HSM sign (PKCS#11 `C_Sign` in SoftHSM, server-side) | ~0.9 ms |
| HSM end-to-end request, allow -> signed (`POST /sign-requests`) | 17.5 ms |
| HSM approve call that completes approval and signs | 18.3 ms |
| MPC 2-of-3 sign ceremony (hot wallet, parties 1+2) | 359 ms |
| MPC 2-of-3 end-to-end request, allow -> signed | 382 ms |
| MPC 3-of-3 sign ceremony (cold wallet, all parties) | 480 ms |
| MPC 3-of-3 final approve call (2nd approval -> signed) | 500 ms |
| MPC DKG keygen (`POST /wallets`, pre-params cached) | 2.69 s |
| MPC DKG keygen, very first run (includes generating + sealing Paillier pre-params) | 13.3 s |

Reading the numbers:
- The sign path itself (policy, DB writes, 4–7 hash-chained audit appends,
  tx build, recovery-id search, verify) costs ~16 ms around the HSM; the HSM
  signature is under 1 ms. Almost all of that is Postgres round trips and the
  serialized audit appends.
- For MPC the ceremony dominates: 9 GG20 rounds, 20 messages (2 parties) or
  60 (3 parties), plus unsealing each share from its party's token. These
  match the T3 bench ([mpc.md](mpc.md)): 2-party median ~370 ms, 3-party ~494 ms.
- The full quorum costs ~120 ms more than the threshold set: a cold-wallet
  signature is slower, and it also waits for two human approvals.
- All four signatures are in-process; a networked MPC deployment adds 9
  round trips of network latency per signature.

## Run output (trimmed)

```text
== health
{"ok":true,"db":{"ok":true},"hsm":{"ok":true,"token":"quorumvault"}}

== 1a. HSM hot wallet: create, policy (approval over 0.01 ETH), allowlist
wallet demo-hsm-hot (hot/hsm) id=52d2d404-1793-44eb-ab3d-7b429e3e0466 address=0x173884df315e159F2EC1175DD43A7D6345F64a96 create=13.7ms
policy {"approval_threshold_wei":"10000000000000000","per_tx_limit_wei":"500000000000000000","daily_limit_wei":"1000000000000000000","required_approvals":1}
allowlist ["0x000000000000000000000000000000000000dead"]

== 1b. HSM: 0.001 ETH -> allowed, signed in-token
request a009267b-d787-4b25-8c96-7014ff3b9683 value=1000000000000000 wei -> status=signed decision={"outcome":"allow","reasons":[],"required_approvals":1} http=17.5ms
  signed: tx_hash=0x6b4fc9dec5c106143aedfa5c5d6a2c70645add239953255ee7a548e3d6509b55
  from (server-recovered) = 0x173884df315e159F2EC1175DD43A7D6345F64a96   wallet = 0x173884df315e159F2EC1175DD43A7D6345F64a96
  raw_tx = 0x02f87583aa36a780843b9aca008506fc23ac0082520894000000000000000000000000000000000000dead87038d7ea4c6800080c080a0a4cec623fbbd608e07a4cec0946de30deecb48ea4030f7bacd1dda5cede43901a05f920a9e6f245bdbde765610ce6b7ed0622b81dc7999e707d9cfb9e5285d080a
  offline verify-tx:
      "recovered_sender": "0x173884df315e159F2EC1175DD43A7D6345F64a96",
      "sender_matches": true,

== 1c. HSM: 0.1 ETH -> pending_approval; alice cannot self-approve; bob approves
request 61d7bb31-5919-4fb4-8b08-dc810cd1a40d value=100000000000000000 wei -> status=pending_approval decision={"outcome":"needs_approval","reasons":["exceeds approval threshold"],"required_approvals":1} http=9.7ms
self-approve by alice -> HTTP 403 {"error":"approval: requester cannot vote on own request"}
approve by bob -> status=signed tally={"approvals":1,"rejected":false,"required":1,"done":true} http=18.3ms
  signed: tx_hash=0x59bc13b74689593152ec156fc6f4f69f6263d4a66526d935b58e6e3091f9b7dc
  from (server-recovered) = 0x173884df315e159F2EC1175DD43A7D6345F64a96   wallet = 0x173884df315e159F2EC1175DD43A7D6345F64a96
  raw_tx = 0x02f87683aa36a780843b9aca008506fc23ac0082520894000000000000000000000000000000000000dead88016345785d8a000080c080a0e7a5147cd4f087cc8c2bbec130ae6fee22e6466686c8236687912a5559403f06a0686a6cb743831478080912b19cbe044747ea0fa488a260ec0d3fa7063eabb2a2
  offline verify-tx:
      "recovered_sender": "0x173884df315e159F2EC1175DD43A7D6345F64a96",
      "sender_matches": true,

== 2. MPC hot wallet: 2-of-3 threshold signing
wallet demo-mpc-hot (hot/mpc) id=0109e38a-4fdb-4b1d-9954-b09f96b14822 address=0x7D26ABF602B27a48863E90E901bCf9A4654B69dd create=2692.4ms
policy {"approval_threshold_wei":"10000000000000000","per_tx_limit_wei":"500000000000000000","daily_limit_wei":"1000000000000000000","required_approvals":1}
allowlist ["0x000000000000000000000000000000000000dead"]
request 0d3ce306-0cb5-47f8-b339-a6139bf93375 value=1000000000000000 wei -> status=signed decision={"outcome":"allow","reasons":[],"required_approvals":1} http=382.5ms
  signed: tx_hash=0xde1e21ba4d9b6f109cd3c4c81b7f215b9f68faa0eff5866ba084f3654900c45b
  from (server-recovered) = 0x7D26ABF602B27a48863E90E901bCf9A4654B69dd   wallet = 0x7D26ABF602B27a48863E90E901bCf9A4654B69dd
  raw_tx = 0x02f87583aa36a780843b9aca008506fc23ac0082520894000000000000000000000000000000000000dead87038d7ea4c6800080c080a0c698e2b7b02c8fef789791663d1cecf0bb2ab097fd9c96bef3d1b97c5e3621f7a0048ff71c04bf553aeeef811ca77e7bcee7d53dfff6e5fdba53411f1c4f0d279a
  offline verify-tx:
      "recovered_sender": "0x7D26ABF602B27a48863E90E901bCf9A4654B69dd",
      "sender_matches": true,
  participants: ["party-1","party-2"]

== 3. MPC cold wallet: 1 wei still needs 2 approvals; full 3-of-3 quorum
wallet demo-mpc-cold (cold/mpc) id=1352317e-b82c-4d7a-aef0-7c64c7620cb9 address=0xfF5542991823925dbD20Ef7d265976478BcF0ff2 create=2690.2ms
policy {"approval_threshold_wei":"10000000000000000","per_tx_limit_wei":"500000000000000000","daily_limit_wei":"1000000000000000000","required_approvals":2}
allowlist ["0x000000000000000000000000000000000000dead"]
request b5d5d253-bebc-47b7-bd63-3b27f517ee8e value=1 wei -> status=pending_approval decision={"outcome":"needs_approval","reasons":["cold wallet requires approval"],"required_approvals":2} http=9.4ms
approve by bob -> status=pending_approval tally={"approvals":1,"rejected":false,"required":2,"done":false} http=6.6ms
approve by carol -> status=signed tally={"approvals":2,"rejected":false,"required":2,"done":true} http=499.6ms
  signed: tx_hash=0x4aa51dcdf3702568bea40cc9d9eafce015a53861a00864fa4b7de8cfb8b867cf
  from (server-recovered) = 0xfF5542991823925dbD20Ef7d265976478BcF0ff2   wallet = 0xfF5542991823925dbD20Ef7d265976478BcF0ff2
  raw_tx = 0x02f86e83aa36a780843b9aca008506fc23ac0082520894000000000000000000000000000000000000dead0180c080a07dd39c56954950f2284ec9e379a491ae0203e5c8765cd1d4f2676d64dd766129a07f99e8cbaec67a51fdecbc55d71096a6fe0be5f79ab690256a88ff3ba786c069
  offline verify-tx:
      "recovered_sender": "0xfF5542991823925dbD20Ef7d265976478BcF0ff2",
      "sender_matches": true,
  participants: ["party-1","party-2","party-3"]

== 4. audit trail for the cold request, and chain verification
  #64 request.created by alice
  #65 policy.decision by alice
  #66 approval.voted by bob
  #67 approval.voted by carol
  #68 request.approved by carol
  #69 sign.started by carol
  #70 sign.completed by carol
audit verify: {"ok":true}
== summary: signed Sepolia (chain 11155111) EIP-1559 txs
  HSM (hot, allow)             0x6b4fc9dec5c106143aedfa5c5d6a2c70645add239953255ee7a548e3d6509b55  from 0x173884df315e159F2EC1175DD43A7D6345F64a96
  HSM (hot, approved)          0x59bc13b74689593152ec156fc6f4f69f6263d4a66526d935b58e6e3091f9b7dc  from 0x173884df315e159F2EC1175DD43A7D6345F64a96
  MPC 2-of-3 (hot, allow)      0xde1e21ba4d9b6f109cd3c4c81b7f215b9f68faa0eff5866ba084f3654900c45b  from 0x7D26ABF602B27a48863E90E901bCf9A4654B69dd
  MPC 3-of-3 (cold, approved)  0x4aa51dcdf3702568bea40cc9d9eafce015a53861a00864fa4b7de8cfb8b867cf  from 0xfF5542991823925dbD20Ef7d265976478BcF0ff2

client ms = curl time_total; server ms = timings_ms (sign = backend ceremony only, else whole call)
| Step                                             | client ms | server ms |
|--------------------------------------------------|----------:|----------:|
| HSM (hot, allow): sign ceremony                  |         - |     0.973 |
| HSM e2e request (POST, allow -> signed)          |      17.5 |    17.052 |
| HSM (hot, approved): sign ceremony               |         - |     0.849 |
| HSM approve call (vote -> signed)                |      18.3 |     17.87 |
| MPC DKG keygen (POST /wallets hot)               |    2692.4 |         - |
| MPC 2-of-3 (hot, allow): sign ceremony           |         - |   358.566 |
| MPC 2-of-3 e2e request (POST, allow -> signed)   |     382.5 |   381.918 |
| MPC DKG keygen (POST /wallets cold)              |    2690.2 |         - |
| MPC 3-of-3 (cold, approved): sign ceremony       |         - |   480.291 |
| MPC 3-of-3 final approve (vote -> signed)        |     499.6 |   499.112 |
```

## How to reproduce

```bash
./scripts/setup-softhsm.sh
export DATABASE_URL='postgres://qv@localhost:55432/quorumvault?sslmode=disable'
CGO_ENABLED=1 go build -o bin/quorumvault ./cmd/quorumvault
QV_HTTP_ADDR=127.0.0.1:18080 ./bin/quorumvault &
QV_URL=http://127.0.0.1:18080 QV_BIN=./bin/quorumvault ./scripts/demo-sepolia.sh
```

To broadcast as well, see the next section (local anvil, no faucet), or start
the server with `SEPOLIA_RPC_URL` pointing to a real Sepolia node and fund the
printed wallet addresses from a faucet first (nonce and fees then come from
the node).

## Broadcast on local anvil (chain ID 11155111)

The same demo in local-chain mode: the server runs with
`SEPOLIA_RPC_URL=http://127.0.0.1:8545`, a local anvil node started with
`--chain-id 11155111` so it accepts the Sepolia transactions unchanged. The
script refuses unless the node reports `anvil` and chain ID 11155111 on a
local host, funds each wallet with `anvil_setBalance`, leaves nonce and fees
to the server (filled from the node), and fetches every receipt.

- Date: 2026-11-02 (CST); same machine and versions as above
- anvil 1.8.5 (`ghcr.io/foundry-rs/foundry:v1.8.5`, Docker), automine (each tx
  is mined in its own block as soon as it arrives)

| Step | Latency |
|---|---:|
| Broadcast, HSM tx (`eth_sendRawTransaction`, server-side) | 0.28–0.44 ms |
| Broadcast, MPC tx (server-side) | 1.3–1.5 ms |
| Receipt available | first poll |
| HSM end-to-end request with broadcast, allow -> signed -> sent | 26.0 ms |
| MPC 2-of-3 end-to-end request with broadcast | 392 ms |
| MPC 3-of-3 final approve with broadcast | 485 ms |

Reading the numbers:
- Broadcast adds about 1 ms to a request: anvil validates the tx (signature,
  chain ID, nonce, balance) and mines it inside the `eth_sendRawTransaction`
  call. All 4 receipts were there on the first `eth_getTransactionReceipt`
  (the ~45 ms "receipt fetched" client times in the table are curl + jq
  process start-up, not chain time). On real Sepolia a receipt takes one or
  more 12 s slots instead.
- `gasUsed` is 21000 for each plain transfer; `effectiveGasPrice` = base fee +
  tip (1 gwei tip; anvil's base fee starts at 1 gwei and falls while blocks
  are nearly empty), always below the `max_fee_per_gas` the server signed
  (2 × base fee + tip).
- The HSM wallet's second tx (1c) got nonce 1 from the node: the first had
  already been mined. The e2e test `ApprovedAfterLaterTransferGetsFreshNonce`
  covers the harder order (approved request overtaken by a later one).
- The same flows run as Go tests on every push: `make test-e2e`, CI job `e2e`.

Run output (trimmed: raw txs and most of the offline `verify-tx` JSON cut):

```text
== health
{"ok":true,"db":{"ok":true},"hsm":{"ok":true,"token":"quorumvault"}}
local chain: anvil/v1.8.5 at http://127.0.0.1:8545, chain id 11155111 (Sepolia), block 18

== 1a. HSM hot wallet: create, policy (approval over 0.01 ETH), allowlist
wallet demo-hsm-hot (hot/hsm) id=b7830fa0-868d-4dbe-918e-214fa18b59de address=0xbe47F11D79d40D2d84814c05492802dB62110B7C create=18.6ms
funded 0xbe47F11D79d40D2d84814c05492802dB62110B7C with 10 ETH via anvil_setBalance (balance 0x8ac7230489e80000)
policy {"approval_threshold_wei":"10000000000000000","per_tx_limit_wei":"500000000000000000","daily_limit_wei":"1000000000000000000","required_approvals":1}
allowlist ["0x000000000000000000000000000000000000dead"]

== 1b. HSM: 0.001 ETH -> allowed, signed in-token
request c682249a-158e-4cc7-9abf-6e3a94d7943a value=1000000000000000 wei -> status=signed decision={"outcome":"allow","reasons":[],"required_approvals":1} http=26.0ms
  signed: tx_hash=0x1f5826f9f1a9c0cf07efa1a13104b8842a784de0c0e052230f754f3a8dfdceda
  from (server-recovered) = 0xbe47F11D79d40D2d84814c05492802dB62110B7C   wallet = 0xbe47F11D79d40D2d84814c05492802dB62110B7C
  broadcast: ok
  receipt (poll 1): block=19 status=1 gasUsed=21000 effectiveGasPrice=1090721093 wei from=0xbe47f11d79d40d2d84814c05492802db62110b7c
  offline verify-tx:
      "nonce": 0,
      "recovered_sender": "0xbe47F11D79d40D2d84814c05492802dB62110B7C",
      "sender_matches": true,

== 1c. HSM: 0.1 ETH -> pending_approval; alice cannot self-approve; bob approves
request fc7e34d2-83f2-4fae-925d-2163c9bb29b3 value=100000000000000000 wei -> status=pending_approval decision={"outcome":"needs_approval","reasons":["exceeds approval threshold"],"required_approvals":1} http=15.9ms
self-approve by alice -> HTTP 403 {"error":"approval: requester cannot vote on own request"}
approve by bob -> status=signed tally={"approvals":1,"rejected":false,"required":1,"done":true} http=10.7ms
  signed: tx_hash=0x3dcad5bd9f5fd01446d8125cfe3e96e7434501107f21b2891440b98d0b2322e6
  from (server-recovered) = 0xbe47F11D79d40D2d84814c05492802dB62110B7C   wallet = 0xbe47F11D79d40D2d84814c05492802dB62110B7C
  broadcast: ok
  receipt (poll 1): block=20 status=1 gasUsed=21000 effectiveGasPrice=1079396833 wei from=0xbe47f11d79d40d2d84814c05492802db62110b7c
  offline verify-tx:
      "nonce": 1,
      "recovered_sender": "0xbe47F11D79d40D2d84814c05492802dB62110B7C",
      "sender_matches": true,

== 2. MPC hot wallet: 2-of-3 threshold signing
wallet demo-mpc-hot (hot/mpc) id=160a1220-f9ee-4342-af8c-0ac70903436c address=0xA3E3Fd5533e906f24c45A1dd0c0C8c5D1A3Bd3A5 create=2690.5ms
funded 0xA3E3Fd5533e906f24c45A1dd0c0C8c5D1A3Bd3A5 with 10 ETH via anvil_setBalance (balance 0x8ac7230489e80000)
policy {"approval_threshold_wei":"10000000000000000","per_tx_limit_wei":"500000000000000000","daily_limit_wei":"1000000000000000000","required_approvals":1}
allowlist ["0x000000000000000000000000000000000000dead"]
request 31ed6a36-5080-41c9-bc50-b6172a933183 value=1000000000000000 wei -> status=signed decision={"outcome":"allow","reasons":[],"required_approvals":1} http=391.6ms
  signed: tx_hash=0xeadfad3b8d7c711530c6cf6526e83a67e751a1fc0ac988058d7223bd8797043b
  from (server-recovered) = 0xA3E3Fd5533e906f24c45A1dd0c0C8c5D1A3Bd3A5   wallet = 0xA3E3Fd5533e906f24c45A1dd0c0C8c5D1A3Bd3A5
  broadcast: ok
  receipt (poll 1): block=21 status=1 gasUsed=21000 effectiveGasPrice=1069486124 wei from=0xa3e3fd5533e906f24c45a1dd0c0c8c5d1a3bd3a5
  offline verify-tx:
      "nonce": 0,
      "recovered_sender": "0xA3E3Fd5533e906f24c45A1dd0c0C8c5D1A3Bd3A5",
      "sender_matches": true,
  participants: ["party-1","party-2"]

== 3. MPC cold wallet: 1 wei still needs 2 approvals; full 3-of-3 quorum
wallet demo-mpc-cold (cold/mpc) id=66515561-d882-4e5f-bf5a-57a9dfa4c11e address=0xaac8494C5e3E97dBAD70ac5a6a3A6a01d80807D1 create=2704.8ms
funded 0xaac8494C5e3E97dBAD70ac5a6a3A6a01d80807D1 with 10 ETH via anvil_setBalance (balance 0x8ac7230489e80000)
policy {"approval_threshold_wei":"10000000000000000","per_tx_limit_wei":"500000000000000000","daily_limit_wei":"1000000000000000000","required_approvals":2}
allowlist ["0x000000000000000000000000000000000000dead"]
request e3943db3-0362-404f-9843-dfb288b84e03 value=1 wei -> status=pending_approval decision={"outcome":"needs_approval","reasons":["cold wallet requires approval"],"required_approvals":2} http=8.0ms
approve by bob -> status=pending_approval tally={"approvals":1,"rejected":false,"required":2,"done":false} http=5.6ms
approve by carol -> status=signed tally={"approvals":2,"rejected":false,"required":2,"done":true} http=484.7ms
  signed: tx_hash=0x176c87160ebd87f58abb1cb6df5470dfab3a85678a2a68fb356a3e9579893945
  from (server-recovered) = 0xaac8494C5e3E97dBAD70ac5a6a3A6a01d80807D1   wallet = 0xaac8494C5e3E97dBAD70ac5a6a3A6a01d80807D1
  broadcast: ok
  receipt (poll 1): block=22 status=1 gasUsed=21000 effectiveGasPrice=1060812519 wei from=0xaac8494c5e3e97dbad70ac5a6a3a6a01d80807d1
  offline verify-tx:
      "nonce": 0,
      "recovered_sender": "0xaac8494C5e3E97dBAD70ac5a6a3A6a01d80807D1",
      "sender_matches": true,
  participants: ["party-1","party-2","party-3"]

== 4. audit trail for the cold request, and chain verification
  #71 request.created by alice
  #72 policy.decision by alice
  #73 approval.voted by bob
  #74 approval.voted by carol
  #75 request.approved by carol
  #76 sign.started by carol
  #77 sign.completed by carol
  #78 tx.broadcast by carol
audit verify: {"ok":true}

== summary: Sepolia (chain 11155111) EIP-1559 txs, mined on local anvil
  HSM (hot, allow)             0x1f5826f9f1a9c0cf07efa1a13104b8842a784de0c0e052230f754f3a8dfdceda  from 0xbe47F11D79d40D2d84814c05492802dB62110B7C
  HSM (hot, approved)          0x3dcad5bd9f5fd01446d8125cfe3e96e7434501107f21b2891440b98d0b2322e6  from 0xbe47F11D79d40D2d84814c05492802dB62110B7C
  MPC 2-of-3 (hot, allow)      0xeadfad3b8d7c711530c6cf6526e83a67e751a1fc0ac988058d7223bd8797043b  from 0xA3E3Fd5533e906f24c45A1dd0c0C8c5D1A3Bd3A5
  MPC 3-of-3 (cold, approved)  0x176c87160ebd87f58abb1cb6df5470dfab3a85678a2a68fb356a3e9579893945  from 0xaac8494C5e3E97dBAD70ac5a6a3A6a01d80807D1

client ms = curl time_total; server ms = timings_ms (sign = backend ceremony only, else whole call)
| Step                                                       | client ms | server ms |
|------------------------------------------------------------|----------:|----------:|
| HSM (hot, allow): broadcast (eth_sendRawTransaction)       |         - |     0.442 |
| HSM (hot, allow): receipt fetched (poll 1, curl+jq)        |      47.3 |         - |
| HSM (hot, allow): sign ceremony                            |         - |     2.607 |
| HSM e2e request (POST, allow -> signed)                    |      26.0 |     25.55 |
| HSM (hot, approved): broadcast (eth_sendRawTransaction)    |         - |     0.282 |
| HSM (hot, approved): receipt fetched (poll 1, curl+jq)     |      42.9 |         - |
| HSM (hot, approved): sign ceremony                         |         - |       0.9 |
| HSM approve call (vote -> signed)                          |      10.7 |    10.353 |
| MPC DKG keygen (POST /wallets hot)                         |    2690.5 |         - |
| MPC 2-of-3 (hot, allow): broadcast (eth_sendRawTransaction) |         - |     1.547 |
| MPC 2-of-3 (hot, allow): receipt fetched (poll 1, curl+jq) |      42.1 |         - |
| MPC 2-of-3 (hot, allow): sign ceremony                     |         - |   360.185 |
| MPC 2-of-3 e2e request (POST, allow -> signed)             |     391.6 |   390.973 |
| MPC DKG keygen (POST /wallets cold)                        |    2704.8 |         - |
| MPC 3-of-3 (cold, approved): broadcast (eth_sendRawTransaction) |         - |     1.302 |
| MPC 3-of-3 (cold, approved): receipt fetched (poll 1, curl+jq) |      46.3 |         - |
| MPC 3-of-3 (cold, approved): sign ceremony                 |         - |   461.201 |
| MPC 3-of-3 final approve (vote -> signed)                  |     484.7 |   484.175 |
```

Reproduce:

```bash
make chain-up            # or: docker run -d --rm --name qv-anvil -p 127.0.0.1:8545:8545 \
                         #   ghcr.io/foundry-rs/foundry:v1.8.5 "anvil --host 0.0.0.0 --chain-id 11155111"
CGO_ENABLED=1 go build -o bin/quorumvault ./cmd/quorumvault
SEPOLIA_RPC_URL=http://127.0.0.1:8545 QV_HTTP_ADDR=127.0.0.1:18080 ./bin/quorumvault &
QV_URL=http://127.0.0.1:18080 QV_BIN=./bin/quorumvault ./scripts/demo-sepolia.sh --local
```
