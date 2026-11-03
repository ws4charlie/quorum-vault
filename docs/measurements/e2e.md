# End-to-end sign path measurements

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

To broadcast as well, start the server with `SEPOLIA_RPC_URL` set and fund
the printed wallet addresses from a faucet first (nonce and fees then come
from the node).
