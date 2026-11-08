# E23-1 — threshold ECDSA (2-of-3) in the cb-mpc wrapper: go / no-go

Date 2026-11-08. cb-mpc v0.2.2 (`2f2c4f1`), not moved. Code: `mpc-party/internal/cbmpc/{threshold,mesh,threshold_backup}.go`, shim additions in `shim.cpp`. Review: `mpc-party/UPSTREAM_REVIEW.md`, section "Multi-party ECDSA". Numbers: `docs/measurements/mpc.md`.

## Recommendation: GO WITH CONDITIONS

`ecdsa_mp` with the access structure `Threshold(2, {m0, m1, m2})` does what E23 needs, through public API only (internals are used for one thing: reading the party name out of the share blob, golden-tested). Signing p95 is **2.0 times** the 2-party p95 (limit set by the task: 3 times). The source review found **no security problem**. It found a library with less outside review than the 2-party path had, which is what the conditions are about.

| Check | Result |
|---|---|
| Names and shape as the lead read them | Confirmed: `dkg_ac`, `refresh_ac`, `sign_ac`; no HD; DKG and refresh need all parties; signing needs only the signers; any pair of the three signs (tested: all 3 pairs, both receivers) |
| Sign p95 against 2-party | 103 ms against 51 ms, in-process and over loopback TCP (limit 3x): pass |
| Security review | No defect found; open gaps listed below |
| Wrapper standard of the 2-party path | Same: `Secret`, wipe, ctx cancel, error kinds, low-S DER checked with btcec, golden, no-mix, malicious peer, `-race` at 32, fuzz |

## Numbers (this machine, Apple M3 Pro; full table in measurements/mpc.md)

| | threshold 2-of-3 | 2-party | ratio |
|---|---:|---:|---:|
| sign p50 / p95 (ms), in-process | 100 / 103 (every pair) | 48 / 50 (derive + sign 50 / 51) | 2.1 / 2.1 |
| sign, bytes sent per signer | 125 KB | 5.2 KB | 24x |
| sign, network rounds | 9 | 6 (9 with derive) | 1.0-1.5x |
| sign, CPU (all signers) | 123 ms | 50 ms | 2.5x |
| DKG, p50 (ms) | 5 | 175 (HD, Paillier) | 0.03x |
| refresh, p50 (ms) | 5 | 109 | 0.05x |
| pair self-test (3 pairs) | 300 ms, 33 rounds | not comparable | |

On a real network add rounds x RTT per signature: 9 x 20 ms = 180 ms (one region), 9 x 100 ms = 900 ms (cross-region), plus 125 KB each way. Three parties in separate trust domains will not share a LAN: this, not CPU, is the cost to plan for. DKG and refresh are cheap (7 KB, 8 rounds) because there is no Paillier key.

## What the wrapper offers (for E23-2)

- `TDKG(ctx, mesh, self)`, `(*TKey).Refresh`, `.Sign(ctx, mesh, peer, receiver, digest)`, `.SelfTest(ctx, mesh, label)`, `.PublicKey`, `.SharePoint`, `LoadTKey`, wipe.
- **Transport.** A session among N parties is a `Mesh`: `Send(ctx, to, msg)` and `Recv(ctx, from)` addressed by member number. `LinkMesh` builds one from one ordinary `Transport` per peer (`NewMemMesh` for tests, `ConnTransport`, or the service's gRPC stream, per peer). cb-mpc attributes a message to a party only by the link it arrived on, so every link must be authenticated (mTLS pinned to that peer) exactly as today. Signing needs only the link to the one peer; DKG, refresh and the self-test need both. A failed party closes its links; the others see `Transport` errors; no group timeout is added beyond ctx and `WithRecvTimeout`.
- **Self-test.** `SelfTest` is called by all three together with a label (keyset id and generation). For each pair (0,1), (0,2), (1,2) the lower member gets a signature over a digest derived from public data only (never from a peer's message, so it is not a signing oracle), checks it, sends it to the higher member, which verifies it against its own public key and answers with a verdict byte. nil on a member means both of its pairs signed and the counterpart confirmed. **Accept new shares only when all three return nil**, and tell each other (the service's two-phase commit). Cost 3 signatures, about 300 ms. A half-refreshed set (one member on the old share) is caught (test).
- **Backup.** One scalar per member, so simpler than the 2-party case (no Paillier key, no "x over q"): `Split` gives the public blob (x wiped, no secret) and x; `PVEExport` encrypts x to the offline recovery key under `TBackupLabel(keyset, member, generation)`; `TPVEVerify` checks it with no secret; `TRestoreScalar` + `TJoin` rebuild the share (checks x*G against the share point). Single-recipient PVE is used, not `pve_batch_ac` (that one shares a secret across several recipients; we have one recovery key). Tested: each member lost and restored then signing with the restored share; old-generation backup does not fit the new generation; the documented procedure (restore, refresh, self-test).
- **Errors.** `Transport` / `Cryptographic` / `Internal` as before. Mixed generations: both sides get `Cryptographic` (better than the 2-party case, where P2 can see success).

## Conditions

1. **E23-2 must run `SelfTest` on all three after every DKG and refresh, before dropping old shares**, and treat any non-nil as "do not accept", with the 2-party two-phase commit extended to three.
2. **Hot balances stay small and cosigner checks stay** (B and C each ask their own `qv-cosigner`). This is the design already; it is also the answer to the dishonest-majority model: two compromised members hold the key.
3. **Keep watching upstream** (advisories, `ecdsa_mp` issues) and re-run the review at every pin change; the first upgrade must re-read `ec_dkg.cpp`, `ecdsa_mp.cpp` and `api/ecdsa_mp.cpp`. The access-structure layer postdates the Cure53 audit.
4. **Ask for an outside look at `ecdsa_mp` before balances grow**, or at least before production (cb-mpc's authors, a second reviewer). This is the one thing this spike cannot supply.
5. **Plan the network.** Budget 9 round trips and 125 KB per signature across the three trust domains; the first fallback order (A+B, then A+C, B+C) costs a failed attempt's timeout before the next pair: use a short per-message timeout on signing.

## Gaps and things not done

- No identifiable abort: a `Cryptographic` error does not name the cheater. The wrapper could attach the peer of the last receive; not done here.
- Load does not check Q against the shares; every signing does (and the self-test).
- Not measured: more than 3 parties, slow links (no network emulation here), memory, the time with the OS under load.
- No change to the 2-party code or its golden fixtures. `scripts/ci.sh` is a Linux/apt script; it was not run on this macOS machine (see report).
