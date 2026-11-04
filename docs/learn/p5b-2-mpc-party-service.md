# P5b-2 — The mpc-party service: two processes, two ports, one protocol session at a time

P5b-1 gave us a library. P5b-2 turns it into two long-running processes, party A (coordinator, P1) and party B (follower,
P2), that talk over mutually authenticated TLS and serve key and signing requests. The gateway is not connected yet
(P5b-3); the production policy check (`Authorizer`) and the HSM sealer (P5b-4) are interfaces with test stand-ins.

## What was built

| Piece | Where |
|---|---|
| gRPC API + generated code (own pure-Go module) | [mpc-party/api](../../mpc-party/api/mpcparty/v1/mpcparty.proto) |
| Config, TLS pinning | [config.go](../../mpc-party/internal/server/config.go), [tlsconf.go](../../mpc-party/internal/server/tlsconf.go) |
| Party A: coordinator | [coord.go](../../mpc-party/internal/server/coord.go), [caller.go](../../mpc-party/internal/server/caller.go) |
| Party B: peer handler | [peer.go](../../mpc-party/internal/server/peer.go) |
| Session transport over a gRPC stream | [session.go](../../mpc-party/internal/server/session.go) |
| Operations (DKG, Refresh, Node, Derive, Sign) | [ops.go](../../mpc-party/internal/server/ops.go) |
| Key store, sealer, job store | [store.go](../../mpc-party/internal/server/store.go), [sealer.go](../../mpc-party/internal/server/sealer.go) |
| Limits | [limits.go](../../mpc-party/internal/server/limits.go) |
| Binary + dev-only authorizer | [cmd/mpc-party](../../mpc-party/cmd/mpc-party/main.go) |
| Real-process tests | [mpc-party/e2e](../../mpc-party/e2e/) |

## Threat model of each port

**Caller port** (A: full API, B: Health). Who can reach it: the gateway and admins. Threat: anyone on the network asking
A to sign, or reading metadata. Defence: TLS 1.3 only, client certificate mandatory, and the certificate must be one of
the pinned SHA-256 fingerprints (no CA: a stolen CA key cannot mint a caller). Even a valid caller does not decide
whether to sign: the `Authorizer` on A and, independently, on B does.

**Peer port** (B only). Who can reach it: party A. Threat: a host that is not A pretending to be A, or a legitimate
caller trying to drive B directly. Defence: the same TLS settings with only A's certificate pinned. A caller's certificate is
refused here (test `TestMutualTLSRefusals`). A, in turn, pins B's certificate when it dials, so a man in the middle cannot
sit between them without one of the two private keys. A has no peer port at all.

The two ports use different listeners and different pin sets on purpose: compromising a caller certificate must not
give access to the protocol channel, and the reverse.

## Why B verifies

A is the coordinator: it receives sign requests and is the only party that learns the signature. If B signed whatever A
asked, one compromised host (A) would be enough to produce any signature. So the OPEN frame carries the intent package and
the digest, and **B calls its own `Authorizer` before it joins the protocol**. In P5b-3 that implementation re-verifies
approver signatures and policy and checks that the digest matches the decoded intent. A refusal by B ends the session
before any cb-mpc message is exchanged (tested: no protocol run starts on either side).

## Session lifecycle

One protocol call = one gRPC stream = one session with a random 128-bit id chosen by A.

```
A: OPEN(op, keyset, paths, digest, job id, intent)
B: checks session id (format, never seen: replay cache), limits, keyset, authorizer  -> ACK   or   FIN{ok=false, kind}
A <-> B: DATA frames = cb-mpc messages (derive, then sign)
B: FIN{ok, result}         A compares B's public result with its own (root key, node, derived key)
A: FIN{ok, commit}         commit only if A's own checks (incl. SelfTest, local signature check) passed
B: FIN{ok}                 only for DKG/Refresh: B has stored the new shares; then A stores its own
```

Every wait has a timeout; a failure sends ABORT or a failing FIN, and the worse of the two parties' error kinds is
returned. The completion handshake exists because a side that returns early can leave the other computing (the spike hit
this). Frames whose session id is not the stream's are dropped and fail the session.

## What each limit protects

| Limit | Default | Protects |
|---|---|---|
| per-message receive timeout | 5 s | a hung or stopped peer holding a thread for ever (one OS thread per session) |
| session timeout | 30 s | a slow-drip peer, runaway sessions |
| max concurrent sessions | 2 x cores | CPU and thread exhaustion; enforced on A (outgoing) and on B (incoming), never queues |
| max frame size | 1 MiB | memory; DKG's largest message measured about 39 KB, and an oversize frame is `Cryptographic` |
| sessions per second per key | 200 | a compromised caller or A hammering one key (each ECDSA signature costs about 25 ms CPU on each party) |
| intent package size | 256 KiB | memory, log size |
| replay cache | 200 000 ids | an old OPEN frame being replayed to B |
| shutdown grace | 10 s | exit without cutting a signature in half |

All limit refusals return the typed kind `LIMIT` immediately; nothing waits in a queue.

## Idempotent signing

Ed25519 and ECDSA signatures from cb-mpc are randomized, so signing twice gives two valid but different signatures, and
a double broadcast of a withdrawal would be a double spend risk. A therefore stores the first signature under the job id
(atomic, fsynced) **before** returning it, and a retry returns the stored bytes. The digest is stored too: same job id
with another digest is refused. Concurrent calls with one job id share a single protocol run.

## DKG and Refresh: SelfTest is part of the RPC

P5b-1 found that a corrupted DKG or Refresh message can leave both parties reporting success with shares that do not
work together. So both operations end with a derive + sign over the same session, and nothing is stored unless A's check
passed and A told B. Refresh keeps the old shares until then; if the self-test fails the old keyset is still current on
both sides (tested with fault injection).

## Gotchas hit

- A released its concurrency slot as soon as it had the result, while B was still finishing: under load B refused the next
  session as over its limit. A now holds the slot until B has closed the stream.
- Job records were written under one store-wide mutex with an fsync; that serialized Ed25519 signing at about 160 sig/s.
  The write is now an exclusive hard link (atomic without a lock): about 235 sig/s.
- A `select` over a data channel and a "done" channel picks randomly when both are ready; buffered frames must be drained
  first or the last message is lost.
- The dev allow-all authorizer lives in a file with a build tag, and the config also needs a risk phrase: a production
  binary cannot enable it whatever the config says (test `TestBinaryRefusesBadStartup`).

## Quiz

1. Why are the caller port and the peer port separate listeners with different pins?
2. Why pin certificates by fingerprint instead of trusting a CA?
3. What does B do with the intent package, and when?
4. What stops an old OPEN frame from being replayed to B?
5. Two Sign calls with the same job id and different digests arrive. What happens?
6. Why must A hold its session slot until B has finished?
7. What is stored when a Refresh's SelfTest fails, and why?
8. In the commit step, who stores first, A or B, and what is the remaining risk?
9. What does the error kind `LIMIT` promise about whether anything ran?
10. Why is the allow-all authorizer both build-tagged and phrase-guarded?

<details>
<summary>Answers</summary>

1. A leaked caller certificate must not open the protocol channel to B, and a peer certificate must not be usable as a caller.
2. No CA means no CA key to steal; the exact certificates that may connect are written in the config.
3. It passes it, with the digest, key and algorithm, to its Authorizer before joining the protocol; a refusal ends the session before any cb-mpc message.
4. Session ids are random and unique; B remembers every id it accepted in a bounded cache and refuses an OPEN for a known id.
5. The first one signs and stores the result; the second is refused with `FailedPrecondition` and no protocol run. Same digest returns the stored signature.
6. B counts its session until its handler returns; if A started a new one earlier, B could refuse it as over the limit.
7. Nothing: the new shares are discarded, the old keyset stays current on both sides, so signing keeps working.
8. B stores first, then A. A crash in between leaves a mismatch; P5b-4's durable two-phase commit closes it.
9. Nothing ran: the refusal happens before any protocol message and no state changed.
10. The tag keeps it out of production binaries entirely; the phrase makes a dev run an explicit decision named in the config.

</details>
