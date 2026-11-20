# Simulated enclave run mode (TEE-T4): the attested sealer against the PKCS#11 sealer

**SIMULATED.** Parties built with `-tags teesim`, mock attester, test CA, one SoftHSM-backed broker per party. Nothing here is a number from enclave hardware: real memory limits, vsock proxies and enclave overhead are in the real-hardware checklist (`docs/runbooks/tee-broker.md`). Local run, Apple Silicon laptop, all processes on one host over loopback, gateway + cosigners + anvil real. Reproduce: `QV_TEE_MEASURE=1 QV_CUSTODY_SIGNER=mpc [QV_CUSTODY_TEE=sim] QV_TEE_KEYSETS=10,50,200 make test-e2e-evm TEST=TestMeasureMPCSealer` (needs the lane's services).

## Party memory (RSS), one keyset, after 31 signatures
| Party | PKCS#11 | Attested (simulated) |
|---|---:|---:|
| A | 57 MiB | 91 MiB |
| B | 59 MiB | 91 MiB |
| C | 47 MiB | 72 MiB |

About 25-35 MiB more: the broker client (TLS, HTTP stack), the evidence code (COSE, X.509, ECDSA P-384) and the locked key arena. With 200 keysets party B grew from 90 to 98 MiB (attested) and from 55 to 74 MiB (PKCS#11): the keysets, not the sealer, drive growth.

## Sign latency (party A's own timing of one signature, 30 sequential withdrawals)
| | p50 | p95 | max |
|---|---:|---:|---:|
| PKCS#11 | 129 ms | 148 ms | 150 ms |
| Attested (simulated) | 122 ms | 131 ms | 148 ms |

No difference beyond noise: the data keys are in memory, so a signature asks no one. The AES key schedule is built per operation, which is not visible at this scale.

## Start-up with N keysets (party B killed and started again; time until all three parties are ready)
| Keysets | PKCS#11 | Attested, broker rate limit off |
|---|---:|---:|
| 10 | 3.2 s | 2.9 s |
| 50 | 15.3 s | 15.5 s |
| 200 | 61.1 s | 63.5 s |

Reconciliation, not the sealer, takes the time (about 0.3 s per keyset). The broker saw 12, 63 and 264 `released` records (one per keyset plus the local key and the earlier DKG/newkey records).

## The broker's rate limit: it is a problem
The broker allows 30 calls per minute and a burst of 10 per party, challenge and release together. A start needs **2 calls per keyset plus 2** (challenge + release, and the local key). Projection with the defaults (not measured as a start; limit logic from T3):

| Keysets | Calls | Start-up with 30/min, burst 10 |
|---|---:|---:|
| 10 | 22 | about 0.4 min (24 s) |
| 50 | 102 | about 3.1 min |
| 200 | 402 | about 13 min |

**Measured:** with the default limit, a DKG of the 6th keyset in a row failed: `B cannot store the new generation: ... broker refused (429): rate_limited`. A DKG or refresh needs a `newkey` (2 calls) on each party, so about 5 in a burst and then about 15 per minute; the operation fails cleanly (old state kept), it does not hang.

Proposal (not done; the broker's rule is out of this task's scope): (a) raise the per-party default to 600/min with burst 100 on a broker that serves three parties; (b) better, a batch release (one challenge and one call for all keysets of a party at start), which needs a protocol change; (c) in the meantime deploy with `rate_per_minute` raised and rely on the party's backoff. The tests of this lane run with the limit effectively off.
