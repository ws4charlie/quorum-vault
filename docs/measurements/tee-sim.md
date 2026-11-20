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

## The broker's rate limit (fixed in fix1)
A start needs **2 calls per keyset plus 2** (challenge + release, and the local key). The first version allowed 30 calls per minute with burst 10 per party. Projected start-up with that limit: about 24 s at 10 keysets, 3.1 min at 50, 13 min at 200. Measured: the 6th DKG in a row failed with `rate_limited`, because a DKG or refresh needs a `newkey` (2 calls) on each party.

Default now: **600 per minute, burst 100, per party** (`broker.DefaultRatePerMinute`, `DefaultRateBurst`; the limit stays per party, so one party's flood cannot use another's tokens). Measured with these defaults (party B killed and started; time until all three parties are ready):

| Keysets | Limit off | 600/min, burst 100 |
|---|---:|---:|
| 10 | 2.9 s | 3.2 s |
| 50 | 15.5 s | 16.3 s |
| 200 | 63.5 s | 97.9 s |

At 200 keysets the limit adds about 34 s (402 calls, 100 at once, the rest at 10 per second), which fits the formula. Tests: a 50-keyset start (102 calls, one every 50 ms) is not limited; a flood of 5000 calls at one instant gets at most the burst through and does not use another party's tokens (`TestDefaultLimitAllowsLargeStartsAndStopsAFlood`).

For later: a batch release (one challenge and one call for all keysets of a party at start) would cut the calls from 2N+2 to 3. It is a protocol change and is not done.
