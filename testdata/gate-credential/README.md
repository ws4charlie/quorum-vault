# Gate credential test vectors

TEST ONLY. `vectors.json` is the shared test data of the Gate credential contract ([spec](../../docs/gate-credential.md)). AgentGate copies it unchanged. Both sides must pass every case.

## What is in it

- `config`: the audience, skew (seconds), maximum lifetime (seconds) and the key set (`kid` and public key, base64url without padding). The keys are derived from the public strings in `seed_string`: seed = SHA-256 of those ASCII bytes. A third key (`test-only-3`) is used by one case and is not in the set.
- `now`: the fixed clock, in Unix seconds. A case may carry its own `now`.
- `cases[]`:
  - `credential`: the exact text received; `null` means none was sent.
  - `signed_bytes_hex`: the bytes the verifier computes from the parsed credential (the domain prefix, then the RFC 8785 form without `sig`). Check your encoder against it byte for byte. Absent when the credential does not parse.
  - `payment`: what the zone decoded from the payload (`valid_after` and `valid_before` only for EIP-3009).
  - `expect`: `ok`, or the error `code` and `field`.
  - `then_expect_on_reuse`: results of presenting the same credential again after the first use. Needs a used-credential store; a pure verifier skips it.

## Use

For each case: build the verifier from `config`, run it on `credential` and `payment` at `now`, compare the code and field. Codes that depend on zone state (`wallet_not_gate_governed`, `fast_lane_cap`) and on the request (`client_not_authorized`, `payload_invalid`, `request_invalid`) have no case.

## Regenerate

```bash
make gate-vectors
```

The file is generated deterministically by `internal/gatecred/gatecredtest/gen`, and a test fails if the committed file differs. Do not edit it by hand.
