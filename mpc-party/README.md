# mpc-party — cb-mpc wrapper (P5b-1)

A tested Go wrapper over [Coinbase cb-mpc](https://github.com/coinbase/cb-mpc) for the hot-wallet signer: 2-party ECDSA
(secp256k1), Ed25519 and BIP340 Schnorr, HD keysets, backup. No network service yet (P5b-2).

**Separate Go module on purpose.** cb-mpc vendors its own libsecp256k1, which collides with go-ethereum's cgo copy at
link time, and the repository root must keep building with no C++ toolchain. Nothing in this module imports
go-ethereum (`TestModuleDoesNotDependOnGoEthereum` enforces it) and nothing in the root module imports this one.

Pinned: **cb-mpc v0.2.2 = `2f2c4f1005729bd575b6f17bce8a47478df7ce78`**, in [cbmpc.pin](cbmpc.pin) (single source of
truth; [pin.go](internal/cbmpc/pin.go) mirrors it and `TestPinMatchesBuild` fails if they or the built library differ).
Why this version and what was reviewed: [docs/spikes/p5a-cbmpc.md](../docs/spikes/p5a-cbmpc.md) and the P5b-1 report.

## Build and test

Needs git, cmake >= 3.20, ninja or make, a C++17 compiler (clang 20 recommended; AppleClang 21 works), curl, perl, Go.
No sudo, nothing installed system-wide; everything lands in the gitignored `.deps/`.

```bash
cd mpc-party
scripts/fetch-build-cbmpc.sh          # clone at the pinned commit, verify the hash, build static OpenSSL 3.6.4 + libcbmpc.a
go vet ./... && go test -race -count=1 ./...
```

The script refuses to build if the source commit differs from `cbmpc.pin`, and skips work when `.deps/BUILD_STAMP`
already matches (commit + script hash). No cmake? `python3 -m venv v && v/bin/pip install cmake ninja && PATH=$PWD/v/bin:$PATH ...`.

Linux: `scripts/install-toolchain-linux.sh` installs clang-20 from apt.llvm.org (key fingerprint checked) and cmake;
`scripts/ci.sh` is the exact list of commands of the CI job `mpc-party` (`.github/workflows/ci.yml`), cache keyed on
`cbmpc.pin` + `fetch-build-cbmpc.sh`.

Fuzz (CI runs 30 s, the task acceptance run was 60 s):

```bash
go test -run '^$' -fuzz FuzzEntryPoints -fuzztime 60s ./internal/cbmpc
```

## API at a glance (`internal/cbmpc`)

| Area | Calls |
|---|---|
| HD keyset (ECDSA, Ed25519) | `DKG`, `(*Keyset).Refresh`, `.Derive`, `.NodeExport` (public key + chain code), `.RootPublicKey`, `.SelfTest`, `LoadKeyset` |
| Signing | `(*SignKey).Sign` (ECDSA 2PC DER low-S, Ed25519 2PC), `DKGBIP340` + `Sign` + `XOnlyPublicKey` + `Refresh` (non-HD) |
| Backup | `(*Keyset).Split`, `NewKeysetSplit`, `Join`, `GeneratePVEKeys`, `(*KeysetSplit).PVEExport`, `PVEVerify`, `PVERestore`, `BackupLabel` |
| Transport | `Transport` interface (`Send/Recv(ctx, ...)`), `NewMemPair`, `ConnTransport`, `ReadFrame/WriteFrame`; options `WithRecvTimeout`, `WithMaxFrame` |
| Errors | `*Error{Kind, Op, Code}`; `IsTransport`, `IsCryptographic`, `IsInternal` |
| Secrets | `Secret` (C memory, mlock, `Wipe`), `WipeBytes` |

P1 is the coordinator and the only party that receives a signature. P2 gets `(nil, nil)` from `Sign`.

### Error classes (what P5b-3 should do)

| Kind | Meaning | Action |
|---|---|---|
| `Transport` | link failed, peer gone, timeout, context cancelled, peer aborted | retry with a fresh session and backoff; no key action |
| `Cryptographic` | a check on the peer's data failed: proof, parse error, oversized frame, final signature check, or a C++ assertion raised while processing peer messages | at most one automatic retry; **freeze the keyset**, page a human |
| `Internal` | invalid argument, use of a wiped secret, unsupported/mismatching blob layout, out of memory, C++ exception outside a protocol call | do not retry blindly; alert |

Honest note: cb-mpc raises `cb_assert` (a C++ exception) on some malformed peer messages. The malicious-peer test hit
it. Inside a protocol call it is therefore classified `Cryptographic` (fail closed); outside one, `Internal`.

### Thread and goroutine safety

All functions and methods are safe for concurrent use, on the same or different keys, each protocol call with its own
`Transport`. `Keyset`/`SignKey` are immutable; `Refresh` returns a new value. Each running protocol call blocks one OS
thread inside cgo. `Wipe` waits for in-flight calls that use that secret. Tested with `-race` at concurrency 32.

Every blocking call returns promptly on context cancel or transport failure: the library stops waiting even when a
`Transport` ignores its context (that costs one parked goroutine until the transport call returns, so honour ctx).

### Secrets: what is wiped and what cannot be

Keyset and key blobs are produced by C++ and handed to Go as a `Secret` that owns the malloc'ed buffer (mlock attempted,
`OPENSSL_cleanse` on `Wipe`, finalizer as a safety net). They enter C++ by pointer, not by copy. Cannot be wiped by this
module: copies you take with `Secret.Bytes()` (use `WipeBytes`), the sealing envelope you build from them, swap and core
dumps (the process must set `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`: P5b-2), the C++ stack and registers of a finished call
(cb-mpc zeroizes its own buffers, not the stack), `std::vector` temporaries inside cb-mpc, and peer messages (they are
not secret). Public data (public keys, chain codes, signatures, PVE ciphertexts) is returned as ordinary `[]byte`.

## Things you must know before using it

1. **Refresh can "succeed" on both sides and still produce shares that do not work together** when a message was corrupted
   (found by the malicious-peer test; ECDSA and Ed25519). Root public key is unchanged and `Derive` works, `Sign` fails.
   Run `Keyset.SelfTest` on the new shares after every `DKG` and `Refresh`, and drop the old shares only after P1's
   self-test passed and P1 told P2. P2's `nil` error from `Sign` or `SelfTest` proves nothing.
2. **Old and new shares do not mix.** Mixed `Sign`: P1 gets `Cryptographic`, no signature; P2 may return success.
   Mixed `Derive`: one side `Cryptographic`, the other sees the closed link.
3. **Backups are per refresh version.** A PVE ciphertext and the stripped blob must come from the same keyset version.
   After a refresh, P1's exact share can exceed q: PVE carries `x mod q`, the exact value is recovered from the Paillier
   ciphertext inside P1's stripped blob (`SECURE_USAGE.md` "ECDSA-2P P1 backup limitations"). **P1's stripped blob holds
   the Paillier private key**: encrypt it like the full keyset.
4. Ed25519 signatures are randomized: store the first one, rebroadcast it, never re-sign.
5. Only the public cb-mpc `sign()` is used (full proof mode). The internal global-abort variant is not reachable.
6. `NodeExport`, the keyset split/join and `qv_hd_info` use cb-mpc internals. Golden tests pin them.

## Upgrade procedure (changing `cbmpc.pin`)

1. Read the upstream diff between the old and new commit: everything under `src/cbmpc/protocol/ecdsa_2p.cpp`,
   `hd_keyset_*`, `hd_tree_bip32.cpp`, `schnorr_2p.cpp`, `eddsa*`, `src/cbmpc/zk/**`, `src/cbmpc/crypto/base_paillier.cpp`,
   `src/cbmpc/api/**`, plus `SECURE_USAGE.md`, security advisories (GHSA) and release notes. Write down why you move.
2. Edit `cbmpc.pin` (tag **and** commit) and `internal/cbmpc/pin.go`. Run `scripts/fetch-build-cbmpc.sh`.
3. Run the tests. **Expected failures if the internal layout changed**, each with a message that names the upstream file:
   - `TestGolden/*`: blob layout (`keyset_blob_v1_t` in `src/cbmpc/api/hd_keyset_ecdsa_2p.cpp` / `hd_keyset_eddsa_2p.cpp`),
     the VRF/chain-code step (`derive_keys` in `src/cbmpc/protocol/hd_keyset_*_2p.cpp`), the non-hardened rule
     (`hd_tree_bip32.cpp`);
   - `TestBIP32VectorECDSA`, `TestBIP32StyleVectorEd25519`: node export diverged from `Derive`;
   - `TestBackupRestoreBothParties`: split/join no longer matches the blob;
   - compile errors in `shim.cpp`: internal headers moved.
4. Fix `shim.cpp` to mirror the new internals. Only after that regenerate the fixtures
   (`go test ./internal/cbmpc -run TestGoldenUpdate -update-golden`) and review the diff of `testdata/golden.json`:
   the node public key and chain code for the fixture shares must not change unless the derivation itself changed on
   purpose. A changed derivation moves every deposit address: stop and ask.
5. Run the full suite with `-race`, the 60 s fuzz, and the two-process tests. Update the docs and CI will rebuild (cache key
   changes with the pin).

`internal/cbmpc/testdata/golden.json` holds TEST-ONLY shares from throwaway keys; they protect nothing.

---

# The service (P5b-2)

Layout: `api/` generated gRPC code (own module, pure Go; `api/generate.sh` lists the generator versions),
`internal/server` the service, `cmd/mpc-party` the binary, `e2e/` real-process tests, `internal/testenv` throwaway
certificates and configs for tests.

| Port | Who connects | Auth | Serves |
|---|---|---|---|
| A `caller_listen` | gateway / admin tooling | mTLS 1.3, caller certificates pinned by SHA-256 fingerprint | `DKG`, `Node`, `Derive`, `Sign`, `Refresh`, `Health` |
| B `caller_listen` | monitoring | same | `Health` only (everything else is `Unimplemented`) |
| B `peer_listen` | party A only | mTLS 1.3, A's certificate pinned | `Peer.Session` (one stream per protocol session) |

A has no peer listener: it dials B. Caller and peer ports are different listeners with different pin sets; a legitimate
caller certificate is refused on the peer port (tested).

## Run two parties locally

Needs the cb-mpc build (`scripts/fetch-build-cbmpc.sh`) and a dev build of the binary, which is the only build that
contains the allow-all authorizer:

```bash
cd mpc-party
go build -tags devauth -o /tmp/mpc-party-dev ./cmd/mpc-party     # dev build: has "dev-allow-all"
go build -o /tmp/mpc-party ./cmd/mpc-party                       # production build: only "deny-all" until P5b-3
```

Make certificates (any tool; the tests generate P-256 self-signed ones) for party A, party B and one caller, and compute
pins: `openssl x509 -in a.crt -outform DER | sha256sum`. Write a 32-byte hex key to `seal.key` (test sealer only).
`b.json`:

```json
{
  "role": "B", "caller_listen": "127.0.0.1:7002", "peer_listen": "127.0.0.1:7003",
  "cert_file": "b.crt", "key_file": "b.key",
  "peer_pins": ["<sha256 of a.crt>"], "caller_pins": ["<sha256 of caller.crt>"],
  "data_dir": "data-b",
  "sealer": {"type": "insecure-static-key-for-tests", "key_file": "seal.key"},
  "authorizer": {"type": "dev-allow-all", "accept_risk": "I UNDERSTAND THIS PARTY SIGNS ANYTHING WITHOUT POLICY CHECKS"}
}
```

`a.json` is the same with `"role": "A"`, `"caller_listen": "127.0.0.1:7001"`, no `peer_listen`,
`"peer_address": "127.0.0.1:7003"`, `peer_pins` = pin of `b.crt`. Start B, then A, each with `-config`:

```bash
/tmp/mpc-party-dev -config b.json &  /tmp/mpc-party-dev -config a.json &
```

Optional `limits`: `recv_timeout_ms` (5000), `session_timeout_ms` (30000), `max_peer_sessions` (2 x cores),
`max_frame_bytes` (1 MiB; the largest DKG message measured is about 39 KB), `sessions_per_sec_key` (200),
`max_intent_bytes` (256 KiB), `shutdown_grace_ms` (10000), `replay_cache_size` (200000). The process refuses to start on a
missing or invalid file, on an unknown field, or with no usable authorizer. Logs are JSON on stderr (op, job id, key id,
duration, outcome, kind); no secrets.

## Behaviour worth knowing

- **Errors** are gRPC statuses with an `ErrorDetail{kind}`: `TRANSPORT` (retry, no key action), `CRYPTOGRAPHIC` (freeze the
  keyset), `INTERNAL`, `REFUSED` (an authorizer said no, nothing ran), `LIMIT` (nothing ran). `server.KindOfStatus(err)`.
- **Sign**: A authorizes, then opens a session; B authorizes on its side from the intent package in the OPEN frame
  before it joins; both derive the key inside the session, A verifies the signature with btcec / `crypto/ed25519` and
  stores it durably before returning it. `job_id` is the idempotency key: same job and digest returns the stored
  signature (`replayed=true`), a different digest is `FailedPrecondition`.
- **DKG and Refresh** always run `SelfTest` on both sides. New shares are stored only after A's self-test passed and A told B;
  B stores first, then A. A crash between the two stores leaves a mismatch that P5b-4's durable two-phase commit
  closes; until then re-run the operation (the old shares are still in the data dir only until the replacement is written).
- **Authorizer**: `server.Authorizer` is called on B (before joining) and on A. The default build has only `deny-all`;
  `dev-allow-all` exists only with `-tags devauth` and the risk phrase in the config. The production implementation is P5b-3.
- Sealing uses the clearly named test sealer (`insecure-static-key-for-tests`). P5b-4 adds the HSM sealer.
- Hardening at start: `RLIMIT_CORE=0` everywhere; on Linux also `PR_SET_DUMPABLE=0` and `mlockall` (result logged).
- SIGTERM/SIGINT: stop accepting, wait for sessions up to `shutdown_grace_ms`, wipe keysets from memory.
