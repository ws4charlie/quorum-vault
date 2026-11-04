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
