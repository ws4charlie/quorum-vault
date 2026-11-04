# spike/cbmpc — P5a throwaway prototype

Not product code. Findings and recommendation: `docs/spikes/p5a-cbmpc.md`.

```bash
spike/cbmpc/scripts/demo.sh        # build everything, run DKG -> HD derive -> MPC sign -> mined on anvil
spike/cbmpc/scripts/verify-all.sh  # BIP32 xpub match, Ed25519, BIP340, refresh, backup recovery, crash tests
spike/cbmpc/scripts/bench.sh       # latency/throughput, loopback and 20 ms RTT
```
Needs git, cmake, a C++17 compiler (clang 20+ preferred), Go, docker. cb-mpc v0.2.2 (pinned commit) is fetched into the
gitignored `.deps/`; nothing is installed system-wide and nothing is vendored. Own Go module (`go.mod` here); the repo root is untouched.
`cmd/party` links C++ (cgo); `cmd/ethdemo` links go-ethereum; they cannot share a binary (duplicate secp256k1 symbols).
