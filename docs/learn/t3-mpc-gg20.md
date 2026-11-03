# T3 — 2-of-3 threshold ECDSA (GG20) with HSM-sealed shares

## What was built

`internal/mpc` runs three signing parties in one process. Together they hold
one secp256k1 key that **no single place ever holds**: each party has a share,
and any 2 of the 3 can produce an ordinary ECDSA signature that verifies against
the joint public key (and recovers to an Ethereum address). All 3 can also sign
together (the "full quorum" used for cold wallets).

| Piece | Where |
|---|---|
| Cluster, config, party IDs, session nonce | [mpc.go](../../internal/mpc/mpc.go) |
| In-memory transport (the router) | [transport.go:28](../../internal/mpc/transport.go:28) |
| Pre-params cache + DKG keygen | [keygen.go:36](../../internal/mpc/keygen.go:36), [keygen.go:123](../../internal/mpc/keygen.go:123) |
| Signing ceremony | [sign.go:28](../../internal/mpc/sign.go:28), [sign.go:89](../../internal/mpc/sign.go:89) |
| `domain.KeyGenerator` / `signer.Signer` adapters | [signer.go](../../internal/mpc/signer.go) |
| AES-GCM sealing inside the token | [seal/seal.go](../../internal/mpc/seal/seal.go) |
| Benchmark | [cmd/mpcbench](../../cmd/mpcbench/main.go), results in [docs/measurements/mpc.md](../measurements/mpc.md) |

The library is `github.com/bnb-chain/tss-lib/v4`. Its "GG20" is Gennaro &
Goldfeder's threshold ECDSA (the 2018 paper's protocol plus the 2020
identifiable-abort and consistency checks).

## The transport (tss-lib gives you none)

Each tss-lib party is a state machine. You call `Start()`, it pushes outgoing
messages to an `outCh`, and you feed incoming wire bytes to
`UpdateFromBytes(bytes, from, isBroadcast)`. Moving the bytes is the caller's
job. `route` ([transport.go:28](../../internal/mpc/transport.go:28)) reads
`outCh`; if `msg.GetTo()` is nil the message is a broadcast and goes to every
other party, else to the listed parties. Each delivery runs in its own
goroutine (parties lock internally). The router counts deliveries, bytes and
the highest round number seen, and stops on the first error or on `ctx`.

Replacing this with TCP/gRPC would not change the protocol at all: only
`route` would change. That is why multi-process transport was a stretch goal.

## Keygen (dealerless DKG), 3 message rounds

Party keys are the integers 1, 2, 3 — they are the Shamir x-coordinates.
`threshold = 1` in tss-lib means a polynomial of degree 1, so **t+1 = 2**
parties are needed to sign.

1. **Round 1 (broadcast).** Each party picks a random secret `u_i` and a random
   degree-1 polynomial with `u_i` as constant term; it broadcasts a hash
   *commitment* to the polynomial's public coefficients, plus its Paillier public
   key and ring-Pedersen parameters (`NTilde, h1, h2`) with proofs that they
   are well formed.
2. **Round 2 (P2P + broadcast).** Each party sends party j its share
   `f_i(j)` privately (P2P, with a proof about its Paillier modulus), and
   broadcasts the *decommitment* (the coefficients as curve points, Feldman VSS).
3. **Round 3 (broadcast).** Each party checks every share it got against the
   broadcast coefficients, sums them into its final share `x_i = Σ f_j(i)`, and
   broadcasts a Paillier proof. Everyone can compute the public key
   `y = Σ u_i·G` and every party's public share `X_j = x_j·G`.

The private key `Σ u_i` is never computed by anyone. The code asserts that all
three parties derived the same `y` ([keygen.go:184](../../internal/mpc/keygen.go:184)).

## Signing, 9 message rounds

With 2 signers each party has `w_i` = its share times a Lagrange coefficient,
so `w_1 + w_2 = x` (the private key). ECDSA needs `s = k⁻¹(m + r·x)` with a
random `k` that also nobody knows. Roughly:

1. Each signer picks `k_i` and `γ_i`, broadcasts a commitment to `Γ_i = γ_i·G`,
   and sends each peer `Enc_Paillier(k_i)` with a range proof (P2P).
2. **MtA** (multiplicative-to-additive): each pair turns `k_i·γ_j` and `k_i·w_j`
   into additive shares using Paillier homomorphism, with ZK proofs (P2P).
3. Each broadcasts `δ_i` (its share of `k·γ`) and a commitment `T_i` to its share
   of `k·x` (GG20 addition).
4. Everyone sums `δ = kγ`, and decommits `Γ_i` with a Schnorr proof.
5. `R = δ⁻¹·ΣΓ_i = k⁻¹·G`, `r = R.x`. Each broadcasts `k_i·R` with a proof;
   the sum must equal `G` (GG20 consistency check).
6. Each broadcasts `σ_i·R` with proofs; the sum must equal the public key.
7–9. Each computes `s_i = m·k_i + r·σ_i`, commits, decommits, and finally
   reveals `s_i`; `s = Σ s_i`.

Rounds 3–9 are cheap; rounds 1–2 (Paillier) dominate. With 3 signers every
broadcast reaches two peers and there are three MtA pairs per direction, which
is why the full quorum sends 3× the messages (60 vs 20).

After the ceremony the code normalises `s` to low-S (Ethereum rejects high-S,
EIP-2) and verifies the signature before returning ([sign.go:135](../../internal/mpc/sign.go:135)).

## Why pre-params, and why they are slow

Each party needs a Paillier key (product of two 1024-bit primes) and
ring-Pedersen parameters `NTilde = P·Q` from two **safe primes** (`p = 2p'+1`
with `p'` prime). Safe primes are rare, so finding them takes seconds to
minutes. They do not depend on the key being generated, so they are made once
per party, cached in `<DataDir>/preparams/party-<id>.json`, and reused
([keygen.go:36](../../internal/mpc/keygen.go:36)). The three parties generate
in parallel. The cache holds the Paillier *private* key, so it is sealed like a
share (AAD `preparams|party-<id>`).

## The session nonce

tss-lib v2+ refuses to run round 1 without `Parameters.SetSessionNonce`. The
nonce is hashed into the session ID that every ZK proof binds to, so a proof
from one ceremony cannot be replayed into another. Rules: same value for every
party in a run, fresh per run, and secret. The code makes 256 random bits per
ceremony ([mpc.go:186](../../internal/mpc/mpc.go:186)) and sets it on every
party's parameters before `Start()`.

## Sealing: what it protects and what it does not

After keygen each party's save data (JSON: `Xi`, `ShareID`, its Paillier key,
everyone's public parameters) is encrypted inside **that party's** token:

- Key: AES-256 object `qv-share-wrap`, `CKA_TOKEN`, `CKA_SENSITIVE`,
  `!CKA_EXTRACTABLE` — created once with `CKM_AES_KEY_GEN`
  ([seal.go:54](../../internal/mpc/seal/seal.go:54)). Reading `CKA_VALUE`
  returns `CKR_ATTRIBUTE_SENSITIVE`.
- `CKM_AES_GCM`, random 12-byte IV, 128-bit tag, AAD = `<keyRef>|party-<id>`.
  File `keys/<keyRef>/party-<id>.sealed`, JSON `{"v":1,"iv":…,"ct":…}`, mode 0600.
- Keygen writes all three files into a temp dir, then renames it: either all
  shares exist or none ([keygen.go:220](../../internal/mpc/keygen.go:220)).

Protects against: a stolen disk or backup (useless without the tokens); a file
copied to another party (other token → GCM fails); a file moved to another key
or party slot (AAD mismatch → GCM fails); bit flips (tag fails).

Does **not** protect: the plaintext share while a ceremony runs — it is in this
process's memory, and all three parties share one process, so one memory dump
leaks all shares. Nor does it stop someone who can log in to two tokens (the
PIN is a dev default). Real separation needs separate machines/operators.

## Mapping to real institutional MPC

| Here | Production custody (Fireblocks, Copper, Coinbase-style) |
|---|---|
| 3 parties, one process | 3+ parties on separate hosts / clouds / an end-user device, mutually authenticated channels |
| In-memory router | Message relay (gRPC / queue) that sees only ciphertext-protected protocol messages |
| SoftHSM AES key seals each share | Share in an HSM, SGX/Nitro enclave, or sealed by a KMS key bound to that host's identity |
| Any 2 of 3 sign | Policy decides the quorum; cold storage may need an offline party |
| One keygen per wallet | Often one master key + BIP-32 style derivation (tss-lib supports a key derivation delta) |
| No resharing | Periodic **key refresh / resharing** (tss-lib `ecdsa/resharing`) to rotate shares without changing the address |
| GG20 | Many vendors moved to CGGMP21 / DKLs (fewer rounds, UC-secure, identifiable abort) |

## Gotchas hit

- `tss.SortPartyIDs` writes `Index` into the `*PartyID` objects. Sharing them
  between concurrent ceremonies would race, so each ceremony makes fresh IDs
  ([mpc.go:83](../../internal/mpc/mpc.go:83)).
- `tss.NewParameters` *panics* on bad inputs (e.g. one party). The code turns
  panics into errors ([mpc.go:196](../../internal/mpc/mpc.go:196)).
- Pass `fullBytesLen = 32` to `signing.NewLocalParty`, or a digest with leading
  zero bytes is signed as a shorter number (the full-quorum test uses one).
- tss-lib logs every round at INFO; set `QV_TSS_LOG=info` to see it.

## Quiz

1. In tss-lib, what `threshold` value gives a 2-of-3 scheme, and why?
2. Who knows the full private key after keygen?
3. What does the router do with a message whose `GetTo()` is nil?
4. Why are pre-params cached, and why are they sealed?
5. What happens if two parties use different session nonces?
6. Why must the nonce be fresh for every ceremony?
7. Which signing rounds use Paillier encryption, and what is MtA for?
8. Party-1's sealed file is copied into party-2's directory. Why can't party-2's token open it?
9. Why does the AAD include the keyRef?
10. Name one attack that sealing does not stop in this design.
11. Why is `s` normalised to low-S?
12. Why does the full 3-party quorum send 3× the messages of a 2-party one?

<details><summary>Answers</summary>

1. `threshold = 1`: tss-lib's t is the polynomial degree; t+1 = 2 shares reconstruct it.
2. Nobody. Each party only knows its share `x_i`; the key `Σ u_i` is never computed.
3. Treats it as a broadcast and delivers it to every party except the sender.
4. Generating safe primes takes seconds to minutes and does not depend on the key, so they are reused; they contain the Paillier private key, which is secret.
5. Their session IDs differ, so proofs fail verification and the ceremony aborts.
6. Proofs bind to the session ID; a reused nonce lets an old transcript's proofs be replayed into a new run.
7. Rounds 1–2. MtA turns a product of two secrets held by different parties (`k_i·γ_j`, `k_i·w_j`) into an additive sharing without revealing either.
8. It was encrypted under party-1's AES key, which exists only in party-1's token; party-2's key differs, so GCM authentication fails (`CKR_ENCRYPTED_DATA_INVALID`).
9. So a valid sealed share cannot be swapped into another key's directory (or another party slot) and be accepted.
10. Reading shares from process memory during a ceremony (all parties share one process); or anyone with two token PINs.
11. Ethereum (EIP-2) rejects signatures with `s > N/2`; `(r, N−s)` is equally valid.
12. Each broadcast goes to 2 peers instead of 1 and there are 3 P2P pairs instead of 1 (each direction), so deliveries go from 20 to 60.

</details>
