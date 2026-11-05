package coldsign

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os/exec"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ---- a software stand-in for the HSM, and a config with three operators, two of whom must approve ----

type swSigner struct{ calls int }

var coldKey, _ = crypto.GenerateKey()

func (s *swSigner) SignDigest(_ context.Context, digest [32]byte) (*big.Int, *big.Int, error) {
	s.calls++
	sig, err := crypto.Sign(digest[:], coldKey)
	if err != nil {
		return nil, nil, err
	}
	return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]), nil
}

type fixture struct {
	t    *testing.T
	cfg  *Config
	keys map[string]ed25519.PrivateKey
	hot  common.Address
	sw   *swSigner
}

var tokenAddr = common.HexToAddress("0x00000000000000000000000000000000000070C3")

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, keys: map[string]ed25519.PrivateKey{}, hot: common.HexToAddress("0x0000000000000000000000000000000000000407"), sw: &swSigner{}}
	ops := map[string]string{}
	for _, n := range []string{"alice", "bob", "carol"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		f.keys[n] = priv
		ops[n] = hex.EncodeToString(pub)
	}
	f.cfg = &Config{
		Chain: "evm-test", ChainID: 31337, Pool: "omnibus", Operators: ops, Threshold: 2,
		Destinations: []string{f.hot.Hex()},
		Assets: map[string]AssetPolicy{
			"ETH":  {Decimals: 18, MaxAmount: "10000000000000000000"},
			"USDT": {Token: tokenAddr.Hex(), Decimals: 6, MaxAmount: "5000000000"},
		},
		MaxFeeWei: "5000000000000000",
		PublicKey: hex.EncodeToString(crypto.FromECDSAPub(&coldKey.PublicKey)),
		RecordDir: t.TempDir(),
	}
	if err := f.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) request(mut func(*Request)) RequestFile {
	r := Request{Version: RequestVersion, ID: "rf-1", Revision: 1, Chain: "evm-test", ChainID: 31337, Pool: "omnibus", Asset: "ETH",
		From: crypto.PubkeyToAddress(coldKey.PublicKey).Hex(), To: f.hot.Hex(), Amount: "2000000000000000000",
		Nonce: 5, Gas: 21000, MaxFeePerGas: "30000000000", MaxPriorityFeePerGas: "1000000000"}
	if mut != nil {
		mut(&r)
	}
	return r.File()
}

func (f *fixture) approvals(rf RequestFile, who ...string) []Approval {
	var out []Approval
	for _, n := range who {
		out = append(out, Approve(n, f.keys[n], rf.RequestHash))
	}
	return out
}

func (f *fixture) sign(rf RequestFile, apps []Approval) (Signed, error) {
	s, _, err := f.cfg.Sign(context.Background(), rf, apps, f.sw)
	return s, err
}

func wantRefusal(t *testing.T, what string, err error, contains string) {
	t.Helper()
	if _, ok := err.(*Refusal); !ok || !strings.Contains(err.Error(), contains) {
		t.Errorf("%s: err = %v, want a refusal containing %q", what, err, contains)
	}
}

func TestCeremonySignsWithTwoOfThree(t *testing.T) {
	f := newFixture(t)
	rf := f.request(nil)
	s, err := f.sign(rf, f.approvals(rf, "alice", "carol"))
	if err != nil {
		t.Fatal(err)
	}
	r := rf.Request
	if _, err := VerifySignedMatches(r, rf.RequestHash, s); err != nil {
		t.Fatalf("the signed file does not match its own request: %v", err)
	}
	// Token refill: the transaction is a transfer(hot, amount) on the configured token.
	tf := f.request(func(r *Request) {
		r.ID, r.Nonce, r.Asset, r.Token, r.Amount, r.Gas = "rf-2", 6, "USDT", tokenAddr.Hex(), "1000000", 70000
	})
	ts, err := f.sign(tf, f.approvals(tf, "bob", "carol"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := VerifySignedMatches(tf.Request, tf.RequestHash, ts)
	if err != nil || *tx.To() != tokenAddr || !strings.HasPrefix(common.Bytes2Hex(tx.Data()), transferSigHex) {
		t.Fatalf("token transaction: %v %+v", err, tx)
	}
}

// Each refusal below is a thing the online side (or a person) might try; the offline tool must say no, and say why.
func TestOfflineToolRefuses(t *testing.T) {
	f := newFixture(t)
	n := uint64(100)
	fresh := func(mut func(*Request)) RequestFile { // a different nonce each time, so refusals are about the thing being tested
		n++
		return f.request(func(r *Request) {
			r.Nonce = n
			if mut != nil {
				mut(r)
			}
		})
	}
	rf := fresh(nil)
	_, err := f.sign(rf, f.approvals(rf, "alice"))
	wantRefusal(t, "one approval of two", err, "1 valid approval(s) from distinct configured operators, 2 required")

	rf = fresh(nil)
	_, err = f.sign(rf, append(f.approvals(rf, "alice"), f.approvals(rf, "alice")...))
	wantRefusal(t, "same operator twice", err, "alice: counted once already")

	rf = fresh(nil)
	mallory := Approve("mallory", ed25519.NewKeyFromSeed(make([]byte, 32)), rf.RequestHash)
	_, err = f.sign(rf, append(f.approvals(rf, "alice"), mallory))
	wantRefusal(t, "unknown operator", err, `"mallory": not a configured operator`)

	rf = fresh(nil)
	forged := Approve("bob", f.keys["alice"], rf.RequestHash) // alice's key under bob's name
	_, err = f.sign(rf, append(f.approvals(rf, "alice"), forged))
	wantRefusal(t, "forged approval", err, "bob: signature does not verify")

	rf = fresh(nil)
	other := f.request(func(r *Request) { r.Nonce = 999 })
	_, err = f.sign(rf, append(f.approvals(rf, "alice"), f.approvals(other, "bob")...))
	wantRefusal(t, "approval of another request", err, "bob: signed another request")

	evil := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	rf = fresh(func(r *Request) { r.To = evil.Hex() })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "destination not pinned", err, "is not one of the pinned hot addresses")

	rf = fresh(func(r *Request) { r.Amount = "10000000000000000001" })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "amount above the cap", err, "above the per-ceremony cap 10")

	rf = fresh(func(r *Request) { r.ChainID = 1 })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "wrong chain id", err, "request is for chain")

	rf = fresh(func(r *Request) { r.Pool = "segregated" })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "wrong pool", err, "this signer holds pool")

	rf = fresh(func(r *Request) { r.From = f.hot.Hex() })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "not from the cold address", err, "this signer's cold address is")

	rf = fresh(func(r *Request) { r.MaxFeePerGas = "900000000000" }) // 21000 x 900 gwei = 1.9e16 > 5e15
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "fee above the cap", err, "above the cap")

	rf = fresh(func(r *Request) { r.Asset, r.Token, r.Gas = "USDT", evil.Hex(), 70000 })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "token contract is not the configured one", err, "is token")

	rf = fresh(func(r *Request) { r.Asset = "DOGE" })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "unknown asset", err, "is not configured")

	// A tampered request file: the amount was changed after the hash was made.
	rf = fresh(nil)
	rf.Request.Amount = "9000000000000000000"
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "tampered request file", err, "damaged or was changed")

	if f.sw.calls != 0 {
		t.Fatalf("the HSM was asked to sign %d times for refused requests", f.sw.calls)
	}
}

func TestSameNonceDifferentContentIsRefusedAfterARestart(t *testing.T) {
	f := newFixture(t)
	a := f.request(nil)
	if _, err := f.sign(a, f.approvals(a, "alice", "bob")); err != nil {
		t.Fatal(err)
	}
	// Same nonce, other amount: refused, from the durable record (a new Config over the same directory = a restart).
	b := f.request(func(r *Request) { r.ID, r.Amount = "rf-other", "3000000000000000000" })
	restarted := *f.cfg
	_, _, err := restarted.Sign(context.Background(), b, f.approvals(b, "alice", "bob"), f.sw)
	wantRefusal(t, "same nonce, different amount", err, "was already signed for different content")
	// Same nonce, other token.
	c := f.request(func(r *Request) { r.Asset, r.Token, r.Amount, r.Gas = "USDT", tokenAddr.Hex(), "1000000", 70000 })
	_, _, err = restarted.Sign(context.Background(), c, f.approvals(c, "alice", "bob"), f.sw)
	wantRefusal(t, "same nonce, different asset", err, "was already signed for different content")

	// The same request again returns the first signed file: no second signature.
	calls := f.sw.calls
	again, _, err := restarted.Sign(context.Background(), a, f.approvals(a, "alice", "carol"), f.sw)
	if err != nil || f.sw.calls != calls {
		t.Fatalf("same request again: %v, HSM calls %d -> %d", err, calls, f.sw.calls)
	}
	first, _ := f.sign(a, f.approvals(a, "alice", "bob"))
	if again.TxHash != first.TxHash {
		t.Fatal("a repeat of the same request produced another transaction")
	}

	// Higher fees on the same payment at the same nonce (a re-export) are the same content: allowed.
	re := f.request(func(r *Request) { r.Revision, r.MaxFeePerGas = 2, "40000000000" })
	if _, err := f.sign(re, f.approvals(re, "bob", "carol")); err != nil {
		t.Fatalf("re-export with higher fees refused: %v", err)
	}
}

// What the online side runs on a file that comes back.
func TestImportChecks(t *testing.T) {
	f := newFixture(t)
	rf := f.request(nil)
	s, err := f.sign(rf, f.approvals(rf, "alice", "bob"))
	if err != nil {
		t.Fatal(err)
	}
	r, h := rf.Request, rf.RequestHash

	// A file for another request (different hash, e.g. an older revision).
	re := f.request(func(r *Request) { r.Revision = 2; r.MaxFeePerGas = "40000000000" })
	if _, err := VerifySignedMatches(re.Request, re.RequestHash, s); err == nil || !strings.Contains(err.Error(), "re-exported, or this is another request") {
		t.Errorf("stale file: %v", err)
	}
	// A tampered file: another destination inside the raw transaction, same hash claimed.
	evilReq := r
	evilReq.To = "0x000000000000000000000000000000000000dEaD"
	evil, _ := evilReq.Tx()
	evilKey, _ := crypto.GenerateKey()
	er, es := rsOf(evil, evilKey)
	signedEvil, _ := assemble(evil, signerFor(evil), signerFor(evil).Hash(evil), er, es, crypto.PubkeyToAddress(evilKey.PublicKey))
	raw, _ := signedEvil.MarshalBinary()
	tam := s
	tam.RawTx, tam.TxHash = hex.EncodeToString(raw), signedEvil.Hash().Hex()
	if _, err := VerifySignedMatches(r, h, tam); err == nil || !strings.Contains(err.Error(), "not the one the request describes") {
		t.Errorf("tampered destination: %v", err)
	}
	// Signed by someone else.
	other, _ := crypto.GenerateKey()
	tx, _ := r.Tx()
	otherSigned, _ := types_sign(tx, other)
	raw2, _ := otherSigned.MarshalBinary()
	imp := s
	imp.RawTx, imp.TxHash = hex.EncodeToString(raw2), otherSigned.Hash().Hex()
	if _, err := VerifySignedMatches(r, h, imp); err == nil || !strings.Contains(err.Error(), "not by the cold address") {
		t.Errorf("wrong signer: %v", err)
	}
	// tx_hash that does not belong to the raw transaction.
	bad := s
	bad.TxHash = fmt.Sprintf("0x%064x", 7)
	if _, err := VerifySignedMatches(r, h, bad); err == nil || !strings.Contains(err.Error(), "tx_hash does not match") {
		t.Errorf("bad hash: %v", err)
	}
}

// The offline tool must not be able to reach a network: it contains no network client at all.
func TestOfflineToolHasNoNetworkClient(t *testing.T) {
	forbidden := []string{"net", "net/http", "net/rpc", "google.golang.org/grpc", "github.com/ethereum/go-ethereum/ethclient", "github.com/ethereum/go-ethereum/rpc",
		"github.com/jackc/pgx/v5", "go.temporal.io/sdk/client", "github.com/twmb/franz-go/pkg/kgo"}
	for _, pkg := range []string{"github.com/ws4charlie/quorum-vault/cmd/qv-cold", "github.com/ws4charlie/quorum-vault/internal/coldsign"} {
		out, err := exec.Command("go", "list", "-deps", pkg).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", pkg, err)
		}
		have := map[string]bool{}
		for _, l := range strings.Fields(string(out)) {
			have[l] = true
		}
		for _, bad := range forbidden {
			if have[bad] {
				t.Errorf("%s imports %s: the offline signer must have no network client", pkg, bad)
			}
		}
	}
}
