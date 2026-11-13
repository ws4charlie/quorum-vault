package coldsign

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol/solmsg"
)

type edSigner struct{ k ed25519.PrivateKey }

func (s edSigner) SignMessage(_ context.Context, m []byte) ([]byte, error) {
	return ed25519.Sign(s.k, m), nil
}

type solEnv struct {
	cfg    *SOLConfig
	cold   string
	hot    string
	mint   string
	signer edSigner
	ops    map[string]ed25519.PrivateKey
}

func randAddr() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base58.Encode(b)
}

func newSOLEnv(t *testing.T) *solEnv {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e := &solEnv{cold: base58.Encode(pub), hot: randAddr(), mint: randAddr(), signer: edSigner{priv}, ops: map[string]ed25519.PrivateKey{}}
	opsPub := map[string]string{}
	for _, n := range []string{"alice", "bob", "carol"} {
		p, k, _ := ed25519.GenerateKey(rand.Reader)
		e.ops[n] = k
		opsPub[n] = hex.EncodeToString(p)
	}
	e.cfg = &SOLConfig{Family: "sol", Chain: "solana-localnet", Pool: "p1", Operators: opsPub, Threshold: 2, Destinations: []string{e.hot},
		Assets:    map[string]SOLAssetPolicy{"SOL": {Decimals: 9, MaxAmount: "10000000000"}, "TKN": {Mint: e.mint, Decimals: 6, MaxAmount: "5000000000"}},
		NoncePool: 4, MaxComputeUnits: 200_000, MaxMicroLamports: 1_000_000, MaxPriorityLamports: 50_000, PublicKey: hex.EncodeToString(pub),
		HSM: HSMConfig{}, RecordDir: t.TempDir()}
	if err := e.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *solEnv) req(asset string, amount string, nonceIdx int, price uint64) SOLRequest {
	cold, _ := solmsg.ParseAddress(e.cold)
	var v [32]byte
	rand.Read(v[:])
	r := SOLRequest{Version: SOLRequestVersion, ID: "r-" + amount, Chain: "solana-localnet", Pool: "p1", Asset: asset, Decimals: 9, From: e.cold, To: e.hot, Amount: amount,
		NonceAccount: solmsg.Address(solmsg.NonceAddress(cold, nonceIdx)), NonceValue: base58.Encode(v[:]), ComputeUnitLimit: 100_000, ComputeUnitPrice: price}
	if asset == "TKN" {
		r.Mint, r.Decimals = e.mint, 6
	}
	return r
}

func (e *solEnv) approvals(r SOLRequest, who ...string) []Approval {
	var out []Approval
	for _, n := range who {
		out = append(out, Approve(n, e.ops[n], r.HashHex()))
	}
	return out
}

func TestSOLSignAndVerify(t *testing.T) {
	e := newSOLEnv(t)
	for _, asset := range []string{"SOL", "TKN"} {
		r := e.req(asset, "1000000", 0, 0)
		s, _, err := e.cfg.Sign(context.Background(), r.File(), e.approvals(r, "alice", "bob"), e.signer)
		if err != nil {
			t.Fatalf("%s: %v", asset, err)
		}
		raw, err := VerifySOLSignedMatches(r, r.HashHex(), s)
		if err != nil || len(raw) == 0 {
			t.Fatalf("%s: verify: %v", asset, err)
		}
		// a different request's signed file is not accepted for this one
		o := e.req(asset, "2000000", 1, 0)
		if _, err := VerifySOLSignedMatches(o, o.HashHex(), s); err == nil {
			t.Fatal("a signed file was accepted for another request")
		}
	}
}

func TestSOLRefusals(t *testing.T) {
	e := newSOLEnv(t)
	ctx := context.Background()
	other := randAddr()
	cases := map[string]func(r *SOLRequest){
		"not a hot shard":    func(r *SOLRequest) { r.To = other },
		"another source":     func(r *SOLRequest) { r.From = other },
		"above the cap":      func(r *SOLRequest) { r.Amount = "10000000001" },
		"zero":               func(r *SOLRequest) { r.Amount = "0" },
		"foreign nonce":      func(r *SOLRequest) { r.NonceAccount = other },
		"unconfigured asset": func(r *SOLRequest) { r.Asset = "XYZ" },
		"wrong mint":         func(r *SOLRequest) { r.Asset, r.Mint = "TKN", other },
		"price over the cap": func(r *SOLRequest) { r.ComputeUnitPrice = 2_000_000 },
		"priority fee cap":   func(r *SOLRequest) { r.ComputeUnitPrice = 600_000 },
		"units over the cap": func(r *SOLRequest) { r.ComputeUnitLimit = 300_000 },
		"another pool":       func(r *SOLRequest) { r.Pool = "p2" },
		"SOL opens a token":  func(r *SOLRequest) { r.CreateDestAccount = true },
		"nonce index beyond": func(r *SOLRequest) {
			c, _ := solmsg.ParseAddress(e.cold)
			r.NonceAccount = solmsg.Address(solmsg.NonceAddress(c, 9))
		},
	}
	for name, mut := range cases {
		r := e.req("SOL", "1000", 0, 0)
		mut(&r)
		if _, _, err := e.cfg.Sign(ctx, r.File(), e.approvals(r, "alice", "bob"), e.signer); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	// a request whose hash does not match its content
	r := e.req("SOL", "1000", 0, 0)
	f := r.File()
	f.Request.Amount = "2000"
	if _, _, err := e.cfg.Sign(ctx, f, e.approvals(r, "alice", "bob"), e.signer); err == nil {
		t.Error("a tampered request was signed")
	}
}

func TestSOLApprovals(t *testing.T) {
	e := newSOLEnv(t)
	ctx := context.Background()
	r := e.req("SOL", "1000", 0, 0)
	if _, _, err := e.cfg.Sign(ctx, r.File(), e.approvals(r, "alice"), e.signer); err == nil {
		t.Fatal("signed with one of two approvals")
	}
	if _, _, err := e.cfg.Sign(ctx, r.File(), e.approvals(r, "alice", "alice"), e.signer); err == nil {
		t.Fatal("one operator counted twice")
	}
	o := e.req("SOL", "1001", 1, 0)
	mixed := append(e.approvals(o, "bob"), e.approvals(r, "alice")...)
	if _, _, err := e.cfg.Sign(ctx, r.File(), mixed, e.signer); err == nil {
		t.Fatal("an approval of another request counted")
	}
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := e.cfg.Sign(ctx, r.File(), append(e.approvals(r, "alice"), Approve("mallory", stranger, r.HashHex())), e.signer); err == nil {
		t.Fatal("an unknown operator counted")
	}
}

// A nonce value is spent once: a second payment on it is refused, a replacement of the same payment needs a higher price, and the same request again returns
// the same signed file.
func TestSOLNonceValueIsSignedForOnePayment(t *testing.T) {
	e := newSOLEnv(t)
	ctx := context.Background()
	r := e.req("SOL", "1000", 0, 10)
	s1, _, err := e.cfg.Sign(ctx, r.File(), e.approvals(r, "alice", "bob"), e.signer)
	if err != nil {
		t.Fatal(err)
	}
	s1b, _, err := e.cfg.Sign(ctx, r.File(), e.approvals(r, "alice", "carol"), e.signer)
	if err != nil || s1b.RawTx != s1.RawTx {
		t.Fatalf("same request again: %v", err)
	}
	// another payment on the same nonce value
	d := r
	d.Amount, d.ID = "9999", "other"
	if _, _, err := e.cfg.Sign(ctx, d.File(), e.approvals(d, "alice", "bob"), e.signer); err == nil || !strings.Contains(err.Error(), "already signed for a different payment") {
		t.Fatalf("a different payment on a spent nonce value: %v", err)
	}
	// the same payment at the same or a lower price
	same := r
	same.Revision, same.ComputeUnitPrice = 1, 10
	if _, _, err := e.cfg.Sign(ctx, same.File(), e.approvals(same, "alice", "bob"), e.signer); err == nil {
		t.Fatal("a replacement without a higher price was signed")
	}
	// the same payment at a higher price
	up := r
	up.Revision, up.ComputeUnitPrice = 2, 50
	if _, _, err := e.cfg.Sign(ctx, up.File(), e.approvals(up, "alice", "bob"), e.signer); err != nil {
		t.Fatalf("replacement: %v", err)
	}
	// and the other destination of the same nonce value (a second hot shard) is a different payment
	e.cfg.Destinations = append(e.cfg.Destinations, randAddr())
	x := up
	x.To, x.Revision, x.ComputeUnitPrice = e.cfg.Destinations[1], 3, 90
	if _, _, err := e.cfg.Sign(ctx, x.File(), e.approvals(x, "alice", "bob"), e.signer); err == nil {
		t.Fatal("the same nonce value was signed to a second destination")
	}
}

func TestSOLVerifySignedRefusesWhatIsNotTheRequest(t *testing.T) {
	e := newSOLEnv(t)
	r := e.req("TKN", "1000000", 0, 0)
	s, _, err := e.cfg.Sign(context.Background(), r.File(), e.approvals(r, "alice", "bob"), e.signer)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(s.RawTx)
	bad := append([]byte{}, raw...)
	bad[len(bad)-1] ^= 1 // alter the message
	t1 := s
	t1.RawTx = hex.EncodeToString(bad)
	if _, err := VerifySOLSignedMatches(r, r.HashHex(), t1); err == nil {
		t.Error("an altered message was accepted")
	}
	// a message another key signed
	_, k2, _ := ed25519.GenerateKey(rand.Reader)
	msg := raw[65:]
	forged := append(append([]byte{1}, ed25519.Sign(k2, msg)...), msg...)
	t2 := s
	t2.RawTx = hex.EncodeToString(forged)
	if _, err := VerifySOLSignedMatches(r, r.HashHex(), t2); err == nil {
		t.Error("a signature of another key was accepted")
	}
}

// The token refill creates the destination's token account only when asked, from the cold address.
func TestSOLMessageShapes(t *testing.T) {
	e := newSOLEnv(t)
	a := e.req("TKN", "1000000", 0, 0)
	b := a
	b.CreateDestAccount = true
	ma, err := a.Message()
	if err != nil {
		t.Fatal(err)
	}
	mb, err := b.Message()
	if err != nil || len(mb) <= len(ma) {
		t.Fatalf("create-account variant not longer: %v", err)
	}
}
