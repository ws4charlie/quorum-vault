package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
)

type fixture struct {
	dir   string
	keys  map[string]string
	pubs  map[string]ed25519.PublicKey
	clock time.Time
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{dir: t.TempDir(), keys: map[string]string{}, pubs: map[string]ed25519.PublicKey{}, clock: time.Unix(1_800_000_000, 0)}
	for _, n := range []string{"alice", "bob", "carol"} {
		pub, priv, _ := ed25519.GenerateKey(nil)
		f.keys[n] = filepath.Join(f.dir, n+".key")
		f.pubs[n] = pub
		if err := os.WriteFile(f.keys[n], []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *fixture) sign(actor string, args ...string) (stdout, stderr string, err error) {
	var o, e bytes.Buffer
	err = signTo(append([]string{"-actor", actor, "-key", f.keys[actor]}, args...), &o, &e, func() time.Time { return f.clock })
	return o.String(), e.String(), err
}

func (f *fixture) first(t *testing.T) string {
	out := filepath.Join(f.dir, "alice.json")
	if _, _, err := f.sign("alice", "-chain", "btc", "-max-tx-fee-sats", "90000", "-max-fee-rate", "200", "-seq", "4", "-out", out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *fixture) rules() btc.FeeCapsRules {
	ap := map[string]btc.FeeCapsApprover{}
	for n, p := range f.pubs {
		ap[n] = btc.FeeCapsApprover{Key: p, Identity: n}
	}
	return btc.FeeCapsRules{Chain: "btc", Approvers: ap, MinApprovers: 2, MaxAge: 10 * time.Minute, MaxInputs: 1, MaxPayments: 1}
}

func load(t *testing.T, path string) btc.FeeCapsChange {
	c, err := readChange(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Two approvers minutes apart: the second one signs with -like at a much later wall clock and the files still join and verify.
func TestLikeSignsTheSameChangeMinutesLater(t *testing.T) {
	f := newFixture(t)
	a := f.first(t)
	f.clock = f.clock.Add(7 * time.Minute)
	bPath := filepath.Join(f.dir, "bob.json")
	_, stderr, err := f.sign("bob", "-like", a, "-out", bPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"signing as bob", "chain btc", "max_tx_fee_sats 90000", "max_fee_rate 200 sat/vB", "sequence 4", "7m0s ago"} {
		if !strings.Contains(stderr, w) {
			t.Errorf("the plain-words line lacks %q:\n%s", w, stderr)
		}
	}
	ca, cb := load(t, a), load(t, bPath)
	if ca.SignedAt != cb.SignedAt {
		t.Fatalf("signed_at %d vs %d", ca.SignedAt, cb.SignedAt)
	}
	m, err := btc.MergeFeeCaps(ca, cb)
	if err != nil {
		t.Fatal(err)
	}
	if who, err := f.rules().Verify(m); err != nil || len(who) != 2 {
		t.Fatalf("verify: %v %v", who, err)
	}
}

func TestLikeAcceptsAgreeingFlagsAndRefusesDisagreeing(t *testing.T) {
	f := newFixture(t)
	a := f.first(t)
	at := load(t, a).SignedAt
	ok := []string{"-like", a, "-chain", "btc", "-max-tx-fee-sats", "90000", "-max-fee-rate", "200", "-seq", "4", "-signed-at", "" + itoa(at)}
	if _, _, err := f.sign("bob", ok...); err != nil {
		t.Fatalf("agreeing flags: %v", err)
	}
	for flag, bad := range map[string]string{"-chain": "ltc", "-max-tx-fee-sats": "91000", "-max-fee-rate": "300", "-seq": "5", "-signed-at": itoa(at + 1)} {
		stdout, _, err := f.sign("bob", "-like", a, flag, bad)
		if err == nil || !strings.Contains(err.Error(), "disagrees") || !strings.Contains(err.Error(), "not signing") || stdout != "" {
			t.Errorf("%s %s: err %v, stdout %q", flag, bad, err, stdout)
		}
	}
}

func TestLikeRefusesBadFiles(t *testing.T) {
	f := newFixture(t)
	a := f.first(t)
	if _, _, err := f.sign("alice", "-like", a); err == nil || !strings.Contains(err.Error(), "already signed") {
		t.Errorf("the same approver twice: %v", err)
	}
	write := func(name, body string) string {
		p := filepath.Join(f.dir, name)
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	c := load(t, a)
	noSig := c
	noSig.Signatures = nil
	badSig := c
	badSig.Signatures = []btc.FeeCapsSignature{{Actor: "alice", Signature: "zz"}}
	noCaps := c
	noCaps.Caps.MaxFeeRate = 0
	for name, v := range map[string]any{"nosig": noSig, "badsig": badSig, "nocaps": noCaps} {
		b, _ := json.Marshal(v)
		if _, _, err := f.sign("bob", "-like", write(name+".json", string(b))); err == nil || !strings.Contains(err.Error(), "not a signed fee-cap change") && !strings.Contains(err.Error(), "malformed") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := f.sign("bob", "-like", write("junk.json", "not json")); err == nil {
		t.Error("junk accepted")
	}
}

// A first file whose caps were changed after alice signed: the second approver (who reads the printed values) signs it, and apply's check refuses.
func TestTamperedFirstFileIsRefusedAtApply(t *testing.T) {
	f := newFixture(t)
	a := f.first(t)
	c := load(t, a)
	c.Caps.MaxFeeRate = 900
	b, _ := json.Marshal(c)
	tampered := filepath.Join(f.dir, "tampered.json")
	os.WriteFile(tampered, b, 0o600)
	bPath := filepath.Join(f.dir, "bob.json")
	_, stderr, err := f.sign("bob", "-like", tampered, "-out", bPath)
	if err != nil || !strings.Contains(stderr, "max_fee_rate 900") {
		t.Fatalf("%v\n%s", err, stderr)
	}
	m, err := btc.MergeFeeCaps(load(t, tampered), load(t, bPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.rules().Verify(m); err == nil || !strings.Contains(err.Error(), "1 valid signatures") {
		t.Fatalf("a tampered file must not verify: %v", err)
	}
	// A first file with the time moved is also refused: the signature no longer matches.
	c = load(t, a)
	c.SignedAt += 60
	m = c
	m.Signatures = append(m.Signatures, load(t, bPath).Signatures...)
	if _, err := f.rules().Verify(m); err == nil {
		t.Fatal("a moved time must not verify")
	}
}

func TestSignedAtAndDefaults(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.dir, "x.json")
	if _, _, err := f.sign("alice", "-chain", "btc", "-max-tx-fee-sats", "90000", "-max-fee-rate", "200", "-seq", "4", "-signed-at", "1799999000", "-out", p); err != nil {
		t.Fatal(err)
	}
	if got := load(t, p).SignedAt; got != 1799999000 {
		t.Fatalf("signed_at %d", got)
	}
	if got := load(t, f.first(t)).SignedAt; got != f.clock.Unix() {
		t.Fatalf("default time %d", got)
	}
	if _, _, err := f.sign("alice", "-chain", "btc"); err == nil {
		t.Fatal("missing flags accepted")
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }
