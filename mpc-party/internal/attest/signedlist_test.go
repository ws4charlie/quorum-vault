package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func testOps(t *testing.T, n, min int) (*Operators, []ed25519.PrivateKey, []string) {
	t.Helper()
	f := OperatorsFile{Keys: map[string]OperatorFile{}, MinOperators: min}
	var privs []ed25519.PrivateKey
	var names []string
	for i := 0; i < n; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		name := string(rune('a' + i))
		f.Keys[name] = OperatorFile{PublicKey: hex.EncodeToString(pub)}
		privs, names = append(privs, priv), append(names, name)
	}
	ops, err := f.Build()
	if err != nil {
		t.Fatal(err)
	}
	return ops, privs, names
}

func sampleList() SignedAllowlist {
	now := time.Now()
	return SignedAllowlist{Seq: 1, SignedAt: now.Unix(), Entries: []AllowEntry{{Party: "A", Measurement: "ABCD", NotBefore: now, NotAfter: now.Add(time.Hour)}}}
}

func TestSignedAllowlist(t *testing.T) {
	ops, privs, names := testOps(t, 3, 2)
	l := sampleList()
	l = SignAllowlist(privs[0], names[0], l)
	if _, err := ops.Verify(l); err == nil {
		t.Fatal("one signature of two needed verified")
	}
	l = SignAllowlist(privs[0], names[0], l) // signing again does not count twice
	if _, err := ops.Verify(l); err == nil || len(l.Signatures) != 1 {
		t.Fatal("the same operator counted twice")
	}
	l = SignAllowlist(privs[1], names[1], l)
	if got, err := ops.Verify(l); err != nil || len(got) != 2 {
		t.Fatalf("two signatures: %v %v", got, err)
	}
	// round trip through JSON, in another time zone and with a differently cased measurement: still the same message
	b, _ := json.Marshal(l)
	l2, err := ParseSignedAllowlist(b)
	if err != nil {
		t.Fatal(err)
	}
	l2.Entries[0].NotBefore = l2.Entries[0].NotBefore.In(time.FixedZone("x", 8*3600))
	l2.Entries[0].Measurement = "abcd"
	if _, err := ops.Verify(l2); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	for name, mod := range map[string]func(*SignedAllowlist){
		"changed measurement": func(x *SignedAllowlist) { x.Entries[0].Measurement = "abce" },
		"changed party":       func(x *SignedAllowlist) { x.Entries[0].Party = "B" },
		"extended window":     func(x *SignedAllowlist) { x.Entries[0].NotAfter = x.Entries[0].NotAfter.Add(time.Hour) },
		"added entry":         func(x *SignedAllowlist) { x.Entries = append(x.Entries, x.Entries[0]) },
		"changed sequence":    func(x *SignedAllowlist) { x.Seq = 9 },
	} {
		x := l
		x.Entries = append([]AllowEntry(nil), l.Entries...)
		mod(&x)
		if _, err := ops.Verify(x); err == nil {
			t.Fatalf("%s still verifies", name)
		}
	}
	// a signature by a key that is not an operator, or under another name, does not count
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	x := SignAllowlist(stranger, "a", sampleList())
	x = SignAllowlist(stranger, "zz", x)
	if _, err := ops.Verify(x); err == nil {
		t.Fatal("a stranger's signatures verified")
	}
}

func TestOperatorsValidation(t *testing.T) {
	if _, err := (OperatorsFile{}).Build(); err == nil {
		t.Fatal("no operators accepted")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k := OperatorFile{PublicKey: hex.EncodeToString(pub)}
	if _, err := (OperatorsFile{Keys: map[string]OperatorFile{"a": k, "b": k}}).Build(); err == nil {
		t.Fatal("two operators with one key accepted")
	}
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	k2 := OperatorFile{PublicKey: hex.EncodeToString(pub2)}
	if _, err := (OperatorsFile{Keys: map[string]OperatorFile{"a": k, "b": k2}, MinOperators: 1}).Build(); err == nil {
		t.Fatal("min_operators 1 with two operators accepted")
	}
	if _, err := (OperatorsFile{Keys: map[string]OperatorFile{"a": {PublicKey: "zz"}}}).Build(); err == nil {
		t.Fatal("bad key accepted")
	}
}

func TestMalformedEntriesRefuseTheList(t *testing.T) {
	ops, privs, names := testOps(t, 2, 2)
	now := time.Now()
	for name, e := range map[string]AllowEntry{
		"empty party":   {Party: "", Measurement: "aa", NotBefore: now, NotAfter: now.Add(time.Hour)},
		"bad hex":       {Party: "A", Measurement: "zz", NotBefore: now, NotAfter: now.Add(time.Hour)},
		"zero time":     {Party: "A", Measurement: "aa", NotAfter: now},
		"ends before":   {Party: "A", Measurement: "aa", NotBefore: now, NotAfter: now.Add(-time.Hour)},
		"party with /":  {Party: "A/B", Measurement: "aa", NotBefore: now, NotAfter: now.Add(time.Hour)},
		"empty measure": {Party: "A", Measurement: "", NotBefore: now, NotAfter: now.Add(time.Hour)},
	} {
		l := SignedAllowlist{Seq: 1, Entries: []AllowEntry{e}}
		l = SignAllowlist(privs[0], names[0], l)
		l = SignAllowlist(privs[1], names[1], l)
		if _, err := ops.Verify(l); err == nil {
			t.Fatalf("%s: a fully signed malformed list verified", name)
		}
	}
	l := SignAllowlist(privs[1], names[1], SignAllowlist(privs[0], names[0], SignedAllowlist{Seq: 0}))
	if _, err := ops.Verify(l); err == nil {
		t.Fatal("sequence 0 verified")
	}
}
