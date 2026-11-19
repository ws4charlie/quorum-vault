package sol

import (
	"context"
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

func testNodeHex(t *testing.T, scalarByte byte) (pub, cc string) {
	t.Helper()
	var b [64]byte
	b[0] = scalarByte
	s, err := edwards25519.NewScalar().SetUniformBytes(b[:])
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(edwards25519.NewIdentityPoint().ScalarBaseMult(s).Bytes()), hex.EncodeToString(append(make([]byte, 31), scalarByte))
}

// Generation 1 is the configured node: the same address every way it is asked for, and a later generation's node gives other addresses.
func TestGenerationOneDerivesTodaysAddresses(t *testing.T) {
	pub1, cc1 := testNodeHex(t, 1)
	pub2, cc2 := testNodeHex(t, 2)
	v, err := Config{Chain: "sol", Network: "localnet", RPCURL: "http://x", AccountPublicKey: pub1, AccountChainCode: cc1}.validated()
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{cfg: v}
	id1, pk, err := DepositIdentity(pub1, cc1)
	if err != nil || id1 != pub1+":"+cc1 || hex.EncodeToString(pk) != pub1 {
		t.Fatalf("identity %q %v", id1, err)
	}
	id2, _, _ := DepositIdentity(pub2, cc2)
	for i := uint64(0); i < 25; i++ {
		want, err := v.node.DepositAddressAt(uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		d0, _ := a.DeriveDepositAddress(context.Background(), "c", i)
		d1, err := a.DeriveDepositAddressAt(context.Background(), chain.DepositKey{Generation: 1, Identity: id1}, "c", i)
		if err != nil {
			t.Fatal(err)
		}
		d2, err := a.DeriveDepositAddressAt(context.Background(), chain.DepositKey{Generation: 2, Identity: id2}, "c", i)
		if err != nil {
			t.Fatal(err)
		}
		if d0.Address != want || d1.Address != want || d1.Kind != chain.KindEd25519 || d2.Address == want {
			t.Fatalf("index %d: configured %s, generation 1 %s, generation 2 %s, want %s", i, d0.Address, d1.Address, d2.Address, want)
		}
	}
	if _, err := a.DeriveDepositAddressAt(context.Background(), chain.DepositKey{Generation: 2, Identity: "nonsense"}, "c", 0); err == nil {
		t.Fatal("a bad identity was accepted")
	}
}

// A transaction whose deposit keys are all generation 1 has the payload it always had; a later generation is named per key, in the payload and the key reference.
func TestUnsignedNamesTheGenerationOfEachDepositKey(t *testing.T) {
	a := &Adapter{cfg: &validatedConfig{Config: Config{Chain: "sol"}}}
	msg := []byte("m")
	u, err := a.unsigned("p", msg, depKey{index: 4}, depKey{index: 9, gen: 1})
	if err != nil {
		t.Fatal(err)
	}
	if string(u.Payload) != `{"message":"bQ==","deposit_indices":[4,9]}` || u.More[0].KeyRef.Path != "d/4" || u.More[1].KeyRef.Path != "d/9" {
		t.Fatalf("generation 1: %s %q %q", u.Payload, u.More[0].KeyRef.Path, u.More[1].KeyRef.Path)
	}
	u, err = a.unsigned("p", msg, depKey{index: 4, gen: 1}, depKey{index: 9, gen: 2})
	if err != nil {
		t.Fatal(err)
	}
	if string(u.Payload) != `{"message":"bQ==","deposit_indices":[4,9],"deposit_gens":[1,2]}` || u.More[0].KeyRef.Path != "d/4" || u.More[1].KeyRef.Path != "g2/d/9" {
		t.Fatalf("mixed: %s %q %q", u.Payload, u.More[0].KeyRef.Path, u.More[1].KeyRef.Path)
	}
	// a rebuilt transaction (a new nonce) keeps the keys it had
	re, err := a.unsignedFromStored("p", u.Payload, []byte("n"))
	if err != nil || re.More[1].KeyRef.Path != "g2/d/9" || re.More[0].KeyRef.Path != "d/4" {
		t.Fatalf("rebuilt %v %v", re.More, err)
	}
}
