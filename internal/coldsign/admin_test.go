package coldsign

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var factoryAddr = common.HexToAddress("0x00000000000000000000000000000000000fAc70")

// adminFixture allows every factory call, with pinned destinations, guardians and admins.
func adminFixture(t *testing.T) *fixture {
	f := newFixture(t)
	f.cfg.Actions = []string{KindSetDestination, KindFreeze, KindSetGuardian, KindTransferAdmin, KindAcceptAdmin}
	f.cfg.Factory = factoryAddr.Hex()
	f.cfg.NewDestinations = []string{f.hot.Hex(), "0x0000000000000000000000000000000000000408"}
	f.cfg.NewGuardians = []string{"0x00000000000000000000000000000000000009a1"}
	f.cfg.NewAdmins = []string{"0x00000000000000000000000000000000000c01d2"}
	if err := f.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) adminRequest(kind, param string, mut func(*Request)) RequestFile {
	return f.request(func(r *Request) {
		r.Kind, r.Contract, r.Param, r.Asset, r.Token, r.Amount, r.Gas = kind, factoryAddr.Hex(), param, "", "", "0", 60000
		r.To = factoryAddr.Hex()
		r.Current = "0x00000000000000000000000000000000000De57"
		if mut != nil {
			mut(r)
		}
	})
}

func TestAdminCalldataSelectors(t *testing.T) {
	for kind, want := range map[string]string{KindSetDestination: "setDestination(address)", KindSetGuardian: "setGuardian(address)", KindTransferAdmin: "transferAdmin(address)"} {
		d, err := AdminCalldata(kind, factoryAddr.Hex())
		if err != nil || len(d) != 36 || common.Bytes2Hex(d[:4]) != common.Bytes2Hex(crypto.Keccak256([]byte(want))[:4]) || common.BytesToAddress(d[4:]) != factoryAddr {
			t.Errorf("%s: %x %v", kind, d, err)
		}
	}
	for kind, want := range map[string]string{KindFreeze: "freeze()", KindAcceptAdmin: "acceptAdmin()"} {
		d, err := AdminCalldata(kind, "")
		if err != nil || len(d) != 4 || common.Bytes2Hex(d) != common.Bytes2Hex(crypto.Keccak256([]byte(want))[:4]) {
			t.Errorf("%s: %x %v", kind, d, err)
		}
	}
	if _, err := AdminCalldata(KindFreeze, factoryAddr.Hex()); err == nil {
		t.Error("freeze took an argument")
	}
}

func TestAdminCeremonySigns(t *testing.T) {
	f := adminFixture(t)
	n := uint64(10)
	for _, c := range []struct{ kind, param string }{
		{KindSetDestination, f.hot.Hex()}, {KindSetGuardian, "0x00000000000000000000000000000000000009a1"},
		{KindTransferAdmin, "0x00000000000000000000000000000000000c01d2"}, {KindFreeze, ""}, {KindAcceptAdmin, ""},
	} {
		n++
		rf := f.adminRequest(c.kind, c.param, func(r *Request) { r.Nonce = n })
		s, err := f.sign(rf, f.approvals(rf, "alice", "bob"))
		if err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
		tx, err := VerifySignedMatches(rf.Request, rf.RequestHash, s)
		if err != nil || *tx.To() != factoryAddr || tx.Value().Sign() != 0 {
			t.Fatalf("%s: signed file %v %+v", c.kind, err, tx)
		}
	}
	// What the operator reads for a destination change: the readable before and after.
	rf := f.adminRequest(KindSetDestination, f.hot.Hex(), nil)
	sum := rf.Request.Summary(18)
	for _, want := range []string{"SET THE SWEEP DESTINATION", "destination: 0x00000000000000000000000000000000000De57  ->  " + f.hot.Hex(), "the forwarder factory"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary lacks %q:\n%s", want, sum)
		}
	}
}

func TestOfflineToolRefusesFactoryCalls(t *testing.T) {
	f := adminFixture(t)
	n := uint64(50)
	req := func(kind, param string, mut func(*Request)) RequestFile {
		n++
		return f.adminRequest(kind, param, func(r *Request) {
			r.Nonce = n
			if mut != nil {
				mut(r)
			}
		})
	}
	evil := common.HexToAddress("0x000000000000000000000000000000000000dEaD").Hex()

	rf := req(KindSetDestination, evil, nil)
	_, err := f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "unpinned destination", err, "is not one of the pinned destinations for set-destination")

	rf = req(KindSetGuardian, evil, nil)
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "unpinned guardian", err, "not one of the pinned guardians")

	rf = req(KindTransferAdmin, evil, nil)
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "unpinned new admin", err, "not one of the pinned admins")

	rf = req(KindSetDestination, f.hot.Hex(), nil)
	_, err = f.sign(rf, f.approvals(rf, "alice"))
	wantRefusal(t, "one approval of two", err, "1 valid approval(s) from distinct configured operators, 2 required")

	rf = req(KindSetDestination, f.hot.Hex(), func(r *Request) { r.Contract = evil })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "wrong contract", err, "this signer administers the factory")

	rf = req(KindSetDestination, f.hot.Hex(), func(r *Request) { r.ChainID = 1 })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "wrong chain", err, "request is for chain")

	rf = req(KindFreeze, "", func(r *Request) { r.Param = f.hot.Hex() })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "freeze with an argument", err, "takes no argument")

	rf = req("self-destruct", "", nil)
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "unknown kind", err, `action kind "self-destruct" is not known`)

	rf = req(KindSetDestination, f.hot.Hex(), func(r *Request) { r.Gas = 3_000_000 })
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "gas far above a factory call", err, "is above the limit")

	rf = req(KindSetDestination, f.hot.Hex(), func(r *Request) { r.Amount = "5" }) // a factory call that also moves funds
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "factory call with an amount", err, "carries no asset or amount")

	rf = req(KindSetDestination, f.hot.Hex(), nil)
	rf.Request.Param = "0x0000000000000000000000000000000000000408" // changed after the hash was made
	_, err = f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "tampered request file", err, "damaged or was changed")

	// Same nonce, different content: a destination signed once cannot become another at that nonce.
	rf = req(KindSetDestination, f.hot.Hex(), nil)
	if _, err = f.sign(rf, f.approvals(rf, "alice", "bob")); err != nil {
		t.Fatal(err)
	}
	other := f.adminRequest(KindSetDestination, "0x0000000000000000000000000000000000000408", func(r *Request) { r.Nonce = rf.Request.Nonce })
	_, err = f.sign(other, f.approvals(other, "alice", "bob"))
	wantRefusal(t, "same nonce, other destination", err, "was already signed for different content")
}

func TestActionKindNotAllowedByConfig(t *testing.T) {
	f := adminFixture(t)
	f.cfg.Actions = []string{KindFreeze} // this signer may only freeze
	rf := f.adminRequest(KindSetDestination, f.hot.Hex(), func(r *Request) { r.Nonce = 90 })
	_, err := f.sign(rf, f.approvals(rf, "alice", "bob"))
	wantRefusal(t, "kind not allowed", err, `action kind "set-destination" is not allowed by this signer's config`)
	rf = f.adminRequest(KindFreeze, "", func(r *Request) { r.Nonce = 91 })
	if _, err := f.sign(rf, f.approvals(rf, "alice", "bob")); err != nil {
		t.Fatalf("the allowed kind was refused: %v", err)
	}
}
