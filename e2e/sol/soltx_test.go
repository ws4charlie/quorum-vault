package sole2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
)

// A minimal legacy-transaction builder for the tests: just enough to fund accounts, make a mint and token accounts, and pay deposits. The
// system under test never builds a transaction in this task; the tests do, as a customer's wallet would.

type key struct {
	pub  [32]byte
	priv ed25519.PrivateKey
}

func newKey(t testing.TB) key {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var k key
	copy(k.pub[:], pub)
	k.priv = priv
	return k
}

func (k key) addr() string { return sol.Address(k.pub) }

func addrBytes(t testing.TB, s string) [32]byte {
	t.Helper()
	b, err := sol.ParseAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type meta struct {
	pub      [32]byte
	signer   bool
	writable bool
}

type ix struct {
	program [32]byte
	accts   []meta
	data    []byte
}

func compactU16(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

// build compiles instructions into a signed legacy transaction (base64) with payer as the fee payer.
func build(t testing.TB, blockhash string, payer key, signers []key, ixs ...ix) string {
	t.Helper()
	type acct struct {
		pub              [32]byte
		signer, writable bool
	}
	order := []*acct{}
	idx := map[[32]byte]*acct{}
	add := func(m meta) {
		if a, ok := idx[m.pub]; ok {
			a.signer = a.signer || m.signer
			a.writable = a.writable || m.writable
			return
		}
		a := &acct{m.pub, m.signer, m.writable}
		idx[m.pub] = a
		order = append(order, a)
	}
	add(meta{payer.pub, true, true})
	for _, in := range ixs {
		for _, m := range in.accts {
			add(m)
		}
		add(meta{in.program, false, false})
	}
	rank := func(a *acct) int {
		switch {
		case a.signer && a.writable:
			return 0
		case a.signer:
			return 1
		case a.writable:
			return 2
		}
		return 3
	}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].pub == payer.pub {
			return true
		}
		if order[j].pub == payer.pub {
			return false
		}
		return rank(order[i]) < rank(order[j])
	})
	pos := map[[32]byte]int{}
	var nsig, nro, nrons int
	for i, a := range order {
		pos[a.pub] = i
		if a.signer {
			nsig++
			if !a.writable {
				nro++
			}
		} else if !a.writable {
			nrons++
		}
	}
	msg := []byte{byte(nsig), byte(nro), byte(nrons)}
	msg = append(msg, compactU16(len(order))...)
	for _, a := range order {
		msg = append(msg, a.pub[:]...)
	}
	bh := sol.MustDecodeBase58(blockhash)
	msg = append(msg, bh...)
	msg = append(msg, compactU16(len(ixs))...)
	for _, in := range ixs {
		msg = append(msg, byte(pos[in.program]))
		msg = append(msg, compactU16(len(in.accts))...)
		for _, m := range in.accts {
			msg = append(msg, byte(pos[m.pub]))
		}
		msg = append(msg, compactU16(len(in.data))...)
		msg = append(msg, in.data...)
	}
	byPub := map[[32]byte]key{payer.pub: payer}
	for _, s := range signers {
		byPub[s.pub] = s
	}
	tx := compactU16(nsig)
	for i := 0; i < nsig; i++ {
		k, ok := byPub[order[i].pub]
		if !ok {
			t.Fatalf("no key for signer %s", sol.Address(order[i].pub))
		}
		tx = append(tx, ed25519.Sign(k.priv, msg)...)
	}
	tx = append(tx, msg...)
	return base64.StdEncoding.EncodeToString(tx)
}

func prog(t testing.TB, s string) [32]byte { return addrBytes(t, s) }

func u64(n uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, n); return b }
func u32(n uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, n); return b }

func (c *chainT) sysTransfer(from, to [32]byte, lamports uint64) ix {
	return ix{program: prog(c.t, sol.SystemProgram), accts: []meta{{from, true, true}, {to, false, true}}, data: append(u32(2), u64(lamports)...)}
}

func (c *chainT) createAccount(from, newAcct, owner [32]byte, lamports, space uint64) ix {
	d := append(append(u32(0), u64(lamports)...), u64(space)...)
	d = append(d, owner[:]...)
	return ix{program: prog(c.t, sol.SystemProgram), accts: []meta{{from, true, true}, {newAcct, true, true}}, data: d}
}

func (c *chainT) initMint(mint, authority [32]byte, decimals byte) ix {
	d := append([]byte{20, decimals}, authority[:]...)
	d = append(d, 0) // no freeze authority
	return ix{program: prog(c.t, sol.TokenProgram), accts: []meta{{mint, false, true}}, data: d}
}

func (c *chainT) initTokenAccount(acct, mint, owner [32]byte) ix {
	return ix{program: prog(c.t, sol.TokenProgram), accts: []meta{{acct, false, true}, {mint, false, false}}, data: append([]byte{18}, owner[:]...)}
}

func (c *chainT) createATA(payer, ata, owner, mint [32]byte) ix {
	return ix{program: prog(c.t, sol.AssociatedTokenProg), data: []byte{1}, accts: []meta{{payer, true, true}, {ata, false, true}, {owner, false, false}, {mint, false, false},
		{prog(c.t, sol.SystemProgram), false, false}, {prog(c.t, sol.TokenProgram), false, false}}}
}

func (c *chainT) mintTo(mint, dest, authority [32]byte, amount uint64) ix {
	return ix{program: prog(c.t, sol.TokenProgram), accts: []meta{{mint, false, true}, {dest, false, true}, {authority, true, false}}, data: append([]byte{7}, u64(amount)...)}
}

func (c *chainT) tokenTransfer(src, dst, authority [32]byte, amount uint64) ix {
	return ix{program: prog(c.t, sol.TokenProgram), accts: []meta{{src, false, true}, {dst, false, true}, {authority, true, false}}, data: append([]byte{3}, u64(amount)...)}
}

// chainT is a client of the validator for the tests.
type chainT struct {
	t   testing.TB
	rpc *sol.RPC
}

func (c *chainT) blockhash() string {
	var out struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := c.rpc.Call(context.Background(), &out, "getLatestBlockhash", map[string]string{"commitment": "confirmed"}); err != nil {
		c.t.Fatal(err)
	}
	return out.Value.Blockhash
}

// send submits a transaction and waits for it to be confirmed. skipPreflight lets a transaction that fails on chain land and be recorded as failed.
// It returns the signature.
func (c *chainT) send(tx string, skipPreflight bool) string {
	c.t.Helper()
	var sig string
	if err := c.rpc.Call(context.Background(), &sig, "sendTransaction", tx, map[string]any{"encoding": "base64", "skipPreflight": skipPreflight, "preflightCommitment": "confirmed"}); err != nil {
		c.t.Fatalf("sendTransaction: %v", err)
	}
	c.waitStatus(sig, "confirmed", true)
	return sig
}

// waitStatus waits until the signature has at least the commitment; with allowFailed a transaction that landed with an error also ends the wait.
func (c *chainT) waitStatus(sig, commitment string, allowFailed bool) (slot uint64, failed bool) {
	c.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var out struct {
			Value []*struct {
				Slot               uint64   `json:"slot"`
				Err                any      `json:"err"`
				ConfirmationStatus string   `json:"confirmationStatus"`
				_                  struct{} `json:"-"`
			} `json:"value"`
		}
		if err := c.rpc.Call(context.Background(), &out, "getSignatureStatuses", []string{sig}, map[string]bool{"searchTransactionHistory": true}); err != nil {
			c.t.Fatal(err)
		}
		if v := out.Value; len(v) == 1 && v[0] != nil {
			rank := map[string]int{"processed": 1, "confirmed": 2, "finalized": 3}
			if rank[v[0].ConfirmationStatus] >= rank[commitment] {
				if v[0].Err != nil && !allowFailed {
					c.t.Fatalf("transaction %s failed on chain: %v", sig, v[0].Err)
				}
				return v[0].Slot, v[0].Err != nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.t.Fatalf("transaction %s did not reach %s", sig, commitment)
	return 0, false
}

func (c *chainT) airdrop(to string, lamports uint64) {
	c.t.Helper()
	var sig string
	if err := c.rpc.Call(context.Background(), &sig, "requestAirdrop", to, lamports); err != nil {
		c.t.Fatalf("airdrop: %v", err)
	}
	c.waitStatus(sig, "confirmed", false)
}

func (c *chainT) rent(space uint64) uint64 {
	var n uint64
	if err := c.rpc.Call(context.Background(), &n, "getMinimumBalanceForRentExemption", space); err != nil {
		c.t.Fatal(err)
	}
	return n
}

// run builds, signs, sends and confirms instructions.
func (c *chainT) run(payer key, signers []key, ixs ...ix) string {
	c.t.Helper()
	return c.send(build(c.t, c.blockhash(), payer, signers, ixs...), false)
}

// newMint makes a mint of the classic Token program with decimals and returns it with its authority.
func (c *chainT) newMint(payer key, decimals byte) key {
	c.t.Helper()
	mint := newKey(c.t)
	sig := c.run(payer, []key{mint}, c.createAccount(payer.pub, mint.pub, prog(c.t, sol.TokenProgram), c.rent(82), 82), c.initMint(mint.pub, payer.pub, decimals))
	c.waitStatus(sig, "finalized", false) // the core reads the mint's decimals at finalized commitment when it starts
	return mint
}

// ata is the associated token account address of owner and mint (the real program checks it: creating an account at a wrong address fails).
func (c *chainT) ata(owner, mint [32]byte) [32]byte {
	c.t.Helper()
	a, err := sol.ATA(owner, mint)
	if err != nil {
		c.t.Fatal(err)
	}
	return a
}

var _ = fmt.Sprint
