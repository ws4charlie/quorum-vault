package btc

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

// The published BIP143 example for a native P2WPKH input (the second input of the transaction in the BIP): the unsigned transaction,
// the key, the amount, and the sighash the BIP lists.
func TestBIP143PublishedVector(t *testing.T) {
	raw, _ := hex.DecodeString("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")
	prev := map[wire.OutPoint]*wire.TxOut{
		tx.TxIn[0].PreviousOutPoint: wire.NewTxOut(625000000, nil), // the first input is P2PK in the BIP; BIP143 hashes only its outpoint and sequence
		tx.TxIn[1].PreviousOutPoint: wire.NewTxOut(600000000, nil),
	}
	got, err := SighashOf(&tx, 1, hash160(pub), 600000000, prev)
	if err != nil {
		t.Fatal(err)
	}
	if want := "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"; hex.EncodeToString(got) != want {
		t.Fatalf("sighash %x, want %s", got, want)
	}
}

// bip143 is a second implementation of the digest, straight from the BIP text, to check BuildUnsigned against on random transactions.
func bip143(tx *wire.MsgTx, idx int, pkh []byte, value int64) []byte {
	dsha := func(b []byte) []byte { a := sha256.Sum256(b); c := sha256.Sum256(a[:]); return c[:] }
	var prevouts, seqs, outs bytes.Buffer
	for _, in := range tx.TxIn {
		prevouts.Write(in.PreviousOutPoint.Hash[:])
		binary.Write(&prevouts, binary.LittleEndian, in.PreviousOutPoint.Index)
		binary.Write(&seqs, binary.LittleEndian, in.Sequence)
	}
	for _, o := range tx.TxOut {
		wire.WriteTxOut(&outs, 0, 0, o)
	}
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, tx.Version)
	b.Write(dsha(prevouts.Bytes()))
	b.Write(dsha(seqs.Bytes()))
	in := tx.TxIn[idx]
	b.Write(in.PreviousOutPoint.Hash[:])
	binary.Write(&b, binary.LittleEndian, in.PreviousOutPoint.Index)
	b.Write([]byte{0x19, 0x76, 0xa9, 0x14})
	b.Write(pkh)
	b.Write([]byte{0x88, 0xac})
	binary.Write(&b, binary.LittleEndian, uint64(value))
	binary.Write(&b, binary.LittleEndian, in.Sequence)
	b.Write(dsha(outs.Bytes()))
	binary.Write(&b, binary.LittleEndian, tx.LockTime)
	binary.Write(&b, binary.LittleEndian, uint32(1)) // SIGHASH_ALL
	return dsha(b.Bytes())
}

func testAccount(t *testing.T) *Account {
	t.Helper()
	m, err := hdkeychain.NewMaster(bytes.Repeat([]byte{7}, 32), &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatal(err)
	}
	k := m
	for _, n := range []uint32{hdkeychain.HardenedKeyStart + 84, hdkeychain.HardenedKeyStart + 1, hdkeychain.HardenedKeyStart} {
		if k, err = k.Derive(n); err != nil {
			t.Fatal(err)
		}
	}
	pub, _ := k.Neuter()
	a, err := NewAccount("regtest", pub.String())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestBuildUnsignedMatchesAnIndependentBIP143(t *testing.T) {
	acct := testAccount(t)
	r := rand.New(rand.NewSource(1))
	for round := 0; round < 25; round++ {
		n := 1 + r.Intn(4)
		p := Payload{Version: 2}
		var sum uint64
		for i := 0; i < n; i++ {
			var h [32]byte
			r.Read(h[:])
			v := uint64(10_000 + r.Intn(5_000_000))
			sum += v
			p.Inputs = append(p.Inputs, PayloadInput{TxID: hex.EncodeToString(h[:]), Vout: uint32(r.Intn(5)), Value: v, Path: []uint32{uint32(r.Intn(2)), uint32(r.Intn(1000))}, Sequence: SequenceRBF})
		}
		a0, _ := acct.Address([]uint32{1, 0})
		p.Outputs = []PayloadOutput{{Address: a0, Value: sum - 1000}}
		u, err := BuildUnsigned(p, acct)
		if err != nil {
			t.Fatal(err)
		}
		for i := range p.Inputs {
			if want := bip143(u.Tx, i, hash160(u.Pubs[i]), int64(p.Inputs[i].Value)); !bytes.Equal(u.Digests[i], want) {
				t.Fatalf("round %d input %d: %x, independent %x", round, i, u.Digests[i], want)
			}
		}
	}
}
