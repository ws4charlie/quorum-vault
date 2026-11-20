package btc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// Assemble joins the payload's transaction with one signature per input: the witness of each is [DER(r,s) + 0x01, public key]. Each
// signature (64 bytes r||s from the gateway) is verified against its input's digest and key before the raw transaction is made.
func (a *Adapter) Assemble(u chain.UnsignedTx, sigs []chain.Signature) (chain.SignedTx, error) {
	p, err := DecodePayload(u.Payload)
	if err != nil {
		return chain.SignedTx{}, err
	}
	built, err := BuildUnsigned(p, a.acct)
	if err != nil {
		return chain.SignedTx{}, err
	}
	if len(sigs) != len(p.Inputs) {
		return chain.SignedTx{}, fmt.Errorf("btc: %d signatures for %d inputs", len(sigs), len(p.Inputs))
	}
	if !bytes.Equal(built.Digests[0], u.Digest) {
		return chain.SignedTx{}, errors.New("btc: payload does not match the digest")
	}
	tx := built.Tx
	for i, sg := range sigs {
		if len(sg.Bytes) != 64 {
			return chain.SignedTx{}, fmt.Errorf("btc: signature %d is %d bytes, want 64", i, len(sg.Bytes))
		}
		var r, s btcec.ModNScalar
		if r.SetByteSlice(sg.Bytes[:32]) || s.SetByteSlice(sg.Bytes[32:]) {
			return chain.SignedTx{}, fmt.Errorf("btc: signature %d is out of range", i)
		}
		if s.IsOverHalfOrder() {
			s.Negate() // low S, which relay policy requires
		}
		sig := ecdsa.NewSignature(&r, &s)
		pub, err := btcec.ParsePubKey(built.Pubs[i])
		if err != nil {
			return chain.SignedTx{}, err
		}
		if !sig.Verify(built.Digests[i], pub) {
			return chain.SignedTx{}, fmt.Errorf("btc: signature %d does not verify against input %d's digest and key", i, i)
		}
		tx.TxIn[i].Witness = wire.TxWitness{append(sig.Serialize(), byte(txscript.SigHashAll)), built.Pubs[i]}
	}
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return chain.SignedTx{}, err
	}
	return chain.SignedTx{Chain: a.cfg.Chain, Raw: buf.Bytes()}, nil
}

// Broadcast hands the transaction to the node. The attempt row learns that it was broadcast first (and keeps the raw transaction, so it can be
// sent again), so a crash after sending cannot lose it. "Already in the mempool", "already known" and "already in a block" are success: sending
// the same transaction twice is safe. Other refusals are classified (classifySend): inputs missing or spent, or stuck.
func (a *Adapter) Broadcast(ctx context.Context, s chain.SignedTx) (string, error) {
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(s.Raw)); err != nil {
		return "", fmt.Errorf("btc: decode raw transaction: %w", err)
	}
	txid := tx.TxHash().String()
	var ownerKind, ownerID, attemptKind string
	var fee int64
	err := a.pool.QueryRow(ctx, `UPDATE btc_attempts SET broadcast_at = COALESCE(broadcast_at, now()), raw = $3, last_sent_at = now() WHERE chain=$1 AND txid=$2 RETURNING owner_kind, owner_id, fee, kind`,
		a.cfg.Chain, txid, s.Raw).Scan(&ownerKind, &ownerID, &fee, &attemptKind)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("btc: %s is not a transaction this cell built", txid)
	}
	if err != nil {
		return "", err
	}
	// What the node refuses about a cancel is kept apart from what it refuses about a send (cancelKind).
	switch attemptKind {
	case "cancel":
		ownerKind = cancelKind(ownerKind)
	case "cpfp": // likewise a child's: what the node refuses about it says nothing about the send
		ownerKind = cpfpKind(ownerKind)
	}
	h, serr := a.send(ctx, txid, s.Raw)
	if serr == nil {
		// The node has it: whatever it refused before about this owner, it takes this one. Only the fee floor stays (a later bump pays more than it).
		_, err := a.pool.Exec(ctx, `UPDATE btc_refusals SET other_refusal = '', updated_at = now() WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND other_refusal <> ''`, a.cfg.Chain, ownerKind, ownerID)
		return h, err
	}
	if errors.Is(serr, chain.ErrBroadcastStuck) || errors.Is(serr, chain.ErrInputsSpent) {
		// The node's own judgement, not a transport error. A refused replacement (an attempt after the owner's first) leaves no trace among the
		// attempts: it must not stay as the newest, where it would hide the earlier ones from the rebroadcast and the outcome. The owner's first attempt
		// stays: it is stuck, not forgotten, and the workflow bumps it. What the node refused is kept in btc_refusals (refusals.go), so that the next
		// bump pays more than a fee that was refused for being too low.
		tag, derr := a.pool.Exec(ctx, `DELETE FROM btc_attempts a WHERE a.chain=$1 AND a.txid=$2 AND EXISTS (
			SELECT 1 FROM btc_attempts b WHERE b.chain=a.chain AND b.owner_kind=a.owner_kind AND b.owner_id=a.owner_id AND b.txid <> a.txid
			AND b.broadcast_at IS NOT NULL AND b.created_at <= a.created_at)`, a.cfg.Chain, txid)
		if derr != nil {
			return h, derr
		}
		if errors.Is(serr, chain.ErrBroadcastStuck) {
			if rerr := a.recordRefusal(ctx, ownerKind, ownerID, uint64(fee), serr, tag.RowsAffected() > 0); rerr != nil {
				return h, rerr
			}
		}
	}
	return h, serr
}

func (a *Adapter) send(ctx context.Context, txid string, raw []byte) (string, error) {
	var got string
	err := a.rpc.Call(ctx, &got, "sendrawtransaction", hex.EncodeToString(raw))
	if err == nil {
		return got, nil
	}
	return txid, classifySend(err)
}

// classifySend maps the node's answer to sendrawtransaction. nil: the node has it (already in the mempool, known, or in a block). A refusal
// that is the node's own judgement (an RPC error) is never retried as a failing activity: inputs missing or spent is chain.ErrInputsSpent
// (the outcome check decides who spent them), and everything else (fee below the relay or mempool minimum, the replacement rules, a conflict
// with a pending transaction of ours) is chain.ErrBroadcastStuck. Of those, a refusal about the fee (the node's own words for a fee under the relay
// minimum, under the mempool minimum, or under what the replacement rules require) is also chain.ErrFeeTooLow: it raises the next fee. Every other
// one does not (non-standard, a too long chain of unconfirmed parents, a conflict, anything unknown). A transport error is returned as it is and is
// retried.
func classifySend(err error) error {
	var re *RPCError
	if !errors.As(err, &re) {
		return err
	}
	m := strings.ToLower(re.Message)
	switch {
	case re.Code == -27 || strings.Contains(m, "already in") || strings.Contains(m, "already known") || strings.Contains(m, "txn-already"):
		return nil
	case re.Code == -25 || strings.Contains(m, "missingorspent") || strings.Contains(m, "missing inputs") || strings.Contains(m, "inputs-missing"):
		return fmt.Errorf("%w: %s", chain.ErrInputsSpent, re.Message)
	}
	if feeRefusal(re.Message) {
		return fmt.Errorf("%w: %w: %s", chain.ErrBroadcastStuck, chain.ErrFeeTooLow, re.Message)
	}
	return fmt.Errorf("%w: %s", chain.ErrBroadcastStuck, re.Message)
}

// feeRefusals are Bitcoin Core's reject reasons for a fee that is too low (validation.cpp and policy/rbf.cpp, as sendrawtransaction reports them
// with code -26):
//
//	"min relay fee not met, 50 < 110"                  the fee rate is under the relay minimum
//	"mempool min fee not met, 80 < 110"                the mempool is full and asks for more than the transaction pays
//	"insufficient fee, rejecting replacement <txid>; new feerate <x> <= old feerate <y>"
//	"insufficient fee, rejecting replacement <txid>, less fees than conflicting txs; <x> < <y>"
//	"insufficient fee, rejecting replacement <txid>, not enough additional fees to relay; <x> < <y>"
//
// The last three are the replacement rules (BIP125) and share the reason "insufficient fee".
var feeRefusals = []string{"min relay fee not met", "mempool min fee not met", "insufficient fee"}

func feeRefusal(msg string) bool {
	m := strings.ToLower(msg)
	for _, f := range feeRefusals {
		if strings.Contains(m, f) {
			return true
		}
	}
	return false
}

// confirmations of a transaction: -1 when the node does not know it, 0 in the mempool, else the depth. It needs the node to run with -txindex.
func (a *Adapter) confirmations(ctx context.Context, txid string) (int64, error) {
	var tx struct {
		Confirmations int64  `json:"confirmations"`
		BlockHash     string `json:"blockhash"`
	}
	err := a.rpc.Call(ctx, &tx, "getrawtransaction", txid, true)
	var re *RPCError
	if errors.As(err, &re) && re.Code == -5 {
		return -1, nil
	}
	if err != nil {
		return 0, err
	}
	return tx.Confirmations, nil
}

// Status of a transaction: confirmed once it has SpendConfirmations confirmations, otherwise pending (in the mempool, shallow, or not known
// to the node: a forgotten transaction can be broadcast again, so it is not dropped).
func (a *Adapter) Status(ctx context.Context, txid string) (chain.TxStatus, error) {
	n, err := a.confirmations(ctx, txid)
	if err != nil {
		return "", err
	}
	if n >= int64(a.cfg.SpendConfirmations) {
		return chain.TxConfirmed, nil
	}
	return chain.TxPending, nil
}

// TxFee is what the attempt pays, from the payload it was built from (inputs minus outputs). For a send whose CPFP child confirmed it is what the pair
// paid: the child's fee is a cost of the send's owner, like a bump (a child that did not confirm paid nothing).
func (a *Adapter) TxFee(ctx context.Context, txid string) (*big.Int, error) {
	var fee int64
	var kind string
	err := a.pool.QueryRow(ctx, `SELECT fee, kind FROM btc_attempts WHERE chain=$1 AND txid=$2`, a.cfg.Chain, txid).Scan(&fee, &kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("btc: no attempt %s", txid)
	}
	if err != nil {
		return nil, err
	}
	total := big.NewInt(fee)
	if kind == "send" {
		c, err := a.confirmedChild(ctx, a.pool, txid)
		if err != nil {
			return nil, err
		}
		if c != nil {
			total.Add(total, new(big.Int).SetUint64(c.fee))
		}
	}
	return total, nil
}

// TxBlock is the height of the block that holds a mined transaction.
func (a *Adapter) TxBlock(ctx context.Context, txid string) (uint64, error) {
	var tx struct {
		BlockHash string `json:"blockhash"`
	}
	if err := a.rpc.Call(ctx, &tx, "getrawtransaction", txid, true); err != nil {
		return 0, err
	}
	if tx.BlockHash == "" {
		return 0, fmt.Errorf("btc: %s is not in a block", txid)
	}
	var h struct {
		Height uint64 `json:"height"`
	}
	if err := a.rpc.Call(ctx, &h, "getblockheader", tx.BlockHash); err != nil {
		return 0, err
	}
	return h.Height, nil
}

// resendEvery is how long a forgotten transaction waits before it is sent again.
const resendEvery = 20 * time.Second

// Outcome looks at every transaction broadcast for the owner.
//   - One confirmed at the spend depth decides (a send, or our own cancel).
//   - Else, if none of ours is in a block and an input of the latest attempt is spent on chain (gettxout without the mempool is null), something
//     we did not make spent it: consumed. An input spent by our own attempt in a block is not that case, and neither is one our attempt only
//     holds in the mempool.
//   - Else the attempts are open, and if the node forgot the latest one (a restart with an empty mempool, an eviction) it is sent again, at most
//     every resendEvery. Outcome is polled by the workflow, so this is where a forgotten transaction comes back.
func (a *Adapter) Outcome(ctx context.Context, ownerKind, ownerID string) (chain.Outcome, error) {
	rows, err := a.pool.Query(ctx, `SELECT txid, kind, payload, raw, last_sent_at FROM btc_attempts WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND broadcast_at IS NOT NULL ORDER BY created_at, txid`,
		a.cfg.Chain, ownerKind, ownerID)
	if err != nil {
		return chain.Outcome{}, err
	}
	type att struct {
		txid, kind string
		payload    []byte
		raw        []byte
		sent       *time.Time
		conf       int64
		parent     string // a CPFP child: the transaction it pulls in
	}
	var atts []att
	for rows.Next() {
		var t att
		if err := rows.Scan(&t.txid, &t.kind, &t.payload, &t.raw, &t.sent); err != nil {
			rows.Close()
			return chain.Outcome{}, err
		}
		if t.kind == "cpfp" {
			cp, err := DecodePayload(t.payload)
			if err != nil || len(cp.Inputs) == 0 {
				rows.Close()
				return chain.Outcome{}, fmt.Errorf("btc: CPFP attempt %s has no input: %v", t.txid, err)
			}
			t.parent = cp.Inputs[0].TxID
		}
		atts = append(atts, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return chain.Outcome{}, err
	}
	out := chain.Outcome{State: chain.OutcomeOpen, Attempts: len(atts)}
	rf, err := a.refusalsOf(ctx, a.pool, ownerKind, ownerID)
	if err != nil {
		return chain.Outcome{}, err
	}
	// An owner on its cancel track is watched through the cancel's refusals (BuildCancel): they are what its replacements are about.
	var cancelling bool
	if err := a.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM btc_refusals WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3)`, a.cfg.Chain, cancelKind(ownerKind), ownerID).Scan(&cancelling); err != nil {
		return chain.Outcome{}, err
	}
	if cancelling {
		if rf, err = a.refusalsOf(ctx, a.pool, cancelKind(ownerKind), ownerID); err != nil {
			return chain.Outcome{}, err
		}
	}
	out.FeeRefusals, out.Refusal = rf.FeeRefusals, rf.Other
	inBlock := false
	for i := range atts {
		c, err := a.confirmations(ctx, atts[i].txid)
		if err != nil {
			return chain.Outcome{}, err
		}
		atts[i].conf = c
		if c >= 1 {
			inBlock = true
		}
	}
	depth := int64(a.cfg.SpendConfirmations)
	// A send that has a CPFP child is decided only when the child is too: the child spends the send's change, so the books must settle both at once (the
	// child's fee is booked with the send's, and its output replaces the change). The child is in the mempool, or in the block of its parent, or about to be.
	childConfirmed := func(parent string) (has, confirmed bool) {
		for _, t := range atts {
			if t.kind == "cpfp" && t.parent == parent {
				has = true
				confirmed = confirmed || t.conf >= depth
			}
		}
		return
	}
	waitingForChild := false
	for _, t := range atts {
		if t.conf < depth || t.kind == "cpfp" {
			continue
		}
		kind := chain.AttemptSend
		if t.kind == "cancel" {
			kind = chain.AttemptCancel
		} else if has, ok := childConfirmed(t.txid); has && !ok {
			waitingForChild = true
			continue
		}
		return chain.Outcome{State: chain.OutcomeConfirmed, Hash: t.txid, Kind: kind, Attempts: len(atts)}, nil
	}
	if len(atts) == 0 {
		return out, nil
	}
	var latest att // the newest attempt that is not a child: the owner's own transaction or its cancel
	for _, t := range atts {
		if t.kind != "cpfp" {
			latest = t
		}
	}
	for _, t := range atts {
		if t.kind == "cpfp" && t.parent == latest.txid {
			out.Child = true
		}
	}
	if !inBlock && !waitingForChild {
		p, err := DecodePayload(latest.payload)
		if err != nil {
			return chain.Outcome{}, err
		}
		for _, in := range p.Inputs {
			var o json.RawMessage
			if err := a.rpc.Call(ctx, &o, "gettxout", in.TxID, in.Vout, false); err != nil {
				return chain.Outcome{}, err
			}
			if string(o) == "null" || len(o) == 0 {
				// A block may have been mined between reading the attempts and reading the output, and that block may hold our own attempt: look at the
				// attempts again before calling the spend foreign.
				for i := range atts {
					c, err := a.confirmations(ctx, atts[i].txid)
					if err != nil {
						return chain.Outcome{}, err
					}
					if c >= 1 {
						return out, nil
					}
				}
				return chain.Outcome{State: chain.OutcomeConsumed, Attempts: len(atts),
					Detail: fmt.Sprintf("input %s:%d was spent on chain by a transaction this system did not make", in.TxID, in.Vout)}, nil
			}
		}
	}
	// When the node knows none of the owner's attempts (a restart with an empty mempool, an eviction), send them again, newest first, until the node
	// takes one, each at most every resendEvery. An attempt the node refuses is passed over in this pass: an older one may still be good.
	allForgotten := true
	for i := range atts {
		if atts[i].conf >= 0 {
			allForgotten = false
		}
	}
	if allForgotten {
		for i := len(atts) - 1; i >= 0; i-- {
			t := atts[i]
			if len(t.raw) == 0 || (t.sent != nil && time.Since(*t.sent) < resendEvery) {
				continue
			}
			_, serr := a.send(ctx, t.txid, t.raw)
			if _, err := a.pool.Exec(ctx, `UPDATE btc_attempts SET last_sent_at = now() WHERE chain=$1 AND txid=$2`, a.cfg.Chain, t.txid); err != nil {
				return chain.Outcome{}, err
			}
			if serr == nil {
				break
			}
			// A refusal leaves it as it was; the next older attempt is offered.
		}
	}
	// A CPFP child the node forgot while the transaction it spends is known (or in a block) is sent again, newest first, at most every resendEvery.
	known := map[string]bool{}
	for _, t := range atts {
		known[t.txid] = t.conf >= 0
	}
	for i := len(atts) - 1; i >= 0; i-- {
		t := atts[i]
		if t.kind != "cpfp" || t.conf >= 0 || !known[t.parent] || len(t.raw) == 0 || (t.sent != nil && time.Since(*t.sent) < resendEvery) {
			continue
		}
		_, serr := a.send(ctx, t.txid, t.raw)
		if _, err := a.pool.Exec(ctx, `UPDATE btc_attempts SET last_sent_at = now() WHERE chain=$1 AND txid=$2`, a.cfg.Chain, t.txid); err != nil {
			return chain.Outcome{}, err
		}
		if serr == nil {
			break
		}
	}
	return out, nil
}

// Reservation: the owner holds the outputs it reserved until they are spent (settled) or given back (nothing was signed).
func (a *Adapter) Reservation(ctx context.Context, q chain.Querier, ownerKind, ownerID string) (chain.Reservation, error) {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM btc_utxos WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND status='reserved'`, a.cfg.Chain, ownerKind, ownerID).Scan(&n); err != nil {
		return chain.Reservation{}, err
	}
	r := chain.Reservation{Open: n > 0, Detail: fmt.Sprintf("%d outputs reserved", n)}
	if n > 0 { // the shard address the reservation is on, for a cancel's destination
		var part, path string
		if err := q.QueryRow(ctx, `SELECT partition_id, path FROM btc_utxos WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND status='reserved' ORDER BY txid, vout LIMIT 1`, a.cfg.Chain, ownerKind, ownerID).Scan(&part, &path); err != nil {
			return chain.Reservation{}, err
		}
		gen, _, gerr := chain.SplitKeyPath(path) // a cancel pays the shard of the generation the reserved outputs are under
		if gerr != nil {
			return chain.Reservation{}, gerr
		}
		sh, err := a.shardOfGen(part, gen)
		if err != nil && ownerKind == "sweep" && len(a.shards) > 0 {
			sh, err = a.shardOfGen(a.sinkPartition(), gen) // a deposit output recorded by a cell without hot shards has no partition: the sink shard takes it
		}
		if err == nil {
			r.Account = sh.address
		}
	}
	return r, nil
}

// Settle runs in the settlement's transaction: the outputs the transaction spent become spent, and its change becomes an available output of the shard.
func (a *Adapter) Settle(ctx context.Context, tx pgx.Tx, ownerKind, ownerID, txid string) error {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT payload FROM btc_attempts WHERE chain=$1 AND txid=$2 AND owner_kind=$3 AND owner_id=$4`, a.cfg.Chain, txid, ownerKind, ownerID).Scan(&raw)
	if err != nil {
		return fmt.Errorf("btc: settle %s: no such attempt of %s %s: %w", txid, ownerKind, ownerID, err)
	}
	p, err := DecodePayload(raw)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE btc_attempts SET settled_at = COALESCE(settled_at, now()) WHERE chain=$1 AND txid=$2`, a.cfg.Chain, txid); err != nil {
		return err
	}
	if err := a.forgetRefusals(ctx, tx, ownerKind, ownerID); err != nil {
		return err
	}
	for _, in := range p.Inputs {
		if _, err := tx.Exec(ctx, `UPDATE btc_utxos SET status='spent', updated_at=now() WHERE chain=$1 AND txid=$2 AND vout=$3`, a.cfg.Chain, in.TxID, in.Vout); err != nil {
			return err
		}
	}
	// A CPFP child that confirmed spent the change of this send: the change never becomes a coin, the child's output does (it is the child that is the
	// hot coin once confirmed). The child's fee was booked with this send's (TxFee).
	child, err := a.confirmedChild(ctx, tx, txid)
	if err != nil {
		return err
	}
	skip := -1
	if child != nil {
		skip = int(child.p.Inputs[0].Vout)
	}
	for n, o := range p.Outputs {
		if n == skip {
			continue
		}
		sh, ok := a.hotByAddr(ctx, tx, o.Address)
		if !ok {
			if _, isCold := a.cold[o.Address]; isCold { // an output on the cold address (a move to cold, a refill's change) is a cold output
				if _, err := tx.Exec(ctx, `INSERT INTO btc_utxos (chain, txid, vout, value, partition_id, path, cold, address) VALUES ($1,$2,$3,$4,'','',true,$5) ON CONFLICT DO NOTHING`,
					a.cfg.Chain, txid, n, int64(o.Value), o.Address); err != nil {
					return err
				}
			}
			continue // otherwise the payment
		}
		if _, err := tx.Exec(ctx, `INSERT INTO btc_utxos (chain, txid, vout, value, partition_id, path) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
			a.cfg.Chain, txid, n, int64(o.Value), sh.partition, sh.keyPath()); err != nil {
			return err
		}
	}
	if child != nil {
		if _, err := tx.Exec(ctx, `UPDATE btc_attempts SET settled_at = COALESCE(settled_at, now()) WHERE chain=$1 AND txid=$2`, a.cfg.Chain, child.txid); err != nil {
			return err
		}
		for n, o := range child.p.Outputs {
			sh, ok := a.hotByAddr(ctx, tx, o.Address)
			if !ok {
				return fmt.Errorf("btc: CPFP child %s pays %s, which is not a hot address of this cell", child.txid, o.Address)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO btc_utxos (chain, txid, vout, value, partition_id, path) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
				a.cfg.Chain, child.txid, n, int64(o.Value), sh.partition, sh.keyPath()); err != nil {
				return err
			}
		}
	}
	return nil
}

// ReleaseUnsigned gives the owner's reserved outputs back. The caller has checked that no signature of the attempt can exist. If the chain no
// longer has one of them, something else spent it (a key signed outside this system): nothing is released and the reservation stays open, so the
// caller parks the owner with an alert instead of freeing money that is not there.
func (a *Adapter) ReleaseUnsigned(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) error {
	rows, err := tx.Query(ctx, `SELECT txid, vout FROM btc_utxos WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND status='reserved'`, a.cfg.Chain, ownerKind, ownerID)
	if err != nil {
		return err
	}
	type ref struct {
		txid string
		vout int
	}
	var refs []ref
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.txid, &r.vout); err != nil {
			rows.Close()
			return err
		}
		refs = append(refs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range refs {
		var o json.RawMessage
		if err := a.rpc.Call(ctx, &o, "gettxout", r.txid, r.vout, false); err != nil {
			return err
		}
		if string(o) == "null" || len(o) == 0 {
			return nil
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE btc_utxos SET status='available', owner_kind=NULL, owner_id=NULL, updated_at=now() WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND status='reserved'`,
		a.cfg.Chain, ownerKind, ownerID); err != nil {
		return err
	}
	// Nothing was signed, so nothing of the owner was ever sent: its built attempts go. The same outputs may be built into the very same transaction
	// again (a sweep planned a second time), and a transaction has one row.
	if _, err = tx.Exec(ctx, `DELETE FROM btc_attempts WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND broadcast_at IS NULL`, a.cfg.Chain, ownerKind, ownerID); err != nil {
		return err
	}
	return a.forgetRefusals(ctx, tx, ownerKind, ownerID)
}

// RecordFunding stores an output paid to a hot address from outside; it reports whether it was new.
func (a *Adapter) RecordFunding(ctx context.Context, tx pgx.Tx, f chain.FundingOutput) (bool, error) {
	if f.Cold {
		if _, ok := a.cold[f.Address]; !ok {
			return false, fmt.Errorf("btc: %s is not a cold address of this cell", f.Address)
		}
		tag, err := tx.Exec(ctx, `INSERT INTO btc_utxos (chain, txid, vout, value, partition_id, path, cold, address) VALUES ($1,$2,$3,$4,'','',true,$5) ON CONFLICT DO NOTHING`,
			a.cfg.Chain, f.TxHash, int64(f.Vout), f.Amount.Int64(), f.Address)
		return err == nil && tag.RowsAffected() == 1, err
	}
	sh, ok := a.hotByAddr(ctx, tx, f.Address)
	if !ok {
		return false, fmt.Errorf("btc: %s is not a hot address of this cell", f.Address)
	}
	tag, err := tx.Exec(ctx, `INSERT INTO btc_utxos (chain, txid, vout, value, partition_id, path) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
		a.cfg.Chain, f.TxHash, int64(f.Vout), f.Amount.Int64(), sh.partition, sh.keyPath())
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// NormalizeAddress validates a withdrawal destination for the configured network and returns its canonical form.
func (a *Adapter) NormalizeAddress(address string) (string, error) {
	d, err := DecodeAddress(address, a.cfg.params)
	if err != nil {
		return "", err
	}
	return d.Canonical, nil
}

var (
	_ chain.FundingRecorder   = (*Adapter)(nil)
	_ chain.Settler           = (*Adapter)(nil)
	_ chain.Releaser          = (*Adapter)(nil)
	_ chain.AddressNormalizer = (*Adapter)(nil)
)
