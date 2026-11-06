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
	tag, err := a.pool.Exec(ctx, `UPDATE btc_attempts SET broadcast_at = COALESCE(broadcast_at, now()), raw = $3, last_sent_at = now() WHERE chain=$1 AND txid=$2`, a.cfg.Chain, txid, s.Raw)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", fmt.Errorf("btc: %s is not a transaction this cell built", txid)
	}
	return a.send(ctx, txid, s.Raw)
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
// with a pending transaction of ours) is chain.ErrBroadcastStuck. A transport error is returned as it is and is retried.
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
	return fmt.Errorf("%w: %s", chain.ErrBroadcastStuck, re.Message)
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

// TxFee is what the attempt pays, from the payload it was built from (inputs minus outputs).
func (a *Adapter) TxFee(ctx context.Context, txid string) (*big.Int, error) {
	var fee int64
	err := a.pool.QueryRow(ctx, `SELECT fee FROM btc_attempts WHERE chain=$1 AND txid=$2`, a.cfg.Chain, txid).Scan(&fee)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("btc: no attempt %s", txid)
	}
	return big.NewInt(fee), err
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
	}
	var atts []att
	for rows.Next() {
		var t att
		if err := rows.Scan(&t.txid, &t.kind, &t.payload, &t.raw, &t.sent); err != nil {
			rows.Close()
			return chain.Outcome{}, err
		}
		atts = append(atts, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return chain.Outcome{}, err
	}
	out := chain.Outcome{State: chain.OutcomeOpen, Attempts: len(atts)}
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
		if c >= int64(a.cfg.SpendConfirmations) {
			kind := chain.AttemptSend
			if atts[i].kind == "cancel" {
				kind = chain.AttemptCancel
			}
			return chain.Outcome{State: chain.OutcomeConfirmed, Hash: atts[i].txid, Kind: kind, Attempts: len(atts)}, nil
		}
	}
	if len(atts) == 0 {
		return out, nil
	}
	latest := atts[len(atts)-1]
	if !inBlock {
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
	if latest.conf < 0 && len(latest.raw) > 0 && (latest.sent == nil || time.Since(*latest.sent) >= resendEvery) {
		_, serr := a.send(ctx, latest.txid, latest.raw)
		if _, err := a.pool.Exec(ctx, `UPDATE btc_attempts SET last_sent_at = now() WHERE chain=$1 AND txid=$2`, a.cfg.Chain, latest.txid); err != nil {
			return chain.Outcome{}, err
		}
		_ = serr // a refusal leaves it stuck: the workflow bumps it, or the outcome becomes consumed
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
		var part string
		if err := q.QueryRow(ctx, `SELECT partition_id FROM btc_utxos WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND status='reserved' ORDER BY txid, vout LIMIT 1`, a.cfg.Chain, ownerKind, ownerID).Scan(&part); err != nil {
			return chain.Reservation{}, err
		}
		sh, err := a.shardOf(part)
		if err != nil && ownerKind == "sweep" && len(a.shards) > 0 {
			sh, err = a.sinkShard(), nil // a deposit output recorded by a cell without hot shards has no partition: the sink shard takes it
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
	for _, in := range p.Inputs {
		if _, err := tx.Exec(ctx, `UPDATE btc_utxos SET status='spent', updated_at=now() WHERE chain=$1 AND txid=$2 AND vout=$3`, a.cfg.Chain, in.TxID, in.Vout); err != nil {
			return err
		}
	}
	for n, o := range p.Outputs {
		sh, ok := a.byAddr[o.Address]
		if !ok {
			continue // the payment
		}
		if _, err := tx.Exec(ctx, `INSERT INTO btc_utxos (chain, txid, vout, value, partition_id, path) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
			a.cfg.Chain, txid, n, int64(o.Value), sh.partition, PathString(sh.path)); err != nil {
			return err
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
	_, err = tx.Exec(ctx, `DELETE FROM btc_attempts WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND broadcast_at IS NULL`, a.cfg.Chain, ownerKind, ownerID)
	return err
}

// RecordFunding stores an output paid to a hot address from outside; it reports whether it was new.
func (a *Adapter) RecordFunding(ctx context.Context, tx pgx.Tx, f chain.FundingOutput) (bool, error) {
	sh, ok := a.byAddr[f.Address]
	if !ok {
		return false, fmt.Errorf("btc: %s is not a hot address of this cell", f.Address)
	}
	tag, err := tx.Exec(ctx, `INSERT INTO btc_utxos (chain, txid, vout, value, partition_id, path) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
		a.cfg.Chain, f.TxHash, int64(f.Vout), f.Amount.Int64(), sh.partition, PathString(sh.path))
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
