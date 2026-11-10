package sol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/partition"
)

// Withdrawals from a hot shard on durable nonces. The seam is the one EVM uses; where Solana differs:
//
//   - What EVM calls a nonce is a nonce ACCOUNT of the shard's pool plus the value it holds. A withdrawal takes one account for its whole life
//     (allocation), signs the account's current value as its blockhash, and gives the account back when a version of it (or a cancel) has landed
//     at finalized commitment. At most one allocation is open per account (a unique index).
//   - Every version of a withdrawal has the same account and value. A version that is not the first only raises the compute unit price. Whichever
//     version lands first advances the nonce, and every other version, signed or not, can never land: the network refuses it.
//   - A transaction that lands and fails still advances the nonce and pays its fee (like an EVM revert).
//   - The nonce is read at finalized commitment when a slot is taken: a slot is free only after the last user of it finalized, so the value cannot
//     change under a fork, and a node that lags shows an unchanged value, which the allocation recognizes and skips.
//   - A Solana transaction is not "replaced" in a pool; a version that is sent while another is pending is simply another transaction that loses
//     the race, and the network refuses it once the nonce advanced.

// ErrNoFreeNonce: every nonce account of the hot shard carries a withdrawal, or is not created yet. It wraps chain.ErrNotEnoughOutputs, which the
// withdrawal workflow already treats as "wait and build again".
var ErrNoFreeNonce = fmt.Errorf("sol: no free nonce account on the hot shard: %w", chain.ErrNotEnoughOutputs)

// cancelUnits is the compute unit limit of a cancel: an AdvanceNonceAccount needs a few hundred.
const cancelUnits = 5_000

var (
	_ chain.Adapter           = (*Adapter)(nil)
	_ chain.Releaser          = (*Adapter)(nil)
	_ chain.AddressNormalizer = (*Adapter)(nil)
)

// ensurePool registers the pool accounts of every hot shard (their addresses follow from the shard). Whether an account exists on the chain
// is checked when it is taken.
func (a *Adapter) ensurePool(ctx context.Context) error {
	seen := map[[32]byte]bool{}
	for _, h := range a.cfg.hot {
		if seen[h] {
			continue
		}
		seen[h] = true
		for i := 0; i < a.cfg.NoncePool; i++ {
			if _, err := a.pool.Exec(ctx, `INSERT INTO sol_nonce_accounts (chain, address, hot_address, idx) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
				a.cfg.Chain, Address(NonceAddress(h, i)), Address(h), i); err != nil {
				return fmt.Errorf("sol: register nonce pool: %w", err)
			}
		}
	}
	return nil
}

// HotAddress is the address of the hot shard that serves a partition.
func (a *Adapter) HotAddress(partitionID string) (string, error) {
	h, ok := a.cfg.hot[partitionID]
	if !ok {
		return "", fmt.Errorf("sol: partition %q has no hot shard", partitionID)
	}
	return Address(h), nil
}

// NormalizeAddress implements chain.AddressNormalizer: a Solana address is 32 bytes in base58; any such key is a valid destination (a program
// derived address is a legitimate owner of a token account), except the all-zero one, which is the system program.
func (a *Adapter) NormalizeAddress(address string) (string, error) {
	raw, err := ParseAddress(address)
	if err != nil {
		return "", err
	}
	if raw == ([32]byte{}) {
		return "", errors.New("the system program address is not a destination")
	}
	return Address(raw), nil
}

type allocRow struct {
	id      int64
	address string
	hot     string
	value   string
	status  string
	payload []byte
	price   uint64
	txHash  string
}

const allocCols = `id, address, hot_address, nonce_value, status, payload, price, COALESCE(tx_hash,'')`

func scanAlloc(row pgx.Row) (allocRow, error) {
	var r allocRow
	var price int64
	err := row.Scan(&r.id, &r.address, &r.hot, &r.value, &r.status, &r.payload, &price, &r.txHash)
	r.price = uint64(price)
	return r, err
}

func (a *Adapter) unsigned(partitionID string, msg []byte) (chain.UnsignedTx, error) {
	pl, err := json.Marshal(Payload{Message: msg})
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return chain.UnsignedTx{Chain: a.cfg.Chain, Digest: msg, Payload: pl, KeyRef: chain.KeyRef{PartitionID: partitionID, Path: PathHot}}, nil
}

func msgOfPayload(payload []byte) ([]byte, error) {
	p, err := parsePayload(payload)
	if err != nil {
		return nil, err
	}
	return p.Message, nil
}

// ownerAlloc reads the owner's allocation, the open one first, locking it when forUpdate.
func (a *Adapter) ownerAlloc(ctx context.Context, q chain.Querier, kind, id string, open bool, forUpdate bool) (allocRow, error) {
	cond := ""
	if open {
		cond = ` AND status IN ('allocated','broadcast')`
	}
	lock := ""
	if forUpdate {
		lock = " FOR UPDATE"
	}
	r, err := scanAlloc(q.QueryRow(ctx, `SELECT `+allocCols+` FROM sol_nonce_allocations WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3`+cond+
		` ORDER BY (status IN ('allocated','broadcast')) DESC, id DESC LIMIT 1`+lock, a.cfg.Chain, kind, id))
	return r, err
}

// BuildWithdrawal builds the transfer from the partition's hot shard on a free nonce account of its pool. The allocation commits or rolls back
// with the caller's transaction. A second call for the same owner returns the message already built: the zone signs one message for it, and a
// new one is only ever a fee raise (BuildReplacement).
func (a *Adapter) BuildWithdrawal(ctx context.Context, tx pgx.Tx, w chain.WithdrawalIntent) (chain.UnsignedTx, error) {
	if w.Amount == nil || w.Amount.Sign() <= 0 || !w.Amount.IsUint64() {
		return chain.UnsignedTx{}, errors.New("sol: withdrawal amount must be between 1 and 2^64-1")
	}
	hot, ok := a.cfg.hot[w.PartitionID]
	if !ok {
		return chain.UnsignedTx{}, fmt.Errorf("sol: partition %q has no hot shard", w.PartitionID)
	}
	if w.ID == "" {
		return chain.UnsignedTx{}, errors.New("sol: empty owner id")
	}
	dest, err := ParseAddress(w.To)
	if err != nil {
		return chain.UnsignedTx{}, fmt.Errorf("sol: withdrawal destination: %w", err)
	}
	if dest == hot {
		return chain.UnsignedTx{}, errors.New("sol: the destination is the hot shard itself")
	}
	kind := w.OwnerKind
	if kind == "" {
		kind = "withdrawal"
	}
	if have, err := a.ownerAlloc(ctx, tx, kind, w.ID, false, true); err == nil {
		if have.status == "confirmed" {
			return chain.UnsignedTx{}, fmt.Errorf("sol: %s %s already landed", kind, w.ID)
		}
		if have.status == "allocated" || have.status == "broadcast" {
			msg, err := msgOfPayload(have.payload)
			if err != nil {
				return chain.UnsignedTx{}, err
			}
			return a.unsigned(w.PartitionID, msg)
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return chain.UnsignedTx{}, err
	}

	// The instructions after the advance and the compute budget.
	amount := w.Amount.Uint64()
	var body []Ix
	if w.Asset == Native {
		body = []Ix{TransferIx(hot, dest, amount)}
	} else {
		m, ok := a.mintOf(w.Asset)
		if !ok {
			return chain.UnsignedTx{}, fmt.Errorf("sol: asset %q is not configured", w.Asset)
		}
		src, err := ATA(hot, m.raw)
		if err != nil {
			return chain.UnsignedTx{}, err
		}
		dst, err := ATA(dest, m.raw)
		if err != nil {
			return chain.UnsignedTx{}, err
		}
		if _, err := a.rpc.GetAccount(ctx, Address(dst), Confirmed); errors.Is(err, ErrNoAccount) {
			body = append(body, CreateATAIx(hot, dst, dest, m.raw)) // the hot shard pays the rent of the account it opens for the customer
		} else if err != nil {
			return chain.UnsignedTx{}, err
		}
		body = append(body, CheckedTransferIx(src, m.raw, dst, hot, amount, uint8(a.cfg.TokenDecimals[w.Asset])))
	}
	price := a.cfg.ComputeUnitPrice
	return a.takeSlot(ctx, tx, kind, w.ID, w.PartitionID, hot, body, a.cfg.ComputeUnitLimit, price)
}

// takeSlot finds a free, usable nonce account of the shard, allocates it to the owner and builds the message on its value.
func (a *Adapter) takeSlot(ctx context.Context, tx pgx.Tx, kind, id, partitionID string, hot [32]byte, body []Ix, limit uint32, price uint64) (chain.UnsignedTx, error) {
	rows, err := tx.Query(ctx, `SELECT n.address FROM sol_nonce_accounts n WHERE n.chain=$1 AND n.hot_address=$2
		AND NOT EXISTS (SELECT 1 FROM sol_nonce_allocations a WHERE a.chain=n.chain AND a.address=n.address AND a.status IN ('allocated','broadcast'))
		ORDER BY n.idx FOR UPDATE OF n SKIP LOCKED`, a.cfg.Chain, Address(hot))
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	var cands []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return chain.UnsignedTx{}, err
		}
		cands = append(cands, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return chain.UnsignedTx{}, err
	}
	for _, addr := range cands {
		st, err := a.rpc.GetNonce(ctx, addr, Finalized)
		if err != nil {
			continue // not created yet, or not a nonce account: not usable now
		}
		if st.Authority != hot {
			continue
		}
		value := Address(st.Value)
		// The last owner of this account landed and the node still shows the value it signed: the node lags. Wait for it to catch up.
		var last string
		if err := tx.QueryRow(ctx, `SELECT nonce_value FROM sol_nonce_allocations WHERE chain=$1 AND address=$2 AND status IN ('confirmed','cancelled')
			ORDER BY id DESC LIMIT 1`, a.cfg.Chain, addr).Scan(&last); err == nil && last == value {
			continue
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return chain.UnsignedTx{}, err
		}
		nonce, _ := ParseAddress(addr)
		ixs := []Ix{AdvanceNonceIx(nonce, hot), SetLimitIx(limit)}
		if price > 0 {
			ixs = append(ixs, SetPriceIx(price))
		}
		ixs = append(ixs, body...)
		msg := Compile(hot, st.Value, ixs...)
		u, err := a.unsigned(partitionID, msg)
		if err != nil {
			return chain.UnsignedTx{}, err
		}
		sp, err := tx.Begin(ctx) // a savepoint: losing a race for the slot must not abort the caller's transaction
		if err != nil {
			return chain.UnsignedTx{}, err
		}
		if _, err := sp.Exec(ctx, `INSERT INTO sol_nonce_allocations (chain, address, hot_address, nonce_value, owner_kind, owner_id, status, payload, price)
			VALUES ($1,$2,$3,$4,$5,$6,'allocated',$7,$8)`, a.cfg.Chain, addr, Address(hot), value, kind, id, u.Payload, int64(price)); err != nil {
			_ = sp.Rollback(ctx)
			continue
		}
		if err := sp.Commit(ctx); err != nil {
			return chain.UnsignedTx{}, err
		}
		return u, nil
	}
	return chain.UnsignedTx{}, ErrNoFreeNonce
}

// bump is the next compute unit price: old plus FeeBumpPercent (at least one micro-lamport), or a first price when there was none.
func (a *Adapter) bump(old uint64) uint64 {
	if old == 0 {
		return 1000
	}
	step := (old*uint64(a.cfg.FeeBumpPercent) + 99) / 100
	if step < 1 {
		step = 1
	}
	return old + step
}

// withPrice returns the instructions of m with the compute unit price set to price (added after the limit if there was none).
func withPrice(m *Message, price uint64) []Ix {
	var out []Ix
	cb, _ := ParseAddress(ComputeBudgetProgram)
	set, last := false, -1
	for _, x := range m.Ixs() {
		if x.Program == cb && len(x.Data) > 0 {
			if x.Data[0] == 3 {
				x, set = SetPriceIx(price), true
			}
			last = len(out)
		}
		out = append(out, x)
	}
	if !set {
		out = append(out[:last+1], append([]Ix{SetPriceIx(price)}, out[last+1:]...)...)
	}
	return out
}

func (a *Adapter) storeBuilt(ctx context.Context, tx pgx.Tx, r allocRow, u chain.UnsignedTx, price uint64) error {
	_, err := tx.Exec(ctx, `UPDATE sol_nonce_allocations SET payload=$2, price=$3, updated_at=now() WHERE id=$1`, r.id, u.Payload, int64(price))
	return err
}

// BuildReplacement rebuilds the latest message of the owner with a higher compute unit price. The nonce account, the value and everything else
// stay as they are, which is what the signing zone requires of a second message. It reads nothing from the node.
func (a *Adapter) BuildReplacement(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (chain.UnsignedTx, error) {
	r, err := a.ownerAlloc(ctx, tx, ownerKind, ownerID, true, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return chain.UnsignedTx{}, fmt.Errorf("sol: no open nonce allocation for %s %s", ownerKind, ownerID)
	}
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	if r.status != "broadcast" {
		return chain.UnsignedTx{}, fmt.Errorf("sol: %s %s was never broadcast; rebuild it instead of replacing it", ownerKind, ownerID)
	}
	raw, err := msgOfPayload(r.payload)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	m, err := DecodeMessage(raw)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	price := a.bump(r.price)
	if price > a.cfg.MaxMicroLamports {
		return chain.UnsignedTx{}, fmt.Errorf("%w: price %d would exceed the maximum %d", chain.ErrCannotBump, price, a.cfg.MaxMicroLamports)
	}
	part := a.partitionOfHot(r.hot, ownerKind, ownerID)
	u, err := a.unsigned(part, Compile(m.Keys[0], m.Blockhash, withPrice(m, price)...))
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return u, a.storeBuilt(ctx, tx, r, u, price)
}

// partitionOfHot names a partition of the shard whose address is hot, for the job's key reference; the intent (what approvers signed) names the
// owner's own partition, and the workflow passes that on, so the zone only needs one that belongs to the same shard.
func (a *Adapter) partitionOfHot(hot, _, _ string) string {
	best := ""
	for p, h := range a.cfg.hot {
		if Address(h) == hot && (best == "" || p < best) {
			best = p
		}
	}
	return best
}

// BuildCancel builds the message that makes sure no version of the owner can ever land: AdvanceNonceAccount on the owner's account and value,
// alone. If a version was broadcast, its price is raised so the cancel is not the slower one.
func (a *Adapter) BuildCancel(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (chain.UnsignedTx, error) {
	r, err := a.ownerAlloc(ctx, tx, ownerKind, ownerID, true, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return chain.UnsignedTx{}, fmt.Errorf("sol: no open nonce allocation for %s %s", ownerKind, ownerID)
	}
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	raw, err := msgOfPayload(r.payload)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	m, err := DecodeMessage(raw)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	price := r.price
	if r.status == "broadcast" {
		price = min(a.bump(r.price), a.cfg.MaxMicroLamports)
	}
	nonce, _ := ParseAddress(r.address)
	ixs := []Ix{AdvanceNonceIx(nonce, m.Keys[0]), SetLimitIx(cancelUnits)}
	if price > 0 {
		ixs = append(ixs, SetPriceIx(price))
	}
	u, err := a.unsigned(a.partitionOfHot(r.hot, ownerKind, ownerID), Compile(m.Keys[0], m.Blockhash, ixs...))
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return u, a.storeBuilt(ctx, tx, r, u, price)
}

// Assemble joins the message with the hot shard's signature: the wire form of a transaction with one signature.
func (a *Adapter) Assemble(u chain.UnsignedTx, sigs []chain.Signature) (chain.SignedTx, error) {
	if len(sigs) != 1 || len(u.More) != 0 {
		return chain.SignedTx{}, fmt.Errorf("sol: a withdrawal has exactly one signature, got %d for %d inputs", len(sigs), 1+len(u.More))
	}
	msg, err := msgOfPayload(u.Payload)
	if err != nil {
		return chain.SignedTx{}, err
	}
	if !bytes.Equal(msg, u.Digest) {
		return chain.SignedTx{}, errors.New("sol: payload does not match digest")
	}
	m, err := DecodeMessage(msg)
	if err != nil {
		return chain.SignedTx{}, err
	}
	if m.NumSigners != 1 {
		return chain.SignedTx{}, fmt.Errorf("sol: the message needs %d signatures, this assembles one", m.NumSigners)
	}
	if len(sigs[0].Bytes) != ed25519.SignatureSize {
		return chain.SignedTx{}, fmt.Errorf("sol: signature is %d bytes, want 64", len(sigs[0].Bytes))
	}
	if !ed25519.Verify(m.Keys[0][:], msg, sigs[0].Bytes) {
		return chain.SignedTx{}, errors.New("sol: the signature is not the fee payer's over the message")
	}
	raw := append(compactU16(1), sigs[0].Bytes...)
	return chain.SignedTx{Chain: a.cfg.Chain, Raw: append(raw, msg...)}, nil
}

// splitTx reads the wire form of a transaction with one signature.
func splitTx(raw []byte) (sig []byte, msg []byte, err error) {
	if len(raw) < 1+64+3 || raw[0] != 1 {
		return nil, nil, errors.New("sol: not a transaction with exactly one signature")
	}
	return raw[1:65], raw[65:], nil
}

// Broadcast sends the transaction. The attempt is recorded before it is sent, so a crash cannot lose the signature; a transaction without an
// allocation is never sent. Sending an attempt of an owner that has already landed sends nothing.
func (a *Adapter) Broadcast(ctx context.Context, s chain.SignedTx) (string, error) {
	sig, msg, err := splitTx(s.Raw)
	if err != nil {
		return "", err
	}
	m, err := DecodeMessage(msg)
	if err != nil {
		return "", err
	}
	hash := base58.Encode(sig)
	if len(m.Instructions) == 0 || m.Instructions[0].Program != mustAddr(SystemProgram) || !bytes.Equal(m.Instructions[0].Data, AdvanceNonceData()) {
		return "", errors.New("sol: refusing to broadcast a transaction that is not on a durable nonce")
	}
	nonceAcct, value := Address(m.Instructions[0].Accts[0]), Address(m.Blockhash)
	kind := "send"
	if len(m.Instructions) > 1 {
		cb := mustAddr(ComputeBudgetProgram)
		cancel := true
		for _, in := range m.Instructions[1:] {
			if in.Program != cb {
				cancel = false
			}
		}
		if cancel {
			kind = "cancel"
		}
	} else {
		kind = "cancel"
	}
	var price uint64
	for _, in := range m.Instructions {
		if in.Program == mustAddr(ComputeBudgetProgram) && len(in.Data) == 9 && in.Data[0] == 3 {
			price = leU64(in.Data[1:])
		}
	}
	dbtx, err := a.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer dbtx.Rollback(ctx) //nolint:errcheck
	r, err := scanAlloc(dbtx.QueryRow(ctx, `SELECT `+allocCols+` FROM sol_nonce_allocations WHERE chain=$1 AND address=$2 AND nonce_value=$3
		ORDER BY id DESC LIMIT 1 FOR UPDATE`, a.cfg.Chain, nonceAcct, value))
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("sol: refusing to broadcast: no allocation of nonce account %s at value %s", nonceAcct, value)
	}
	if err != nil {
		return "", err
	}
	if r.status != "allocated" && r.status != "broadcast" {
		return hash, nil // the allocation is decided: nothing to send
	}
	if _, err := dbtx.Exec(ctx, `INSERT INTO sol_tx_attempts (signature, chain, allocation_id, kind) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, hash, a.cfg.Chain, r.id, kind); err != nil {
		return "", fmt.Errorf("sol: record attempt: %w", err)
	}
	if _, err := dbtx.Exec(ctx, `UPDATE sol_nonce_allocations SET status='broadcast', tx_hash=$2, price=GREATEST(price,$3), updated_at=now() WHERE id=$1`, r.id, hash, int64(price)); err != nil {
		return "", fmt.Errorf("sol: record broadcast: %w", err)
	}
	if err := dbtx.Commit(ctx); err != nil {
		return "", err
	}
	if _, err := a.rpc.SendRaw(ctx, s.Raw); err != nil {
		return "", fmt.Errorf("sol: broadcast: %w", err)
	}
	return hash, nil
}

func leU64(b []byte) uint64 {
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// attemptOf finds what an attempt belongs to.
func (a *Adapter) attemptOf(ctx context.Context, hash string) (allocRow, string, error) {
	var kind string
	var r allocRow
	var price int64
	err := a.pool.QueryRow(ctx, `SELECT a.id, a.address, a.hot_address, a.nonce_value, a.status, a.payload, a.price, COALESCE(a.tx_hash,''), t.kind
		FROM sol_tx_attempts t JOIN sol_nonce_allocations a ON a.id=t.allocation_id WHERE t.chain=$1 AND t.signature=$2`, a.cfg.Chain, hash).
		Scan(&r.id, &r.address, &r.hot, &r.value, &r.status, &r.payload, &price, &r.txHash, &kind)
	r.price = uint64(price)
	return r, kind, err
}

// Status reports a transaction's state. Confirmed and failed both need finalized commitment (a landed transaction that fails still advanced the
// nonce); dropped is no status while the nonce account no longer holds the value the transaction signed, read at finalized, and a status read made
// after that finds nothing: something else advanced the nonce. A transaction the leaders merely never saw stays pending.
func (a *Adapter) Status(ctx context.Context, hash string) (chain.TxStatus, error) {
	st, err := a.sigStatus(ctx, hash)
	if err != nil {
		return "", err
	}
	if st != nil {
		return a.fromStatus(ctx, hash, st)
	}
	r, _, err := a.attemptOf(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return chain.TxPending, nil
	}
	if err != nil {
		return "", err
	}
	now, err := a.rpc.GetNonce(ctx, r.address, Finalized)
	if err != nil {
		return "", fmt.Errorf("sol: nonce %s: %w", r.address, err)
	}
	if Address(now.Value) == r.value {
		return chain.TxPending, nil
	}
	// The nonce moved. Our transaction may be the one that moved it and finalized after the first status read: read again, now that the nonce
	// has been read. Only a miss here means something else used it.
	if st, err = a.sigStatus(ctx, hash); err != nil {
		return "", err
	} else if st != nil {
		return a.fromStatus(ctx, hash, st)
	}
	return chain.TxDropped, nil
}

func (a *Adapter) sigStatus(ctx context.Context, hash string) (*SigStatus, error) {
	sts, err := a.rpc.SignatureStatuses(ctx, []string{hash})
	if err != nil {
		return nil, err
	}
	return sts[0], nil
}

func (a *Adapter) fromStatus(ctx context.Context, hash string, st *SigStatus) (chain.TxStatus, error) {
	if st.Status != Finalized {
		return chain.TxPending, nil
	}
	a.finalize(ctx, hash)
	if st.Failed() {
		return chain.TxFailed, nil
	}
	return chain.TxConfirmed, nil
}

// finalize closes the allocation of a final transaction: 'cancelled' when it was a cancel, else 'confirmed' (a failed transaction still used the
// nonce). The account is then free for the next owner.
func (a *Adapter) finalize(ctx context.Context, hash string) {
	_, _ = a.pool.Exec(ctx, `UPDATE sol_nonce_allocations al SET status = CASE WHEN t.kind='cancel' THEN 'cancelled' ELSE 'confirmed' END, tx_hash=t.signature, updated_at=now()
		FROM sol_tx_attempts t WHERE t.chain=$1 AND t.signature=$2 AND al.id=t.allocation_id AND al.status IN ('allocated','broadcast')`, a.cfg.Chain, hash)
}

// Outcome looks at every attempt ever broadcast for the owner: any of them may be the one that landed.
func (a *Adapter) Outcome(ctx context.Context, ownerKind, ownerID string) (chain.Outcome, error) {
	rows, err := a.pool.Query(ctx, `SELECT t.signature, t.kind FROM sol_tx_attempts t JOIN sol_nonce_allocations a ON a.id=t.allocation_id
		WHERE a.chain=$1 AND a.owner_kind=$2 AND a.owner_id=$3 ORDER BY t.created_at`, a.cfg.Chain, ownerKind, ownerID)
	if err != nil {
		return chain.Outcome{}, err
	}
	type attempt struct{ hash, kind string }
	var atts []attempt
	for rows.Next() {
		var t attempt
		if err := rows.Scan(&t.hash, &t.kind); err != nil {
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
	if len(atts) == 0 {
		return out, nil
	}
	kindOf := func(k string) string {
		if k == "cancel" {
			return chain.AttemptCancel
		}
		return chain.AttemptSend
	}
	dropped := 0
	for _, t := range atts {
		st, err := a.Status(ctx, t.hash)
		if err != nil {
			return chain.Outcome{}, err
		}
		switch st {
		case chain.TxConfirmed:
			return chain.Outcome{State: chain.OutcomeConfirmed, Hash: t.hash, Kind: kindOf(t.kind), Attempts: len(atts)}, nil
		case chain.TxFailed:
			// A cancel that fails still advanced the nonce: the account is free either way.
			return chain.Outcome{State: chain.OutcomeConfirmed, Hash: t.hash, Kind: kindOf(t.kind), Failed: t.kind != "cancel", Attempts: len(atts)}, nil
		case chain.TxDropped:
			dropped++
		}
	}
	if dropped == len(atts) {
		out.State = chain.OutcomeConsumed
		out.Detail = a.reservationDetail(ctx, ownerKind, ownerID)
	}
	return out, nil
}

// Reservation is the owner's nonce account while its allocation is open: some signature for it may still be broadcast.
func (a *Adapter) Reservation(ctx context.Context, q chain.Querier, ownerKind, ownerID string) (chain.Reservation, error) {
	r, err := a.ownerAlloc(ctx, q, ownerKind, ownerID, false, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return chain.Reservation{}, nil
	}
	if err != nil {
		return chain.Reservation{}, err
	}
	return chain.Reservation{Open: r.status == "allocated" || r.status == "broadcast", Account: r.hot,
		Detail: fmt.Sprintf("nonce account %s value %s of hot shard %s", r.address, r.value, r.hot)}, nil
}

func (a *Adapter) reservationDetail(ctx context.Context, kind, id string) string {
	r, err := a.Reservation(ctx, a.pool, kind, id)
	if err != nil {
		return ""
	}
	return r.Detail
}

// ReleaseUnsigned gives the nonce account back when the owner's attempt was refused and the caller knows no signature exists (the account was
// never used, so its value is unchanged). It refuses when an attempt was ever broadcast.
func (a *Adapter) ReleaseUnsigned(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) error {
	r, err := a.ownerAlloc(ctx, tx, ownerKind, ownerID, true, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if r.status != "allocated" {
		return fmt.Errorf("sol: %s %s was broadcast; its nonce account cannot be released unused", ownerKind, ownerID)
	}
	_, err = tx.Exec(ctx, `UPDATE sol_nonce_allocations SET status='released', updated_at=now() WHERE id=$1`, r.id)
	return err
}

// TxFee is what the transaction cost the hot shard beyond what it sent: the network fee with its priority part, and the rent of a token
// account it opened for the destination. A transaction that failed paid its fee only. Errors until the transaction is final.
func (a *Adapter) TxFee(ctx context.Context, hash string) (*big.Int, error) {
	tx, err := a.rpc.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}
	if tx == nil || tx.Meta == nil {
		return nil, fmt.Errorf("sol: transaction %s has no finalized record yet", hash)
	}
	fee := new(big.Int).SetUint64(tx.Meta.Fee)
	if len(tx.Meta.Err) != 0 && string(tx.Meta.Err) != "null" {
		return fee, nil
	}
	keys := tx.Transaction.Message.AccountKeys
	if len(keys) == 0 || len(tx.Meta.PreBalances) == 0 || len(tx.Meta.PostBalances) == 0 {
		return fee, nil
	}
	out := new(big.Int).Sub(new(big.Int).SetUint64(tx.Meta.PreBalances[0]), new(big.Int).SetUint64(tx.Meta.PostBalances[0]))
	for _, in := range tx.Transaction.Message.Instructions {
		p, ok := decodeParsed(in.Parsed)
		if !ok || in.ProgramID != SystemProgram || p.Type != "transfer" {
			continue
		}
		var info struct {
			Source   string `json:"source"`
			Lamports uint64 `json:"lamports"`
		}
		if json.Unmarshal(p.Info, &info) == nil && info.Source == keys[0].Pubkey {
			out.Sub(out, new(big.Int).SetUint64(info.Lamports))
		}
	}
	if out.Cmp(fee) < 0 {
		return fee, nil
	}
	return out, nil
}

// TxBlock is the slot of a finalized transaction.
func (a *Adapter) TxBlock(ctx context.Context, hash string) (uint64, error) {
	tx, err := a.rpc.GetTransaction(ctx, hash)
	if err != nil {
		return 0, err
	}
	if tx == nil {
		return 0, fmt.Errorf("sol: transaction %s is not final", hash)
	}
	return tx.Slot, nil
}

// compile-time use of strings/partition for the file's helpers.
var (
	_ = strings.TrimSpace
	_ partition.Key
)
