package evm

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

// ErrSweepFrozen: the factory's destination is zero (its admin froze sweeping).
// Funds stay where they are; stop sweeping rather than treating this as an outage.
var ErrSweepFrozen = errors.New("evm: sweeping is frozen (factory destination is zero)")

// ErrDestinationMismatch: the factory pays somewhere other than Config.SweepDestination.
// The admin changed it and the configuration (including the signing zone's) is stale.
var ErrDestinationMismatch = errors.New("evm: factory destination differs from the configured sweep destination")

// DefaultCancelGas is the gas limit of a cancel (a plain self-send).
const DefaultCancelGas uint64 = 21000

// Adapter is the EVM chain cell.
type Adapter struct {
	cfg  Config
	pool *pgxpool.Pool
	ec   *ethclient.Client
}

var _ chain.Adapter = (*Adapter)(nil)

// New connects to cfg.RPCURL and refuses a node whose chain ID differs from cfg.ChainID.
func New(ctx context.Context, cfg Config, pool *pgxpool.Pool) (*Adapter, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.RPCURL == "" {
		return nil, errors.New("evm: config: rpc url is required")
	}
	if pool == nil {
		return nil, errors.New("evm: nil database pool")
	}
	ec, err := ethclient.DialContext(ctx, cfg.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("evm: dial: %w", err)
	}
	id, err := ec.ChainID(ctx)
	if err != nil {
		ec.Close()
		return nil, fmt.Errorf("evm: chain id: %w", err)
	}
	if id.Uint64() != cfg.ChainID {
		ec.Close()
		return nil, fmt.Errorf("evm: node chain id %s, configured %d", id, cfg.ChainID)
	}
	return &Adapter{cfg: cfg, pool: pool, ec: ec}, nil
}

// Close releases the RPC connection.
func (a *Adapter) Close() { a.ec.Close() }

// Chain returns the configured chain name.
func (a *Adapter) Chain() string { return a.cfg.Chain }

// DeriveDepositAddress is pure: the forwarder address for (customerID, index),
// computed locally. No RPC and no key. The contract is deployed at the first sweep.
func (a *Adapter) DeriveDepositAddress(_ context.Context, customerID string, index uint64) (chain.DepositAddress, error) {
	if customerID == "" {
		return chain.DepositAddress{}, errors.New("evm: empty customer id")
	}
	return deriveAddress(a.cfg, customerID, index), nil
}

func deriveAddress(cfg Config, customerID string, index uint64) chain.DepositAddress {
	addr := PredictAddress(cfg.Factory, DeriveSalt(customerID, index))
	return chain.DepositAddress{Chain: cfg.Chain, Address: addr.Hex(), Kind: chain.KindForwarder, DerivationIndex: index}
}

// fees returns EIP-1559 fees from the node: tip = node suggestion, cap = 2*base + tip.
func (a *Adapter) fees(ctx context.Context) (tip, feeCap, base *big.Int, err error) {
	if tip, err = a.ec.SuggestGasTipCap(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("evm: tip: %w", err)
	}
	h, err := a.ec.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("evm: header: %w", err)
	}
	base = h.BaseFee
	if base == nil {
		base = new(big.Int)
	}
	feeCap = new(big.Int).Add(new(big.Int).Mul(base, big.NewInt(2)), tip)
	return tip, feeCap, base, nil
}

func (a *Adapter) estimate(ctx context.Context, from, to common.Address, value *big.Int, data []byte) (uint64, error) {
	g, err := a.ec.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &to, Value: value, Data: data})
	if err != nil {
		return 0, fmt.Errorf("evm: estimate gas: %w", err)
	}
	return g, nil
}

func (a *Adapter) unsigned(p eth.TxParams, from common.Address, partition string) (chain.UnsignedTx, error) {
	_, digest, err := eth.BuildTx(p)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	payload, err := newPayload(a.cfg.ChainID, from, p).marshal()
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return chain.UnsignedTx{Chain: a.cfg.Chain, Digest: digest[:], Payload: payload, KeyRef: chain.KeyRef{PartitionID: partition}}, nil
}

// BuildWithdrawal builds a transfer from the partition's hot address. The nonce
// is allocated inside tx, so it commits or rolls back with the caller.
func (a *Adapter) BuildWithdrawal(ctx context.Context, tx pgx.Tx, w chain.WithdrawalIntent) (chain.UnsignedTx, error) {
	if w.Amount == nil || w.Amount.Sign() <= 0 {
		return chain.UnsignedTx{}, errors.New("evm: withdrawal amount must be > 0")
	}
	if !common.IsHexAddress(w.To) {
		return chain.UnsignedTx{}, fmt.Errorf("evm: withdrawal destination %q", w.To)
	}
	from, err := a.cfg.hot(w.PartitionID)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	tok, native, err := a.cfg.asset(w.Asset)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	dest := common.HexToAddress(w.To)
	to, value, data := dest, new(big.Int).Set(w.Amount), []byte(nil)
	if !native {
		to, value = tok.Address, new(big.Int)
		if data, err = packTransfer(dest, w.Amount); err != nil {
			return chain.UnsignedTx{}, err
		}
	}
	return a.buildAndAllocate(ctx, tx, "withdrawal", w.ID, w.PartitionID, from, to, value, data)
}

// BuildSweep builds a call from the hot address of s.ToPartition to the
// factory: deployAndFlush(salt, tokens). The hot wallet pays gas. The salt comes
// from the deposit_addresses row of s.From.
func (a *Adapter) BuildSweep(ctx context.Context, tx pgx.Tx, s chain.SweepIntent) (chain.UnsignedTx, error) {
	from, err := a.cfg.hot(s.ToPartition)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	data, err := a.sweepData(ctx, tx, s)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return a.buildAndAllocate(ctx, tx, "sweep", s.ID, s.ToPartition, from, a.cfg.Factory, new(big.Int), data)
}

type queryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// checkDestination reads factory.destination() and maps zero to ErrSweepFrozen.
func (a *Adapter) checkDestination(ctx context.Context) error {
	if err := loadABIs(); err != nil {
		return err
	}
	data, err := factoryABI.Pack("destination")
	if err != nil {
		return err
	}
	out, err := a.ec.CallContract(ctx, ethereum.CallMsg{To: &a.cfg.Factory, Data: data}, nil)
	if err != nil {
		return fmt.Errorf("evm: read factory destination: %w", err)
	}
	dest := common.BytesToAddress(out)
	switch {
	case dest == (common.Address{}):
		return ErrSweepFrozen
	case dest != a.cfg.SweepDestination:
		return fmt.Errorf("%w: factory %s, config %s", ErrDestinationMismatch, dest, a.cfg.SweepDestination)
	}
	return nil
}

func (a *Adapter) sweepData(ctx context.Context, q queryer, s chain.SweepIntent) ([]byte, error) {
	if err := a.checkDestination(ctx); err != nil {
		return nil, err
	}
	tok, native, err := a.cfg.asset(s.Asset)
	if err != nil {
		return nil, err
	}
	if !common.IsHexAddress(s.From) {
		return nil, fmt.Errorf("evm: sweep source %q", s.From)
	}
	src := common.HexToAddress(s.From)
	var customer string
	var idx int64
	err = q.QueryRow(ctx, `SELECT customer_id, derivation_index FROM deposit_addresses WHERE chain=$1 AND address=$2 AND kind='forwarder'`,
		a.cfg.Chain, src.Hex()).Scan(&customer, &idx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("evm: %s is not a known deposit address", src.Hex())
	}
	if err != nil {
		return nil, fmt.Errorf("evm: lookup deposit address: %w", err)
	}
	salt := DeriveSalt(customer, uint64(idx))
	if got := PredictAddress(a.cfg.Factory, salt); got != src {
		return nil, fmt.Errorf("evm: deposit address %s does not match its derivation (%s)", src.Hex(), got.Hex())
	}
	var tokens []common.Address
	if !native {
		tokens = []common.Address{tok.Address}
	}
	return packDeployAndFlush(salt, tokens)
}

func (a *Adapter) buildAndAllocate(ctx context.Context, tx pgx.Tx, kind, id, partition string, from, to common.Address, value *big.Int, data []byte) (chain.UnsignedTx, error) {
	if id == "" {
		return chain.UnsignedTx{}, errors.New("evm: empty owner id")
	}
	gas, err := a.estimate(ctx, from, to, value, data)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	if gas > 21000 {
		gas = gas * 12 / 10
	}
	tip, feeCap, _, err := a.fees(ctx)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	if err := a.checkFee(gas, feeCap); err != nil {
		return chain.UnsignedTx{}, err
	}
	nonce, status, err := a.allocateNonce(ctx, tx, from, kind, id, tip, feeCap)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	u, err := a.unsigned(eth.TxParams{
		ChainID: new(big.Int).SetUint64(a.cfg.ChainID), Nonce: nonce, To: to, Value: value, Data: data,
		Gas: gas, GasTipCap: tip, GasFeeCap: feeCap,
	}, from, partition)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	if status == "allocated" { // once broadcast, the stored payload is what was sent
		if err := a.storeUnsigned(ctx, tx, from.Hex(), nonce, u, tip, feeCap); err != nil {
			return chain.UnsignedTx{}, err
		}
	}
	return u, nil
}

// allocRow is the open allocation of an owner, locked FOR UPDATE.
type allocRow struct {
	addr    string
	nonce   int64
	payload []byte
	sent    bool // at least one attempt was broadcast
	tip     *big.Int
	feeCap  *big.Int
}

func (a *Adapter) lockOpenAllocation(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (allocRow, error) {
	var r allocRow
	var hash, tip, fcap string
	err := tx.QueryRow(ctx, `SELECT address, nonce, payload, COALESCE(tx_hash,''), max_priority_fee_per_gas::text, max_fee_per_gas::text
		FROM evm_nonce_allocations WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND status IN ('allocated','broadcast')
		ORDER BY nonce DESC LIMIT 1 FOR UPDATE`, a.cfg.Chain, ownerKind, ownerID).Scan(&r.addr, &r.nonce, &r.payload, &hash, &tip, &fcap)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, fmt.Errorf("evm: no open allocation for %s %s", ownerKind, ownerID)
	}
	if err != nil {
		return r, err
	}
	r.sent = hash != ""
	r.tip, _ = new(big.Int).SetString(tip, 10)
	r.feeCap, _ = new(big.Int).SetString(fcap, 10)
	if r.tip == nil || r.feeCap == nil {
		return r, fmt.Errorf("evm: allocation of %s %s has no fees", ownerKind, ownerID)
	}
	return r, nil
}

// bump raises old by FeeBumpPercent (rounded up), or to fresh if that is higher.
func (a *Adapter) bump(old, fresh *big.Int) *big.Int {
	b := new(big.Int).Mul(old, big.NewInt(int64(100+a.cfg.FeeBumpPercent)))
	b.Add(b, big.NewInt(99)).Div(b, big.NewInt(100))
	if fresh.Cmp(b) > 0 {
		return fresh
	}
	return b
}

// checkFee refuses a transaction whose worst-case fee exceeds MaxTxFeeWei: the
// signing gateway would reject it, so it must not be built.
func (a *Adapter) checkFee(gas uint64, feeCap *big.Int) error {
	if fee := new(big.Int).Mul(new(big.Int).SetUint64(gas), feeCap); fee.Cmp(a.cfg.MaxTxFeeWei) > 0 {
		return fmt.Errorf("evm: worst-case fee %s exceeds MaxTxFeeWei %s", fee, a.cfg.MaxTxFeeWei)
	}
	return nil
}

// storeUnsigned records the payload and fees of the latest unsigned build, so
// replacement and cancel never depend on the node remembering the transaction.
func (a *Adapter) storeUnsigned(ctx context.Context, tx pgx.Tx, addr string, nonce uint64, u chain.UnsignedTx, tip, feeCap *big.Int) error {
	_, err := tx.Exec(ctx, `UPDATE evm_nonce_allocations SET payload=$4, max_priority_fee_per_gas=$5, max_fee_per_gas=$6, updated_at=now()
		WHERE chain=$1 AND address=$2 AND nonce=$3`, a.cfg.Chain, addr, int64(nonce), u.Payload, tip.String(), feeCap.String())
	if err != nil {
		return fmt.Errorf("evm: store payload: %w", err)
	}
	return nil
}

// BuildReplacement rebuilds the transaction owned by (ownerKind, ownerID) at the
// same nonce from the stored payload, with both fee fields raised by at least
// FeeBumpPercent. It reads nothing from the node.
func (a *Adapter) BuildReplacement(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (chain.UnsignedTx, error) {
	r, err := a.lockOpenAllocation(ctx, tx, ownerKind, ownerID)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	if !r.sent {
		return chain.UnsignedTx{}, fmt.Errorf("evm: %s %s was never broadcast; rebuild it instead of replacing it", ownerKind, ownerID)
	}
	pl, err := decodePayload(r.payload)
	if err != nil {
		return chain.UnsignedTx{}, fmt.Errorf("evm: stored payload of %s %s: %w", ownerKind, ownerID, err)
	}
	params, from, err := pl.params()
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	tip, feeCap, _, err := a.fees(ctx)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	params.GasTipCap, params.GasFeeCap = a.bump(r.tip, tip), a.bump(r.feeCap, feeCap)
	if params.GasTipCap.Cmp(params.GasFeeCap) > 0 {
		params.GasFeeCap = new(big.Int).Set(params.GasTipCap)
	}
	if err := a.checkFee(params.Gas, params.GasFeeCap); err != nil {
		return chain.UnsignedTx{}, err
	}
	u, err := a.unsigned(params, from, a.cfg.partitionOf(from))
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return u, a.storeUnsigned(ctx, tx, r.addr, params.Nonce, u, params.GasTipCap, params.GasFeeCap)
}

// BuildCancel builds a zero-value, 21,000-gas self-send at the owner's nonce, to
// free a nonce whose job was refused (nonces are strictly sequential, so one
// stuck nonce blocks every later one). If the allocation was broadcast the fees
// are bumped as in a replacement. When it confirms the allocation is 'cancelled'.
func (a *Adapter) BuildCancel(ctx context.Context, tx pgx.Tx, ownerKind, ownerID string) (chain.UnsignedTx, error) {
	r, err := a.lockOpenAllocation(ctx, tx, ownerKind, ownerID)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	from := common.HexToAddress(r.addr)
	tip, feeCap, _, err := a.fees(ctx)
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	if r.sent {
		tip, feeCap = a.bump(r.tip, tip), a.bump(r.feeCap, feeCap)
		if tip.Cmp(feeCap) > 0 {
			feeCap = new(big.Int).Set(tip)
		}
	}
	if err := a.checkFee(DefaultCancelGas, feeCap); err != nil {
		return chain.UnsignedTx{}, err
	}
	u, err := a.unsigned(eth.TxParams{
		ChainID: new(big.Int).SetUint64(a.cfg.ChainID), Nonce: uint64(r.nonce), To: from, Value: new(big.Int),
		Gas: DefaultCancelGas, GasTipCap: tip, GasFeeCap: feeCap,
	}, from, a.cfg.partitionOf(from))
	if err != nil {
		return chain.UnsignedTx{}, err
	}
	return u, a.storeUnsigned(ctx, tx, r.addr, uint64(r.nonce), u, tip, feeCap)
}

// Assemble attaches sig (64 bytes r||s, or 65 bytes r||s||v with v in
// {0,1,27,28}) to the payload's transaction. S is normalized to low-S and the
// recovery id is chosen so that the signature recovers to the payload's sender.
func (a *Adapter) Assemble(u chain.UnsignedTx, sig chain.Signature) (chain.SignedTx, error) {
	pl, err := decodePayload(u.Payload)
	if err != nil {
		return chain.SignedTx{}, err
	}
	txn, digest, from, err := pl.tx()
	if err != nil {
		return chain.SignedTx{}, err
	}
	if string(digest[:]) != string(u.Digest) {
		return chain.SignedTx{}, errors.New("evm: payload does not match digest")
	}
	if pl.ChainID != a.cfg.ChainID {
		return chain.SignedTx{}, fmt.Errorf("evm: payload chain id %d", pl.ChainID)
	}
	if len(sig.Bytes) != 64 && len(sig.Bytes) != 65 {
		return chain.SignedTx{}, fmt.Errorf("evm: signature is %d bytes, want 64 or 65", len(sig.Bytes))
	}
	norm := signer.NormalizeLowS(signer.Signature{
		R: new(big.Int).SetBytes(sig.Bytes[:32]), S: new(big.Int).SetBytes(sig.Bytes[32:64]),
	})
	sig65 := make([]byte, 65)
	norm.R.FillBytes(sig65[:32])
	norm.S.FillBytes(sig65[32:64])
	var signed *types.Transaction
	for v := byte(0); v <= 1; v++ {
		sig65[64] = v
		pub, err := crypto.Ecrecover(digest[:], sig65)
		if err != nil || common.BytesToAddress(crypto.Keccak256(pub[1:])[12:]) != from {
			continue
		}
		if signed, err = txn.WithSignature(types.LatestSignerForChainID(txn.ChainId()), sig65); err != nil {
			return chain.SignedTx{}, err
		}
		break
	}
	if signed == nil {
		return chain.SignedTx{}, eth.ErrSenderMismatch
	}
	if err := eth.VerifySender(signed, from); err != nil {
		return chain.SignedTx{}, err
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return chain.SignedTx{}, err
	}
	return chain.SignedTx{Chain: a.cfg.Chain, Raw: raw}, nil
}

// Broadcast sends the transaction. "Already known" counts as success. The
// allocation row learns the hash first, so a crash after sending cannot lose it.
func (a *Adapter) Broadcast(ctx context.Context, s chain.SignedTx) (string, error) {
	t, err := eth.DecodeRaw(s.Raw)
	if err != nil {
		return "", err
	}
	if t.ChainId().Uint64() != a.cfg.ChainID {
		return "", fmt.Errorf("evm: transaction chain id %s, want %d", t.ChainId(), a.cfg.ChainID)
	}
	from, err := types.Sender(types.LatestSignerForChainID(t.ChainId()), t)
	if err != nil {
		return "", fmt.Errorf("evm: recover sender: %w", err)
	}
	if err := a.recordBroadcast(ctx, from, t); err != nil {
		return "", err
	}
	if err := a.ec.SendTransaction(ctx, t); err != nil {
		msg := strings.ToLower(err.Error())
		switch {
		case strings.Contains(msg, "already known") || strings.Contains(msg, "known transaction") || strings.Contains(msg, "already imported"):
		case strings.Contains(msg, "nonce too low"):
			// Fine only if this very transaction is the one that mined.
			if r, rerr := a.ec.TransactionReceipt(ctx, t.Hash()); rerr != nil || r == nil {
				return "", fmt.Errorf("evm: broadcast: %w", err)
			}
		default:
			return "", fmt.Errorf("evm: broadcast: %w", err)
		}
	}
	return t.Hash().Hex(), nil
}

// recordBroadcast inserts the attempt (before sending, so a crash cannot lose
// the hash) and points the allocation at it. A transaction whose nonce has no
// allocation is an error: an unknown nonce is never sent.
func (a *Adapter) recordBroadcast(ctx context.Context, from common.Address, t *types.Transaction) error {
	h := t.Hash().Hex()
	kind := "send"
	if t.To() != nil && *t.To() == from && t.Value().Sign() == 0 && len(t.Data()) == 0 {
		kind = "cancel"
	}
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `INSERT INTO evm_tx_attempts (tx_hash, chain, address, nonce, kind) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (tx_hash) DO NOTHING`, h, a.cfg.Chain, from.Hex(), int64(t.Nonce()), kind); err != nil {
		return fmt.Errorf("evm: record attempt: %w", err)
	}
	ct, err := tx.Exec(ctx, `UPDATE evm_nonce_allocations SET
		status = CASE WHEN status IN ('confirmed','cancelled') THEN status ELSE 'broadcast' END,
		tx_hash = CASE WHEN status IN ('confirmed','cancelled') THEN tx_hash ELSE $4 END,
		max_priority_fee_per_gas = $5, max_fee_per_gas = $6, updated_at = now()
		WHERE chain=$1 AND address=$2 AND nonce=$3`,
		a.cfg.Chain, from.Hex(), int64(t.Nonce()), h, t.GasTipCap().String(), t.GasFeeCap().String())
	if err != nil {
		return fmt.Errorf("evm: record broadcast: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("evm: refusing to broadcast: no nonce allocation for %s nonce %d", from.Hex(), t.Nonce())
	}
	return tx.Commit(ctx)
}

// safeHead is the highest block that has Confirmations blocks on top of it.
func (a *Adapter) safeHead(ctx context.Context) (head, safe uint64, ok bool, err error) {
	head, err = a.ec.BlockNumber(ctx)
	if err != nil {
		return 0, 0, false, fmt.Errorf("evm: block number: %w", err)
	}
	if head < a.cfg.Confirmations {
		return head, 0, false, nil
	}
	return head, head - a.cfg.Confirmations, true, nil
}

// Status reports a transaction's state. Confirmed needs Confirmations blocks on
// top of the mining block; failed is receipt status 0; dropped is no receipt
// while the sender's confirmed nonce has passed the transaction's nonce.
func (a *Adapter) Status(ctx context.Context, txHash string) (chain.TxStatus, error) {
	h := common.HexToHash(txHash)
	r, err := a.ec.TransactionReceipt(ctx, h)
	switch {
	case err == nil:
		_, safe, ok, serr := a.safeHead(ctx)
		if serr != nil {
			return "", serr
		}
		final := ok && r.BlockNumber.Uint64() <= safe
		if final {
			a.finalize(ctx, h.Hex())
		}
		if r.Status != types.ReceiptStatusSuccessful {
			return chain.TxFailed, nil
		}
		if final {
			return chain.TxConfirmed, nil
		}
		return chain.TxPending, nil
	case !errors.Is(err, ethereum.NotFound):
		return "", fmt.Errorf("evm: receipt: %w", err)
	}
	// No receipt: pending in the node's pool, or dropped.
	if _, pending, err := a.ec.TransactionByHash(ctx, h); err == nil && pending {
		return chain.TxPending, nil
	}
	var addr string
	var nonce int64
	err = a.pool.QueryRow(ctx, `SELECT address, nonce FROM evm_tx_attempts WHERE chain=$1 AND tx_hash=$2`,
		a.cfg.Chain, h.Hex()).Scan(&addr, &nonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return chain.TxPending, nil
	}
	if err != nil {
		return "", err
	}
	n, err := a.ec.NonceAt(ctx, common.HexToAddress(addr), nil)
	if err != nil {
		return "", fmt.Errorf("evm: nonce: %w", err)
	}
	if n > uint64(nonce) {
		return chain.TxDropped, nil
	}
	return chain.TxPending, nil
}

// finalize marks the allocation of a final transaction: 'cancelled' when the
// mined attempt was a cancel, else 'confirmed' (a reverted transaction still
// consumed its nonce).
func (a *Adapter) finalize(ctx context.Context, txHash string) {
	_, _ = a.pool.Exec(ctx, `UPDATE evm_nonce_allocations al
		SET status = CASE WHEN at.kind = 'cancel' THEN 'cancelled' ELSE 'confirmed' END, tx_hash = at.tx_hash, updated_at = now()
		FROM evm_tx_attempts at
		WHERE at.chain=$1 AND at.tx_hash=$2 AND al.chain=at.chain AND al.address=at.address AND al.nonce=at.nonce
		  AND al.status IN ('allocated','broadcast')`, a.cfg.Chain, txHash)
}

// EstimateSweepFee is eth_estimateGas of the sweep call times the current
// (base fee + tip), in wei.
func (a *Adapter) EstimateSweepFee(ctx context.Context, s chain.SweepIntent) (*big.Int, error) {
	from := a.cfg.SweepDestination
	if s.ToPartition != "" {
		var err error
		if from, err = a.cfg.hot(s.ToPartition); err != nil {
			return nil, err
		}
	}
	data, err := a.sweepData(ctx, a.pool, s)
	if err != nil {
		return nil, err
	}
	gas, err := a.estimate(ctx, from, a.cfg.Factory, new(big.Int), data)
	if err != nil {
		return nil, err
	}
	tip, _, base, err := a.fees(ctx)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Mul(new(big.Int).SetUint64(gas), new(big.Int).Add(base, tip)), nil
}
