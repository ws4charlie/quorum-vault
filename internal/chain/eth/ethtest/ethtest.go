// Package ethtest is the test side of internal/chain/eth: Assemble turns a backend's (r, s) into a signed transaction (it finds the
// recovery id v), and Client is a small JSON-RPC client that fills nonce and fees, broadcasts and waits for a receipt. Production signs and
// broadcasts through the chain adapter (internal/chain/evm); only tests and test harnesses import this package.
//
// Signers (HSM and MPC) return only (r, s). Ethereum also needs v, the recovery id (0 or 1) that tells a verifier which of the two candidate
// public keys for r is the signer's. Assemble tries both values and keeps the one that recovers the key's public key.
package ethtest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

// ErrNoRecoveryID: the signature recovers to neither candidate key.
var ErrNoRecoveryID = errors.New("eth: signature does not recover to the key (no recovery id fits)")

// Signed is an assembled transaction ready to broadcast.
type Signed struct {
	Tx    *types.Transaction
	Sig65 []byte // r || s || v, v in {0,1}
	Raw   []byte // EIP-2718 envelope: 0x02 || rlp(...)
	Hash  common.Hash
	From  common.Address
}

// Assemble attaches sig to tx. S is normalized to low-S first (EIP-2 rejects
// high-S; flipping S also flips the recovery id, so normalizing before the
// search keeps the two consistent). The recovery id is the v in {0,1} for
// which ecrecover(digest, r||s||v) equals pub. The result's sender is checked
// against pub's address before it is returned.
func Assemble(tx *types.Transaction, sig signer.Signature, pub *ecdsa.PublicKey) (Signed, error) {
	if sig.R == nil || sig.S == nil || pub == nil {
		return Signed{}, errors.New("eth: nil signature or public key")
	}
	sig = signer.NormalizeLowS(sig)
	digest := eth.Digest(tx)
	if !signer.Verify(pub, digest, sig) {
		return Signed{}, errors.New("eth: signature does not verify against the public key")
	}
	want := crypto.FromECDSAPub(pub)
	sig65 := make([]byte, 65)
	sig.R.FillBytes(sig65[0:32])
	sig.S.FillBytes(sig65[32:64])
	found := false
	for v := byte(0); v <= 1; v++ {
		sig65[64] = v
		got, err := crypto.Ecrecover(digest[:], sig65)
		if err == nil && bytes.Equal(got, want) {
			found = true
			break
		}
	}
	if !found {
		return Signed{}, ErrNoRecoveryID
	}
	s := types.LatestSignerForChainID(tx.ChainId())
	signed, err := tx.WithSignature(s, sig65)
	if err != nil {
		return Signed{}, fmt.Errorf("eth: attach signature: %w", err)
	}
	from := crypto.PubkeyToAddress(*pub)
	if err := eth.VerifySender(signed, from); err != nil {
		return Signed{}, err
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return Signed{}, fmt.Errorf("eth: encode: %w", err)
	}
	return Signed{Tx: signed, Sig65: sig65, Raw: raw, Hash: signed.Hash(), From: from}, nil
}

// Client is an optional JSON-RPC connection used to fill
// nonce/fees and to broadcast.
type Client struct {
	ec      *ethclient.Client
	chainID *big.Int
}

// Dial connects to rpcURL and reads its chain id.
func Dial(ctx context.Context, rpcURL string) (*Client, error) {
	ec, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("eth: dial: %w", err)
	}
	id, err := ec.ChainID(ctx)
	if err != nil {
		ec.Close()
		return nil, fmt.Errorf("eth: chain id: %w", err)
	}
	return &Client{ec: ec, chainID: id}, nil
}

func (c *Client) ChainID() *big.Int { return new(big.Int).Set(c.chainID) }
func (c *Client) Close()            { c.ec.Close() }

// Suggest returns the pending nonce of from and EIP-1559 fees:
// tip = node suggestion, fee cap = 2 * base fee + tip.
func (c *Client) Suggest(ctx context.Context, from common.Address) (nonce uint64, tip, feeCap *big.Int, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if nonce, err = c.ec.PendingNonceAt(ctx, from); err != nil {
		return 0, nil, nil, fmt.Errorf("eth: nonce: %w", err)
	}
	if tip, err = c.ec.SuggestGasTipCap(ctx); err != nil {
		return 0, nil, nil, fmt.Errorf("eth: tip: %w", err)
	}
	h, err := c.ec.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("eth: header: %w", err)
	}
	base := h.BaseFee
	if base == nil {
		base = new(big.Int)
	}
	feeCap = new(big.Int).Add(new(big.Int).Mul(base, big.NewInt(2)), tip)
	return nonce, tip, feeCap, nil
}

// Broadcast sends a raw signed transaction and returns its hash.
func (c *Client) Broadcast(ctx context.Context, raw []byte) (common.Hash, error) {
	tx, err := eth.DecodeRaw(raw)
	if err != nil {
		return common.Hash{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := c.ec.SendTransaction(ctx, tx); err != nil {
		return common.Hash{}, fmt.Errorf("eth: broadcast: %w", err)
	}
	return tx.Hash(), nil
}

// WaitReceipt polls for the receipt of hash every poll interval (0 = 200 ms)
// until it is mined or ctx ends. A mined tx with status 0 (reverted) is
// returned without error; the caller checks receipt.Status.
func (c *Client) WaitReceipt(ctx context.Context, hash common.Hash, poll time.Duration) (*types.Receipt, error) {
	if poll <= 0 {
		poll = 200 * time.Millisecond
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		r, err := c.ec.TransactionReceipt(ctx, hash)
		if err == nil {
			return r, nil
		}
		if !errors.Is(err, ethereum.NotFound) {
			return nil, fmt.Errorf("eth: receipt %s: %w", hash.Hex(), err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("eth: receipt %s: %w", hash.Hex(), ctx.Err())
		case <-t.C:
		}
	}
}
