package evm

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// sweptTopic is keccak256("Swept(address,uint256)"), the Forwarder's event.
var sweptTopic = crypto.Keccak256Hash([]byte("Swept(address,uint256)"))

// TxFee is the fee the mined transaction paid: gas used x effective gas price, plus the L1 data fee on an OP-stack chain (ParseReceipt). A
// reverted transaction paid its fee too, so the receipt status is not checked.
func (a *Adapter) TxFee(ctx context.Context, txHash string) (*big.Int, error) {
	_, fee, err := a.receipt(ctx, txHash)
	if err != nil {
		return nil, err
	}
	if fee == nil {
		return nil, fmt.Errorf("evm: receipt of %s has no effective gas price", txHash)
	}
	return fee, nil
}

// MovedAssets reads the Forwarder Swept events of a successful transaction. An
// event counts only if its emitter is a forwarder we derived (a row of
// deposit_addresses): anyone can deploy a contract that emits the same
// event. Tokens that are not configured assets are ignored. A reverted
// transaction moved nothing. Entries come in log order; one address and asset
// can appear twice if the transaction flushed it twice.
func (a *Adapter) MovedAssets(ctx context.Context, txHash string) ([]chain.MovedAsset, error) {
	r, _, err := a.receipt(ctx, txHash)
	if err != nil {
		return nil, err
	}
	if r.Status != types.ReceiptStatusSuccessful {
		return nil, nil
	}
	known := map[common.Address]bool{}
	var out []chain.MovedAsset
	for _, l := range r.Logs {
		if l.Removed || len(l.Topics) != 2 || l.Topics[0] != sweptTopic || len(l.Data) != 32 {
			continue
		}
		ok, seen := known[l.Address]
		if !seen {
			if ok, err = a.isForwarder(ctx, l.Address); err != nil {
				return nil, err
			}
			known[l.Address] = ok
		}
		if !ok {
			continue
		}
		token := common.BytesToAddress(l.Topics[1].Bytes())
		asset := a.cfg.NativeAsset
		if token != (common.Address{}) {
			sym, found := a.cfg.symbolOf(token)
			if !found {
				continue
			}
			asset = sym
		}
		amt := new(big.Int).SetBytes(l.Data)
		if amt.Sign() == 0 {
			continue
		}
		out = append(out, chain.MovedAsset{Address: l.Address.Hex(), Asset: asset, Amount: amt})
	}
	return out, nil
}

func (a *Adapter) isForwarder(ctx context.Context, addr common.Address) (bool, error) {
	var n int
	err := a.pool.QueryRow(ctx, `SELECT count(*) FROM deposit_addresses WHERE chain=$1 AND address=$2 AND kind='forwarder'`,
		a.cfg.Chain, addr.Hex()).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("evm: look up forwarder %s: %w", addr.Hex(), err)
	}
	return n > 0, nil
}

func (a *Adapter) receipt(ctx context.Context, txHash string) (*types.Receipt, *big.Int, error) {
	r, fee, err := ReadReceipt(ctx, a.ec.Client(), common.HexToHash(txHash), a.cfg.L1FeeModeOf())
	if errors.Is(err, ethereum.NotFound) {
		return nil, nil, fmt.Errorf("evm: %s has no receipt yet", txHash)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("evm: receipt %s: %w", txHash, err)
	}
	return r, fee, nil
}
