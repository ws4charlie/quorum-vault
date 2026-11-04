package evm

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

const (
	logChunkBlocks = 2000 // block span per eth_getLogs call
	logChunkAddrs  = 200  // topic-2 addresses per eth_getLogs call
	scanWorkers    = 8
)

type depositAddr struct {
	asset string // empty: any asset
}

func (a *Adapter) depositSet(ctx context.Context) (map[common.Address]depositAddr, error) {
	rows, err := a.pool.Query(ctx, `SELECT address, COALESCE(asset,'') FROM deposit_addresses WHERE chain=$1`, a.cfg.Chain)
	if err != nil {
		return nil, fmt.Errorf("evm: read deposit addresses: %w", err)
	}
	defer rows.Close()
	set := map[common.Address]depositAddr{}
	for rows.Next() {
		var addr, asset string
		if err := rows.Scan(&addr, &asset); err != nil {
			return nil, err
		}
		if common.IsHexAddress(addr) {
			set[common.HexToAddress(addr)] = depositAddr{asset: asset}
		}
	}
	return set, rows.Err()
}

// Scan returns deposits in [fromHeight, safe head], where safe head = head -
// Confirmations. It is stateless and repeatable: the same range always returns
// the same deposits with the same DedupKeys.
//
// ERC-20: Transfer logs of configured tokens whose `to` is a deposit address.
// Native: successful transactions whose `to` is a deposit address and whose value
// is > 0. ETH is not forwarded on receipt (the forwarder's receive() is empty), so a
// deposit looks the same before and after the forwarder is deployed. Limit: ETH that reaches a deposit address through an internal call
// from another contract (no top-level transaction to it) is not seen here and
// is left to balance reconciliation.
func (a *Adapter) Scan(ctx context.Context, fromHeight uint64) (chain.ScanResult, error) {
	_, safe, ok, err := a.safeHead(ctx)
	if err != nil {
		return chain.ScanResult{}, err
	}
	res := chain.ScanResult{SafeHeadHeight: safe}
	if !ok || fromHeight > safe {
		return res, nil
	}
	set, err := a.depositSet(ctx)
	if err != nil {
		return res, err
	}
	if len(set) == 0 {
		return res, nil
	}
	erc, err := a.scanTokens(ctx, set, fromHeight, safe)
	if err != nil {
		return res, err
	}
	nat, err := a.scanNative(ctx, set, fromHeight, safe)
	if err != nil {
		return res, err
	}
	res.Deposits = append(erc, nat...)
	sort.SliceStable(res.Deposits, func(i, j int) bool {
		if res.Deposits[i].BlockHeight != res.Deposits[j].BlockHeight {
			return res.Deposits[i].BlockHeight < res.Deposits[j].BlockHeight
		}
		return res.Deposits[i].DedupKey < res.Deposits[j].DedupKey
	})
	return res, nil
}

func (a *Adapter) scanTokens(ctx context.Context, set map[common.Address]depositAddr, from, to uint64) ([]chain.ObservedDeposit, error) {
	if len(a.cfg.Assets) == 0 {
		return nil, nil
	}
	if err := loadABIs(); err != nil {
		return nil, err
	}
	var tokens []common.Address
	for _, t := range a.cfg.Assets {
		tokens = append(tokens, t.Address)
	}
	sort.Slice(tokens, func(i, j int) bool { return strings.Compare(tokens[i].Hex(), tokens[j].Hex()) < 0 })
	var addrs []common.Hash
	for ad := range set {
		addrs = append(addrs, common.BytesToHash(ad.Bytes()))
	}
	sort.Slice(addrs, func(i, j int) bool { return strings.Compare(addrs[i].Hex(), addrs[j].Hex()) < 0 })
	topic := erc20ABI.Events["Transfer"].ID

	var out []chain.ObservedDeposit
	for lo := from; lo <= to; lo += logChunkBlocks {
		hi := min(lo+logChunkBlocks-1, to)
		for i := 0; i < len(addrs); i += logChunkAddrs {
			part := addrs[i:min(i+logChunkAddrs, len(addrs))]
			logs, err := a.ec.FilterLogs(ctx, ethereum.FilterQuery{
				FromBlock: new(big.Int).SetUint64(lo), ToBlock: new(big.Int).SetUint64(hi),
				Addresses: tokens, Topics: [][]common.Hash{{topic}, nil, part},
			})
			if err != nil {
				return nil, fmt.Errorf("evm: filter logs: %w", err)
			}
			for _, l := range logs {
				if l.Removed || len(l.Topics) != 3 || len(l.Data) != 32 {
					continue // not an ERC-20 Transfer (ERC-721 has 4 topics)
				}
				sym, known := a.cfg.symbolOf(l.Address)
				to := common.BytesToAddress(l.Topics[2].Bytes())
				meta, isDeposit := set[to]
				amt := new(big.Int).SetBytes(l.Data)
				if !known || !isDeposit || amt.Sign() == 0 || (meta.asset != "" && meta.asset != sym) {
					continue
				}
				out = append(out, chain.ObservedDeposit{
					Chain: a.cfg.Chain, Asset: sym, Address: to.Hex(), Amount: amt, BlockHeight: l.BlockNumber,
					TxHash: l.TxHash.Hex(), DedupKey: fmt.Sprintf("%s:%s:%d", a.cfg.Chain, strings.ToLower(l.TxHash.Hex()), l.Index),
				})
			}
		}
	}
	return out, nil
}

func (a *Adapter) scanNative(ctx context.Context, set map[common.Address]depositAddr, from, to uint64) ([]chain.ObservedDeposit, error) {
	n := int(to - from + 1)
	blocks := make([][]chain.ObservedDeposit, n)
	errs := make([]error, n)
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < scanWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				blocks[i], errs[i] = a.nativeInBlock(ctx, set, from+uint64(i))
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
	var out []chain.ObservedDeposit
	for i := range blocks {
		if errs[i] != nil {
			return nil, errs[i]
		}
		out = append(out, blocks[i]...)
	}
	return out, nil
}

func (a *Adapter) nativeInBlock(ctx context.Context, set map[common.Address]depositAddr, height uint64) ([]chain.ObservedDeposit, error) {
	b, err := a.ec.BlockByNumber(ctx, new(big.Int).SetUint64(height))
	if err != nil {
		return nil, fmt.Errorf("evm: block %d: %w", height, err)
	}
	var out []chain.ObservedDeposit
	for _, t := range b.Transactions() {
		if t.To() == nil || t.Value().Sign() == 0 {
			continue
		}
		meta, ok := set[*t.To()]
		if !ok || (meta.asset != "" && meta.asset != a.cfg.NativeAsset) {
			continue
		}
		r, err := a.ec.TransactionReceipt(ctx, t.Hash())
		if err != nil {
			return nil, fmt.Errorf("evm: receipt %s: %w", t.Hash(), err)
		}
		if r.Status != types.ReceiptStatusSuccessful {
			continue // reverted: no value moved
		}
		out = append(out, chain.ObservedDeposit{
			Chain: a.cfg.Chain, Asset: a.cfg.NativeAsset, Address: t.To().Hex(), Amount: new(big.Int).Set(t.Value()),
			BlockHeight: height, TxHash: t.Hash().Hex(),
			DedupKey: fmt.Sprintf("%s:%s:native", a.cfg.Chain, strings.ToLower(t.Hash().Hex())),
		})
	}
	return out, nil
}
