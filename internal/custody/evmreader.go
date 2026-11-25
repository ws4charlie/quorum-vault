package custody

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"strings"
)

// EVMReader is the Reader for an EVM node.
type EVMReader struct {
	cfg *Config
	ec  *ethclient.Client
	erc abi.ABI
}

var _ Reader = (*EVMReader)(nil)

const balanceOfABI = `[{"type":"function","name":"balanceOf","inputs":[{"name":"a","type":"address"}],"outputs":[{"type":"uint256"}],"stateMutability":"view"}]`

// NewEVMReader dials cfg.EVM.RPCURL.
func NewEVMReader(ctx context.Context, cfg *Config) (*EVMReader, error) {
	ec, err := ethclient.DialContext(ctx, cfg.EVM.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("custody: dial: %w", err)
	}
	a, err := abi.JSON(strings.NewReader(balanceOfABI))
	if err != nil {
		return nil, err
	}
	return &EVMReader{cfg: cfg, ec: ec, erc: a}, nil
}

// Close releases the connection.
func (r *EVMReader) Close() { r.ec.Close() }

// SafeHead is head minus the configured confirmations.
func (r *EVMReader) SafeHead(ctx context.Context) (uint64, error) {
	h, err := r.ec.BlockNumber(ctx)
	if err != nil {
		return 0, err
	}
	if h < r.cfg.EVM.Confirmations {
		return 0, nil
	}
	return h - r.cfg.EVM.Confirmations, nil
}

// TxBlock is the block number of a mined transaction.
func (r *EVMReader) TxBlock(ctx context.Context, txHash string) (uint64, error) {
	rc, err := r.ec.TransactionReceipt(ctx, common.HexToHash(txHash))
	if err != nil {
		return 0, fmt.Errorf("custody: receipt %s: %w", txHash, err)
	}
	return rc.BlockNumber.Uint64(), nil
}

// Balance of address in asset at height (native: eth_getBalance, token: balanceOf).
func (r *EVMReader) Balance(ctx context.Context, address, asset string, height uint64) (*big.Int, error) {
	a, ok := r.cfg.Assets[asset]
	if !ok {
		return nil, fmt.Errorf("custody: unknown asset %q", asset)
	}
	at := new(big.Int).SetUint64(height)
	addr := common.HexToAddress(address)
	if a.Native() {
		return r.ec.BalanceAt(ctx, addr, at)
	}
	data, err := r.erc.Pack("balanceOf", addr)
	if err != nil {
		return nil, err
	}
	out, err := r.ec.CallContract(ctx, ethereum.CallMsg{To: &a.Address, Data: data}, at)
	if err != nil {
		return nil, fmt.Errorf("custody: balanceOf %s: %w", asset, err)
	}
	return new(big.Int).SetBytes(out), nil
}

var _ ReceiptReader = (*EVMReader)(nil)

// Receipt reads the receipt of a transaction: its block, whether it succeeded and what it paid in gas. found is false while the node has none.
func (r *EVMReader) Receipt(ctx context.Context, txHash string) (Receipt, bool, error) {
	rc, err := r.ec.TransactionReceipt(ctx, common.HexToHash(txHash))
	if errors.Is(err, ethereum.NotFound) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, fmt.Errorf("custody: receipt %s: %w", txHash, err)
	}
	out := Receipt{Block: rc.BlockNumber.Uint64(), Success: rc.Status == types.ReceiptStatusSuccessful}
	if rc.EffectiveGasPrice != nil {
		out.Fee = new(big.Int).Mul(new(big.Int).SetUint64(rc.GasUsed), rc.EffectiveGasPrice)
	}
	return out, true, nil
}

// authorizationUsedTopic is keccak256("AuthorizationUsed(address,bytes32)"), the event of EIP-3009 tokens (Circle USDC among them).
var authorizationUsedTopic = crypto.Keccak256Hash([]byte("AuthorizationUsed(address,bytes32)"))

// x402LogChunk is the block span of one eth_getLogs call (public RPC nodes limit it).
const x402LogChunk = 2000

var _ AuthorizationReader = (*EVMReader)(nil)

// AuthorizationsUsed implements AuthorizationReader: the AuthorizationUsed events of the token configured as asset, for payer, in blocks [from, to].
func (r *EVMReader) AuthorizationsUsed(ctx context.Context, asset, payer string, from, to uint64) ([]UsedAuthorization, error) {
	a, ok := r.cfg.Assets[asset]
	if !ok || a.Native() {
		return nil, fmt.Errorf("custody: %q is not a token", asset)
	}
	var out []UsedAuthorization
	for lo := from; lo <= to; lo += x402LogChunk {
		hi := min(lo+x402LogChunk-1, to)
		logs, err := r.ec.FilterLogs(ctx, ethereum.FilterQuery{FromBlock: new(big.Int).SetUint64(lo), ToBlock: new(big.Int).SetUint64(hi),
			Addresses: []common.Address{a.Address}, Topics: [][]common.Hash{{authorizationUsedTopic}, {common.BytesToHash(common.HexToAddress(payer).Bytes())}}})
		if err != nil {
			return nil, fmt.Errorf("custody: filter AuthorizationUsed: %w", err)
		}
		for _, l := range logs {
			if l.Removed || len(l.Topics) != 3 {
				continue
			}
			out = append(out, UsedAuthorization{Nonce: "0x" + hex.EncodeToString(l.Topics[2].Bytes()), Block: l.BlockNumber, TxHash: l.TxHash.Hex()})
		}
	}
	return out, nil
}

// BlockTime implements AuthorizationReader.
func (r *EVMReader) BlockTime(ctx context.Context, height uint64) (uint64, error) {
	h, err := r.ec.HeaderByNumber(ctx, new(big.Int).SetUint64(height))
	if err != nil {
		return 0, fmt.Errorf("custody: header %d: %w", height, err)
	}
	return h.Time, nil
}
