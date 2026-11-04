package custody

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
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
