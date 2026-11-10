// Package chainfactory is the one place where a chain family picks its parts of the business zone: the chain.Adapter
// that builds, broadcasts and tracks transactions, and the custody.Reader that reads balances and heights. qv-core and
// qv-worker open their chain through it, so a new family is added here and nowhere else in the commands. (The signing
// zone picks its codec the same way, in gateway.NewCodec, for qv-gateway and qv-cosigner.)
package chainfactory

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/custody"
)

// Backend is what a chain family gives the business zone.
type Backend struct {
	Adapter chain.Adapter
	Reader  custody.Reader
	closers []func()
}

// Close releases the connections of the backend.
func (b *Backend) Close() {
	for i := len(b.closers) - 1; i >= 0; i-- {
		b.closers[i]()
	}
}

// Open connects the chain of cfg. An unknown family is an error: the process must not start.
func Open(ctx context.Context, cfg *custody.Config, pool *pgxpool.Pool) (*Backend, error) {
	switch cfg.Family {
	case "", custody.FamilyEVM:
		adapter, err := evm.New(ctx, cfg.EVM, pool)
		if err != nil {
			return nil, err
		}
		reader, err := custody.NewEVMReader(ctx, cfg)
		if err != nil {
			adapter.Close()
			return nil, err
		}
		return &Backend{Adapter: adapter, Reader: reader, closers: []func(){adapter.Close, reader.Close}}, nil
	case custody.FamilyBTC:
		adapter, err := btc.New(ctx, cfg.BTC, pool)
		if err != nil {
			return nil, err
		}
		return &Backend{Adapter: adapter, Reader: adapter, closers: []func(){adapter.Close}}, nil
	case custody.FamilySOL:
		adapter, err := sol.New(ctx, cfg.SOL, pool)
		if err != nil {
			return nil, err
		}
		return &Backend{Adapter: adapter, Reader: adapter, closers: []func(){adapter.Close}}, nil
	}
	return nil, fmt.Errorf("chainfactory: chain %q: unknown chain family %q", cfg.Chain, cfg.Family)
}
