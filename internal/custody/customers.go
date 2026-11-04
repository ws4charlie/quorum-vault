package custody

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidID reports whether s is usable as a customer ID (it is embedded in ledger account IDs).
func ValidID(s string) bool { return idPattern.MatchString(s) }

// Customer is a customer record.
type Customer struct {
	ID      string `json:"id"`
	USState string `json:"us_state,omitempty"`
}

// CreateCustomer is idempotent by ID: creating an existing customer returns it.
// It also opens the customer's ledger accounts.
func (s *Service) CreateCustomer(ctx context.Context, actor, id, usState string) (Customer, bool, error) {
	if !ValidID(id) {
		return Customer{}, false, fmt.Errorf("%w: customer id must match %s", ErrInvalid, idPattern)
	}
	created := false
	err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO customers (id, entity, us_state) VALUES ($1,$2,NULLIF($3,'')) ON CONFLICT (id) DO NOTHING`, id, s.Cfg.Entity, usState)
		if err != nil {
			return err
		}
		created = tag.RowsAffected() == 1
		for _, sym := range s.Cfg.AssetList {
			if err := s.ensureCustomerAccount(ctx, tx, id, sym); err != nil {
				return err
			}
		}
		if created {
			return emit(ctx, tx, outbox.TopicAudit, "customer:"+id, "customer.created", map[string]any{"actor": actor, "customer": id})
		}
		return nil
	})
	if err != nil {
		return Customer{}, false, err
	}
	return Customer{ID: id, USState: usState}, created, nil
}

// DepositAddress is a customer's deposit address on a chain.
type DepositAddress struct {
	Customer string `json:"customer"`
	Chain    string `json:"chain"`
	Address  string `json:"address"`
	Kind     string `json:"kind"`
}

// EnsureDepositAddress returns the customer's address on the chain, creating
// it on first use. One address per customer per chain; repeat calls return it.
func (s *Service) EnsureDepositAddress(ctx context.Context, actor, customer, chainName string) (DepositAddress, error) {
	if chainName != s.Cfg.Chain {
		return DepositAddress{}, fmt.Errorf("%w: unknown chain %q", ErrInvalid, chainName)
	}
	var exists bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM customers WHERE id=$1)`, customer).Scan(&exists); err != nil {
		return DepositAddress{}, err
	}
	if !exists {
		return DepositAddress{}, fmt.Errorf("%w: customer %q", ErrNotFound, customer)
	}
	d, err := s.Chain.DeriveDepositAddress(ctx, customer, 0)
	if err != nil {
		return DepositAddress{}, err
	}
	out := DepositAddress{Customer: customer, Chain: d.Chain, Address: d.Address, Kind: d.Kind}
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO deposit_addresses (customer_id, chain, asset, address, derivation_index, kind)
			VALUES ($1,$2,NULL,$3,$4,$5) ON CONFLICT (customer_id, chain) DO NOTHING`,
			customer, d.Chain, d.Address, int64(d.DerivationIndex), d.Kind)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		return emit(ctx, tx, outbox.TopicAudit, "deposit-address:"+d.Address, "deposit_address.created",
			map[string]any{"actor": actor, "customer": customer, "chain": d.Chain, "address": d.Address})
	})
	if err != nil {
		return DepositAddress{}, err
	}
	// The row that won may predate this call (same customer, same chain): read it back.
	err = s.Pool.QueryRow(ctx, `SELECT address, kind FROM deposit_addresses WHERE customer_id=$1 AND chain=$2`, customer, d.Chain).Scan(&out.Address, &out.Kind)
	if err != nil {
		return DepositAddress{}, err
	}
	return out, nil
}

// AssetBalance is a customer's balance in one asset (base units, decimal strings).
type AssetBalance struct {
	Chain     string `json:"chain"`
	Asset     string `json:"asset"`
	Available string `json:"available"`
	Held      string `json:"held"`
	Posted    string `json:"posted"`
}

// Balances lists a customer's balances.
func (s *Service) Balances(ctx context.Context, customer string) ([]AssetBalance, error) {
	var exists bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM customers WHERE id=$1)`, customer).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("%w: customer %q", ErrNotFound, customer)
	}
	rows, err := s.Pool.Query(ctx, `SELECT chain, asset, (posted-held)::text, held::text, posted::text FROM ledger_accounts
		WHERE customer_id=$1 AND kind='customer' ORDER BY chain, asset`, customer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AssetBalance
	for rows.Next() {
		var b AssetBalance
		if err := rows.Scan(&b.Chain, &b.Asset, &b.Available, &b.Held, &b.Posted); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
