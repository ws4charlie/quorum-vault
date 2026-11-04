package ledger

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// CheckInvariants verifies, in one statement (one snapshot):
//   - every account's posted equals the sum of its entries;
//   - every account's held equals the sum of its pending holds;
//   - total posted per (chain, asset) is zero.
//
// It returns an error describing every violation found.
func CheckInvariants(ctx context.Context, q Querier) error {
	rows, err := q.Query(ctx, `
		SELECT 'posted_vs_entries', a.id, a.posted::text || ' != ' || COALESCE(e.s, 0)::text
		  FROM ledger_accounts a
		  LEFT JOIN (SELECT account_id, SUM(amount) s FROM ledger_entries GROUP BY account_id) e ON e.account_id = a.id
		 WHERE a.posted <> COALESCE(e.s, 0)
		UNION ALL
		SELECT 'held_vs_holds', a.id, a.held::text || ' != ' || COALESCE(h.s, 0)::text
		  FROM ledger_accounts a
		  LEFT JOIN (SELECT account_id, SUM(amount) s FROM ledger_holds WHERE status = 'pending' GROUP BY account_id) h ON h.account_id = a.id
		 WHERE a.held <> COALESCE(h.s, 0)
		UNION ALL
		SELECT 'zero_sum', chain || '/' || asset, SUM(posted)::text
		  FROM ledger_accounts GROUP BY chain, asset HAVING SUM(posted) <> 0`)
	if err != nil {
		return fmt.Errorf("ledger: check invariants: %w", err)
	}
	defer rows.Close()
	var bad []string
	for rows.Next() {
		var kind, id, detail string
		if err := rows.Scan(&kind, &id, &detail); err != nil {
			return err
		}
		bad = append(bad, fmt.Sprintf("%s %s: %s", kind, id, detail))
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("ledger: check invariants: %w", err)
	}
	if len(bad) > 0 {
		return errors.New("ledger: invariants violated: " + strings.Join(bad, "; "))
	}
	return nil
}

// CheckInvariants is the method form of the package function.
func (Postgres) CheckInvariants(ctx context.Context, q Querier) error { return CheckInvariants(ctx, q) }

// ClearingResidual returns the posted balance of each named account; a
// clearing account whose flow has fully settled has residual 0. With no IDs it
// covers every account of kind clearing. A named unknown account is an error.
func ClearingResidual(ctx context.Context, q Querier, accountIDs ...string) (map[string]*big.Int, error) {
	var (
		sql  = `SELECT id, posted::text FROM ledger_accounts WHERE kind = 'clearing'`
		args []any
	)
	if len(accountIDs) > 0 {
		sql = `SELECT id, posted::text FROM ledger_accounts WHERE id = ANY($1)`
		args = []any{accountIDs}
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("ledger: clearing residual: %w", err)
	}
	defer rows.Close()
	out := map[string]*big.Int{}
	for rows.Next() {
		var id, posted string
		if err := rows.Scan(&id, &posted); err != nil {
			return nil, err
		}
		v, ok := new(big.Int).SetString(posted, 10)
		if !ok {
			return nil, fmt.Errorf("ledger: bad numeric for account %q", id)
		}
		out[id] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ledger: clearing residual: %w", err)
	}
	for _, id := range accountIDs {
		if _, ok := out[id]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrAccountNotFound, id)
		}
	}
	return out, nil
}

// ClearingResidual is the method form of the package function.
func (Postgres) ClearingResidual(ctx context.Context, q Querier, accountIDs ...string) (map[string]*big.Int, error) {
	return ClearingResidual(ctx, q, accountIDs...)
}
