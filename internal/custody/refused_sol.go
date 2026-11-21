package custody

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// A Solana attempt the zone refused (docs/limits.md, "Solana: a refused job"). One transaction has one sign job per signer (the hot shard and each deposit
// key), and the core calls the attempt refused as soon as ANY job is rejected, while the others may still be in the gateway's hands. What a refusal leaves
// behind is decided from every job of the attempt, once none is being signed:
//
//	any job done or failed        a signature exists (the gateway keeps its claim for a failed one): the nonce is kept and a cancel (advance the nonce
//	                              account) frees it; if the zone refuses that too, the owner is parked for an operator
//	any job refused by a cosigner after the gateway reserved ("signer_refused"): the gateway's guard holds a claim on the nonce account, though nothing was
//	                              signed. Releasing the allocation would hand a nonce account to the next transaction that the zone refuses for ever
//	                              (replay_nonce_taken), so the cancel is asked for, as on EVM. Not for a compromised generation: it cannot cancel, and
//	                              its drain takes the account's lamports whatever claims it (below)
//	every job refused by a rule   nothing was reserved and nothing signed, and a transaction needs every signer's signature, so none can exist for this
//	                              message: the nonce account is released unused (its value is unchanged) and the owner ends cleanly
//
// A refusal before any reservation looks the same whether the first job or its sibling is read first, so the core waits (a bounded time) for siblings that
// are being signed before it decides; without that a cancel was built for an attempt that held no claim, the zone refused it ("not claimed by any signed
// intent") and the owner was parked.

// solSettleWait bounds the wait for jobs that are being signed when the core decides what a refusal left behind. It is a variable for the tests.
var solSettleWait = 30 * time.Second

// solSettleStep is how often the wait looks again.
const solSettleStep = 200 * time.Millisecond

// settleSolJobs waits until no job of the owner's own track is being signed, or until solSettleWait has passed or ctx ends (the caller then decides as before:
// a job still being signed means a signature may exist).
func (s *Service) settleSolJobs(ctx context.Context, o Owner) error {
	if s.Cfg.Family != FamilySOL {
		return nil
	}
	deadline := time.Now().Add(solSettleWait)
	for {
		var n int
		if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM sign_jobs WHERE starts_with(id, $1) AND status=$2`, string(OwnerTrack(o))+":", signjob.StatusSigning).Scan(&n); err != nil {
			return err
		}
		if n == 0 || !time.Now().Before(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(solSettleStep):
		}
	}
}

// solClaimedRefusal reports whether a job of the owner's own track was refused by a cosigner after the gateway reserved: the zone holds a claim on the nonce
// account although nothing was signed. The job rows are locked by the caller's earlier read in the same transaction.
func (s *Service) solClaimedRefusal(ctx context.Context, tx pgx.Tx, o Owner) (bool, error) {
	if s.Cfg.Family != FamilySOL {
		return false, nil
	}
	var yes bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sign_jobs WHERE starts_with(id, $1) AND status=$2 AND starts_with(COALESCE(reject_reason, ''), 'signer_refused'))`,
		string(OwnerTrack(o))+":", signjob.StatusRejected).Scan(&yes)
	if err != nil || !yes {
		return false, err
	}
	// A compromised generation signs only drains, so it cannot cancel, and nothing else will ever use the claimed nonce account: a drain's withdrawal of the
	// account is on a recent blockhash, makes no claim, and the zone signs it although the account is claimed (gateway test
	// TestSolCompromisedDrainTakesAClaimedNonceAccount). The allocation is released, as it was before; keeping it would hold the drain back for ever
	// ("transactions built from the old address are still in flight").
	var hot string
	err = tx.QueryRow(ctx, `SELECT hot_address FROM sol_nonce_allocations WHERE chain=$1 AND owner_kind=$2 AND owner_id=$3 AND status='allocated' ORDER BY id DESC LIMIT 1`,
		s.Cfg.Chain, o.Kind, o.ID).Scan(&hot)
	if isNoRows(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	bad, err := addressCompromised(ctx, tx, hot)
	return !bad, err
}

// Replans of a refused sweep. A sweep the zone refuses leaves nothing behind and is planned again (with the back-off of sweepBackoff). A refusal that
// does not go away (a generation the zone does not know, a rule that a deposit never meets) would be planned, refused and failed for ever, so after
// solRefusedBound failures in a row the address is tried once in solRefusedProbe only, with one ALERT.
const (
	solRefusedBound = 6
	solRefusedProbe = 24 * time.Hour
)

// solRefusedLeftAlone reports whether the address is left alone because its last solRefusedBound sweeps were all refused by the zone, and the last one is
// younger than solRefusedProbe. It gives the ALERT once per address and process.
func (s *Service) solRefusedLeftAlone(ctx context.Context, addr, asset string) (bool, error) {
	rows, err := s.Pool.Query(ctx, `SELECT status, COALESCE(failure_reason, ''), EXTRACT(EPOCH FROM (now() - updated_at)) FROM sweeps
		WHERE chain=$1 AND from_address=$2 AND asset=$3 ORDER BY created_at DESC LIMIT $4`, s.Cfg.Chain, addr, asset, solRefusedBound)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	n := 0
	var age float64
	var reason string
	for rows.Next() {
		var st, why string
		var a float64
		if err := rows.Scan(&st, &why, &a); err != nil {
			return false, err
		}
		if st != "failed" || !strings.HasPrefix(why, "gateway refused:") || strings.Contains(why, "signing failed twice") {
			return false, rows.Err()
		}
		if n == 0 {
			age, reason = a, why
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	if n < solRefusedBound {
		return false, nil
	}
	if _, seen := s.sweepAlerted.LoadOrStore("refused:"+addr+"/"+asset, true); !seen {
		slog.Error("ALERT: the signing zone has refused the last sweeps of a deposit address every time; it is tried again once a day (docs/runbooks/key-replacement.md, docs/limits.md)",
			"chain", s.Cfg.Chain, "address", addr, "asset", asset, "refusals", n, "last_reason", reason)
	}
	return time.Duration(age*float64(time.Second)) < solRefusedProbe, nil
}
