package custody

import (
	"context"
	"log/slog"
	"math/big"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Coins claimed by a refused payment under a compromised generation (btc_claim.go), with a fake Bitcoin cell: what the core does with the owner, and what the
// drain planner does while a coin is held.

type btcClaimChain struct {
	btcViewChain
	gen      int
	reserved []btc.ReservedOwner
	plan     btc.DrainPlan
	held     []string
	open     bool // Reservation reports an open reservation (a cancel can be built)
}

func (f *btcClaimChain) PlanDrain(context.Context, string, string) (btc.DrainPlan, error) {
	return f.plan, nil
}
func (f *btcClaimChain) BuildDrain(context.Context, pgx.Tx, btc.DrainRequest) (chain.UnsignedTx, error) {
	return chain.UnsignedTx{}, nil
}
func (f *btcClaimChain) ShardAddressAtGen(_ string, gen int) (string, error) {
	return map[int]string{1: "old", 2: "new"}[gen], nil
}
func (f *btcClaimChain) ReservedUnder(context.Context, string, int) (int, error) {
	n := 0
	for _, o := range f.reserved {
		n += o.Coins
	}
	return n, nil
}
func (f *btcClaimChain) ReservedOwnersUnder(context.Context, string, int) ([]btc.ReservedOwner, error) {
	return f.reserved, nil
}
func (f *btcClaimChain) OwnerGen(context.Context, pgx.Tx, string, string) (int, error) {
	return f.gen, nil
}
func (f *btcClaimChain) HoldClaimed(_ context.Context, _ pgx.Tx, ops []string, _ string) (int, error) {
	f.held = append(f.held, ops...)
	return len(ops), nil
}
func (f *btcClaimChain) ReleaseUnsigned(context.Context, pgx.Tx, string, string) error { return nil }

func btcClaimWorld(t *testing.T, state string) (*Service, *btcClaimChain) {
	t.Helper()
	cfg, err := btcFile("regtest", xpubFor(t, &chaincfg.RegressionNetParams)).Build()
	if err != nil {
		t.Fatal(err)
	}
	acct, err := btc.NewAccount("regtest", xpubFor(t, &chaincfg.RegressionNetParams))
	if err != nil {
		t.Fatal(err)
	}
	hot, _ := acct.Address([]uint32{1, 0})
	cfg.BTC.HotShards = []btc.HotShardConfig{{PartitionID: cfg.PartitionKey(cfg.Native, 0).String(), Address: hot, Path: []uint32{1, 0}}}
	fc := &btcClaimChain{gen: 1}
	s := New(dbtest.New(t), cfg, fc, &fakeReader{})
	ctx := context.Background()
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	tree, _ := cfg.depositTreeID()
	for _, q := range []string{
		`INSERT INTO keysets (shard_id, generation, key_ref, address, public_key, state, successor) VALUES ('` + string(tree) + `', 2, 'ref2', 'xpub2', '\x02', 'candidate', NULL)`,
		`UPDATE keysets SET state='` + state + `', successor=2 WHERE shard_id='` + string(tree) + `' AND generation=1`,
		`UPDATE keysets SET state='active' WHERE shard_id='` + string(tree) + `' AND generation=2`,
	} {
		if _, err := s.Pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	return s, fc
}

func driveState(t *testing.T, s *Service) (string, string) {
	t.Helper()
	tree, _ := s.Cfg.depositTreeID()
	var st, why string
	if err := s.Pool.QueryRow(context.Background(), `SELECT state, reason FROM keyset_drains WHERE shard_id=$1 AND generation=1`, string(tree)).Scan(&st, &why); err != nil {
		t.Fatal(err)
	}
	return st, why
}

// With a coin held by a refused payment the drain of a compromised generation does not wait: the free coins move at once, and the state names the held ones. A
// draining generation still waits for what it has in flight.
func TestBTCDrainMovesFreeCoinsWhileACoinIsHeld(t *testing.T) {
	for _, tc := range []struct {
		state    string
		wantMove bool
	}{{"compromised", true}, {"draining", false}} {
		t.Run(tc.state, func(t *testing.T) {
			s, fc := btcClaimWorld(t, tc.state)
			fc.reserved = []btc.ReservedOwner{{Kind: "withdrawal", ID: "w1", Coins: 1, Sats: 60_000_000}}
			fc.plan = btc.DrainPlan{Amount: big.NewInt(25_000_000), Inputs: 1}
			mv, err := s.PlanDrains(context.Background(), slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantMove != (len(mv) == 1) {
				t.Fatalf("moves %+v", mv)
			}
			st, why := driveState(t, s)
			if tc.wantMove && (st != "moving" || !strings.Contains(why, "1 coins reserved by payments in flight")) {
				t.Fatalf("%s %q", st, why)
			}
			if !tc.wantMove && (st != "waiting" || !strings.Contains(why, "reserved by transactions that are not final")) {
				t.Fatalf("%s %q", st, why)
			}
		})
	}
}

// Nothing left to move but a held coin: the generation is not drained, and the state says where the cancel is.
func TestBTCDrainStateNamesTheCancelOfAHeldCoin(t *testing.T) {
	ctx := context.Background()
	s, fc := btcClaimWorld(t, "compromised")
	fc.reserved = []btc.ReservedOwner{{Kind: "withdrawal", ID: "w1", Coins: 2, Sats: 60_000_000}}
	fc.plan = btc.DrainPlan{Amount: new(big.Int)}
	if _, err := s.PlanDrains(ctx, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if st, why := driveState(t, s); st != "waiting" || !strings.Contains(why, "2 coins reserved by payments in flight") {
		t.Fatalf("%s %q", st, why)
	}
	cancelJob(t, s, "withdrawal", "w1", "pending")
	if _, err := s.PlanDrains(ctx, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if st, why := driveState(t, s); st != "waiting" || !strings.Contains(why, "2 coins held by a refused payment: cancel pending") {
		t.Fatalf("%s %q", st, why)
	}
	s.Pool.Exec(ctx, `UPDATE sign_jobs SET status='done'`)
	if _, err := s.PlanDrains(ctx, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if st, why := driveState(t, s); st != "waiting" || !strings.Contains(why, "cancel signed, waiting for confirmation") {
		t.Fatalf("%s %q", st, why)
	}
	s.Pool.Exec(ctx, `DELETE FROM sign_jobs`)
	fc.reserved = nil
	if _, err := s.PlanDrains(ctx, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if st, _ := driveState(t, s); st != "drained" {
		t.Fatalf("nothing held and nothing to move: %s", st)
	}
}

func cancelJob(t *testing.T, s *Service, kind, id, status string) {
	t.Helper()
	o := Owner{Kind: kind, ID: id, PartitionID: "p"}
	intent := []byte(`{"kind":"cancel","id":"x"}`)
	err := InTx(context.Background(), s.Pool, func(tx pgx.Tx) error {
		if err := signjob.Enqueue(context.Background(), tx, signjob.Job{ID: CancelTrack(o).FirstJob(), PartitionID: s.Cfg.PartitionKey(s.Cfg.Native, 0).String(), KeyRef: "k", Chain: s.Cfg.Chain, Intent: intent, Digest: []byte{1}, Payload: []byte(`{}`)}); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `UPDATE sign_jobs SET status=$2 WHERE id=$1`, CancelTrack(o).FirstJob(), status)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func ownerJob(t *testing.T, s *Service, o Owner, status, why string) {
	t.Helper()
	err := InTx(context.Background(), s.Pool, func(tx pgx.Tx) error {
		if err := signjob.Enqueue(context.Background(), tx, signjob.Job{ID: OwnerTrack(o).FirstJob(), PartitionID: s.Cfg.PartitionKey(s.Cfg.Native, 0).String(), KeyRef: "k", Chain: s.Cfg.Chain, Intent: []byte(`{"kind":"withdrawal","id":"w"}`), Digest: []byte{2}, Payload: []byte(`{}`)}); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `UPDATE sign_jobs SET status=$2, reject_reason=NULLIF($3,'') WHERE id=$1`, OwnerTrack(o).FirstJob(), status, why)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// When a refused payment's coins are held (the zone holds a claim) and when they are released.
func TestBTCClaimHeldDecision(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, status, why, coreState string
		want                         bool
	}{
		{"refused by a cosigner that has the mark, the core does not yet", "rejected", "signer_refused: authorizer on B refused: keyset_state: generation 1 of x is compromised: it signs nothing", "draining", true},
		{"refused by a cosigner, the core has the mark", "rejected", "signer_refused: authorizer on B refused: something else", "compromised", true},
		{"refused by a cosigner, nobody has the mark", "rejected", "signer_refused: authorizer on B refused: something else", "draining", false},
		{"refused by a rule of the gateway (nothing claimed)", "rejected", "keyset_state: generation 1 of x is compromised: it signs nothing", "compromised", false},
		{"a signature may exist", "done", "", "compromised", false},
		{"being signed", "signing", "", "compromised", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := btcClaimWorld(t, tc.coreState)
			o := Owner{Kind: "withdrawal", ID: "w1", PartitionID: "p"}
			ownerJob(t, s, o, tc.status, tc.why)
			var got bool
			if err := InTx(ctx, s.Pool, func(tx pgx.Tx) error {
				var err error
				got, err = s.btcClaimHeld(ctx, tx, o)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("held = %v, want %v", got, tc.want)
			}
			// a held owner is never released
			if tc.want {
				if rel, err := s.ReleaseIfUnsigned(ctx, o); err != nil || rel {
					t.Fatalf("released a held owner: %v %v", rel, err)
				}
			}
		})
	}
}

// A drain refused replay_nonce_taken names the coin: it is held out of the next moves and the retry is at once.
func TestBTCDrainRefusedForAClaimedCoinHoldsIt(t *testing.T) {
	ctx := context.Background()
	s, fc := btcClaimWorld(t, "compromised")
	fc.plan = btc.DrainPlan{Amount: big.NewInt(25_000_000), Inputs: 1}
	mv, err := s.PlanDrains(ctx, slog.New(slog.DiscardHandler))
	if err != nil || len(mv) != 1 {
		t.Fatalf("%v %+v", err, mv)
	}
	txid := strings.Repeat("ab", 32)
	reason := "the signing zone refused: replay_nonce_taken: " + txid + ":1 of 1/0 already signed for intent wd-77"
	if err := s.FailDrainBeforeBroadcast(ctx, mv[0].ID, reason, ""); err != nil {
		t.Fatal(err)
	}
	if len(fc.held) != 1 || fc.held[0] != txid+":1" {
		t.Fatalf("held %v", fc.held)
	}
	st, why := driveState(t, s)
	if st != "waiting" || !strings.Contains(why, "held out of the drain moves") {
		t.Fatalf("%s %q", st, why)
	}
	var retry any
	s.Pool.QueryRow(ctx, `SELECT retry_after FROM keyset_drains WHERE generation=1`).Scan(&retry)
	if retry != nil {
		t.Fatalf("retry_after %v: the next move does not contain the coin, nothing to wait for", retry)
	}
}

func (f *btcClaimChain) Reservation(context.Context, chain.Querier, string, string) (chain.Reservation, error) {
	return chain.Reservation{Open: f.open, Account: "bcrt1hot"}, nil
}

func (f *btcClaimChain) BuildCancel(context.Context, pgx.Tx, string, string) (chain.UnsignedTx, error) {
	return chain.UnsignedTx{Chain: "BTC", Digest: []byte{9, 9}, Payload: []byte(`{}`), KeyRef: chain.KeyRef{Path: "k"}}, nil
}

// An expired cancel of a held coin is renewed once; a repeat of the request (an activity retry after a lost reply) follows the latest attempt whatever state it
// is in, signing or done included, and never answers with the expired one.
func TestBTCCancelRenewalIsFollowedOnRepeat(t *testing.T) {
	ctx := context.Background()
	s, fc := btcClaimWorld(t, "compromised")
	fc.open = true
	o := Owner{Kind: "withdrawal", ID: "w1", PartitionID: s.Cfg.PartitionKey(s.Cfg.Native, 0).String()}
	ownerJob(t, s, o, "rejected", "signer_refused: authorizer on B refused: keyset_state: generation 1 of x is compromised: it signs nothing")
	cancelJob(t, s, o.Kind, o.ID, "rejected")
	first := CancelTrack(o).FirstJob()
	if _, err := s.Pool.Exec(ctx, `UPDATE sign_jobs SET reject_reason='intent_expired: intent expired at 1, now 2' WHERE id=$1`, first); err != nil {
		t.Fatal(err)
	}
	renewed, err := s.EnqueueCancel(ctx, o)
	if err != nil || renewed == first || renewed == "" {
		t.Fatalf("no renewal: %q %v", renewed, err)
	}
	for _, st := range []string{"pending", "signing", "done"} {
		if _, err := s.Pool.Exec(ctx, `UPDATE sign_jobs SET status=$2 WHERE id=$1`, renewed, st); err != nil {
			t.Fatal(err)
		}
		if again, err := s.EnqueueCancel(ctx, o); err != nil || again != renewed {
			t.Fatalf("renewal %s: a repeat returned %q (%v), want %q", st, again, err, renewed)
		}
	}
}
