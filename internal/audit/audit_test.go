package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/domain"
)

// appendEv appends ev in a transaction of its own (what every caller of AppendTx does around its own writes).
func appendEv(ctx context.Context, pool *pgxpool.Pool, ev domain.AuditEvent) (domain.AuditEvent, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return domain.AuditEvent{}, err
	}
	defer tx.Rollback(ctx)
	if ev, err = audit.AppendTx(ctx, tx, ev, ""); err != nil {
		return domain.AuditEvent{}, err
	}
	return ev, tx.Commit(ctx)
}

// stored reads back the rows of audit_log, ordered by seq, optionally only those of a request or a wallet.
func stored(t *testing.T, pool *pgxpool.Pool, requestID, walletID string) []domain.AuditEvent {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT seq, at, actor, type, coalesce(request_id::text, ''), coalesce(wallet_id::text, ''),
		coalesce(key_id::text, ''), payload::text, prev_hash, hash FROM audit_log
		WHERE ($1 = '' OR request_id::text = $1) AND ($2 = '' OR wallet_id::text = $2) ORDER BY seq`, requestID, walletID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []domain.AuditEvent
	for rows.Next() {
		var ev domain.AuditEvent
		var payload *string
		if err := rows.Scan(&ev.Seq, &ev.At, &ev.Actor, &ev.Type, &ev.RequestID, &ev.WalletID, &ev.KeyID, &payload, &ev.PrevHash, &ev.Hash); err != nil {
			t.Fatal(err)
		}
		ev.At = ev.At.UTC()
		if payload != nil {
			ev.Payload = json.RawMessage(*payload)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAppendChainsThreeEvents(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	wid := uuid.NewString()

	var got []domain.AuditEvent
	for i, typ := range []string{domain.EventWalletCreated, domain.EventPolicyUpdated, domain.EventAllowlistUpdated} {
		ev, err := appendEv(ctx, pool, domain.AuditEvent{
			Actor: "alice", Type: typ, WalletID: wid,
			Payload: json.RawMessage(fmt.Sprintf(`{"i": %d, "b": "x", "a": [1, 2]}`, i)),
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if ev.Seq != int64(i+1) {
			t.Fatalf("seq = %d, want %d", ev.Seq, i+1)
		}
		if ev.At.IsZero() || len(ev.Hash) != 32 || len(ev.PrevHash) != 32 {
			t.Fatalf("event not filled: %+v", ev)
		}
		got = append(got, ev)
	}
	if !bytes.Equal(got[0].PrevHash, make([]byte, 32)) {
		t.Fatalf("genesis prev_hash = %x, want zeros", got[0].PrevHash)
	}
	for i := 1; i < len(got); i++ {
		if !bytes.Equal(got[i].PrevHash, got[i-1].Hash) {
			t.Fatalf("event %d prev_hash does not link to event %d", i+1, i)
		}
	}

	// Stored rows equal the returned events exactly (At round-trips).
	listed := stored(t, pool, "", wid)
	if len(listed) != 3 {
		t.Fatalf("listed %d events, want 3", len(listed))
	}
	for i := range listed {
		a, b := listed[i], got[i]
		if a.Seq != b.Seq || !a.At.Equal(b.At) || a.Actor != b.Actor || a.Type != b.Type ||
			a.WalletID != b.WalletID || string(a.Payload) != string(b.Payload) ||
			!bytes.Equal(a.Hash, b.Hash) || !bytes.Equal(a.PrevHash, b.PrevHash) {
			t.Fatalf("listed %+v != appended %+v", a, b)
		}
	}
	ok, bad, err := audit.VerifyChain(ctx, pool)
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %d, %v; want ok", ok, bad, err)
	}
}

func TestAppendNormalizesIDsAndNullPayload(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	rid := uuid.NewString()
	if _, err := appendEv(ctx, pool, domain.AuditEvent{Actor: "a", Type: domain.EventRequestCreated, RequestID: strings.ToUpper(rid)}); err != nil {
		t.Fatal(err)
	}
	if _, err := appendEv(ctx, pool, domain.AuditEvent{Actor: "a", Type: domain.EventRequestCreated, KeyID: "not-a-uuid"}); err == nil {
		t.Fatal("invalid key_id accepted")
	}
	if _, err := appendEv(ctx, pool, domain.AuditEvent{Actor: "a", Type: "x", Payload: json.RawMessage(`{bad`)}); err == nil {
		t.Fatal("invalid payload accepted")
	}
	if _, err := appendEv(ctx, pool, domain.AuditEvent{Type: "x"}); err == nil {
		t.Fatal("missing actor accepted")
	}
	evs := stored(t, pool, rid, "")
	if len(evs) != 1 || evs[0].RequestID != rid || evs[0].Payload != nil {
		t.Fatalf("stored = %+v", evs)
	}
	if ok, bad, err := audit.VerifyChain(ctx, pool); err != nil || !ok {
		t.Fatalf("Verify = %v, %d, %v", ok, bad, err)
	}
}

// The wallet id of each entry is stored as given, so a wallet's entries can be found (List and its filter were deleted with the second API).
func TestAppendStoresWalletIDs(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	w1, w2 := uuid.NewString(), uuid.NewString()
	for i := 0; i < 5; i++ {
		w := w1
		if i%2 == 1 {
			w = w2
		}
		if _, err := appendEv(ctx, pool, domain.AuditEvent{Actor: "a", Type: domain.EventPolicyUpdated, WalletID: w}); err != nil {
			t.Fatal(err)
		}
	}
	if all := stored(t, pool, "", ""); len(all) != 5 {
		t.Fatalf("all = %d", len(all))
	}
	one := stored(t, pool, "", w1)
	if len(one) != 3 || one[0].Seq != 1 || one[1].Seq != 3 || one[2].Seq != 5 {
		t.Fatalf("w1 events = %+v", one)
	}
	if two := stored(t, pool, "", w2); len(two) != 2 || two[0].Seq != 2 || two[1].Seq != 4 {
		t.Fatalf("w2 events = %+v", two)
	}
}

func TestConcurrentAppendsFormValidChain(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	const workers, each = 16, 5
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				_, err := appendEv(ctx, pool, domain.AuditEvent{Actor: fmt.Sprintf("worker-%d", w), Type: domain.EventSignStarted,
					Payload: json.RawMessage(fmt.Sprintf(`{"i":%d}`, i))})
				if err != nil {
					errs <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	evs := stored(t, pool, "", "")
	if len(evs) != workers*each {
		t.Fatalf("got %d events, want %d", len(evs), workers*each)
	}
	for i, ev := range evs {
		if ev.Seq != int64(i+1) {
			t.Fatalf("gap: position %d has seq %d", i, ev.Seq)
		}
	}
	if ok, bad, err := audit.VerifyChain(ctx, pool); err != nil || !ok {
		t.Fatalf("Verify = %v, %d, %v", ok, bad, err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := appendEv(ctx, pool, domain.AuditEvent{Actor: "a", Type: domain.EventSignCompleted,
			Payload: json.RawMessage(fmt.Sprintf(`{"amount":"%d"}`, i))}); err != nil {
			t.Fatal(err)
		}
	}
	// A superuser bypasses the append-only trigger and edits seq 3's payload.
	for _, stmt := range []string{
		`ALTER TABLE audit_log DISABLE TRIGGER USER`,
		`UPDATE audit_log SET payload = '{"amount":"999"}' WHERE seq = 3`,
		`ALTER TABLE audit_log ENABLE TRIGGER USER`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	ok, bad, err := audit.VerifyChain(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if ok || bad != 3 {
		t.Fatalf("Verify = ok %v, firstBadSeq %d; want false, 3", ok, bad)
	}
}

func TestVerifyDetectsDeletedRow(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if _, err := appendEv(ctx, pool, domain.AuditEvent{Actor: "a", Type: domain.EventSignStarted}); err != nil {
			t.Fatal(err)
		}
	}
	for _, stmt := range []string{
		`ALTER TABLE audit_log DISABLE TRIGGER USER`,
		`DELETE FROM audit_log WHERE seq = 2`,
		`ALTER TABLE audit_log ENABLE TRIGGER USER`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	ok, bad, err := audit.VerifyChain(ctx, pool)
	if err != nil || ok || bad != 3 {
		t.Fatalf("Verify = %v, %d, %v; want false, 3", ok, bad, err)
	}
}

func TestUpdateDeleteStillRejected(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	if _, err := appendEv(ctx, pool, domain.AuditEvent{Actor: "a", Type: domain.EventWalletCreated}); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE audit_log SET actor = 'evil'`,
		`DELETE FROM audit_log`,
		`TRUNCATE audit_log`,
	} {
		if _, err := pool.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: err = %v, want append-only error", stmt, err)
		}
	}
	if ok, _, err := audit.VerifyChain(ctx, pool); err != nil || !ok {
		t.Fatalf("chain broken after rejected writes: %v %v", ok, err)
	}
}
