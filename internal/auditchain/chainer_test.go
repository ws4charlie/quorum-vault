package auditchain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

func writeAudit(t *testing.T, pool *pgxpool.Pool, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		tx, err := pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := outbox.Write(context.Background(), tx, outbox.TopicAudit, fmt.Sprint("k", i), map[string]any{"type": "test.event", "actor": "alice", "n": i}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func count(t *testing.T, pool *pgxpool.Pool, q string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func mustVerify(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if ok, bad, err := audit.VerifyChain(context.Background(), pool); err != nil || !ok {
		t.Fatalf("chain: ok=%v bad=%d err=%v", ok, bad, err)
	}
}

func drain(t *testing.T, c *Chainer) {
	t.Helper()
	for {
		n, err := c.RunOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
	}
}

func TestChainerAppendsEachRowOnce(t *testing.T) {
	pool := dbtest.New(t)
	writeAudit(t, pool, 7)
	// A row for another topic is not audit.
	tx, _ := pool.Begin(context.Background())
	outbox.Write(context.Background(), tx, outbox.TopicWithdrawals, "w", map[string]any{"type": "x"})
	tx.Commit(context.Background())

	c := NewChainer(pool, ChainerOptions{BatchSize: 3})
	drain(t, c)
	drain(t, c) // again: nothing new
	if n := count(t, pool, `SELECT count(*) FROM audit_log`); n != 7 {
		t.Fatalf("audit entries = %d, want 7", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM outbox WHERE topic='qv.audit' AND chained_at IS NULL`); n != 0 {
		t.Fatalf("%d audit rows left unchained", n)
	}
	var actor, typ, subject string
	pool.QueryRow(context.Background(), `SELECT actor, type, payload->>'subject' FROM audit_log WHERE seq=1`).Scan(&actor, &typ, &subject)
	if actor != "alice" || typ != "test.event" || subject != "k0" {
		t.Fatalf("first entry = %s %s %s", actor, typ, subject)
	}
	mustVerify(t, pool)
}

// A crash after appending but before committing leaves the rows unchained and the chain untouched; the next run does it all.
func TestChainerCrashBetweenReadAndAppendLosesNothing(t *testing.T) {
	pool := dbtest.New(t)
	writeAudit(t, pool, 5)
	c := NewChainer(pool, ChainerOptions{})
	c.beforeCommit = func() error { return errors.New("crash") }
	if _, err := c.RunOnce(context.Background()); err == nil {
		t.Fatal("the crash was not seen")
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_log`); n != 0 {
		t.Fatalf("%d entries survived a crash before commit", n)
	}
	c.beforeCommit = nil
	drain(t, c)
	if n := count(t, pool, `SELECT count(*) FROM audit_log`); n != 5 {
		t.Fatalf("entries = %d, want 5", n)
	}
	mustVerify(t, pool)
}

// Several chainers at once: one works, the others see the lock; every row is chained exactly once.
func TestChainersRacing(t *testing.T) {
	pool := dbtest.New(t)
	writeAudit(t, pool, 60)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := NewChainer(pool, ChainerOptions{BatchSize: 7})
			for j := 0; j < 30; j++ {
				if _, err := c.RunOnce(context.Background()); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	drain(t, NewChainer(pool, ChainerOptions{}))
	if n := count(t, pool, `SELECT count(*) FROM audit_log`); n != 60 {
		t.Fatalf("entries = %d, want 60", n)
	}
	if n := count(t, pool, `SELECT count(DISTINCT source_id) FROM audit_log`); n != 60 {
		t.Fatalf("distinct sources = %d, want 60", n)
	}
	mustVerify(t, pool)
}

// A row committed late, with a lower seq than rows already chained, is still chained.
func TestChainerPicksUpRowCommittedOutOfOrder(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	slow, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.Write(ctx, slow, outbox.TopicAudit, "slow", map[string]any{"type": "test.slow", "actor": "a"}); err != nil {
		t.Fatal(err)
	}
	writeAudit(t, pool, 2) // higher seq, committed first
	c := NewChainer(pool, ChainerOptions{})
	drain(t, c)
	if n := count(t, pool, `SELECT count(*) FROM audit_log`); n != 2 {
		t.Fatalf("entries before the slow commit = %d, want 2", n)
	}
	if err := slow.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	drain(t, c)
	if n := count(t, pool, `SELECT count(*) FROM audit_log WHERE type='test.slow'`); n != 1 {
		t.Fatal("the late row was never chained")
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_log`); n != 3 {
		t.Fatalf("entries = %d, want 3", n)
	}
	mustVerify(t, pool)
}

func TestOutboxRowsCannotBeEdited(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()
	writeAudit(t, pool, 1)
	for _, q := range []string{
		`UPDATE outbox SET payload = '{"type":"x"}'`,
		`UPDATE outbox SET topic = 'qv.other'`,
		`DELETE FROM outbox`,
		`TRUNCATE outbox`,
	} {
		if _, err := pool.Exec(ctx, q); err == nil {
			t.Errorf("%s was allowed", q)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE outbox SET published_at = now()`); err != nil {
		t.Errorf("marking published: %v", err)
	}
	drain(t, NewChainer(pool, ChainerOptions{}))
	if _, err := pool.Exec(ctx, `UPDATE outbox SET chained_at = NULL`); err == nil {
		t.Error("chained_at was reset")
	}
}

type fakePub struct {
	mu   sync.Mutex
	down bool
	got  []audit.Anchor
}

func (f *fakePub) Publish(_ context.Context, e outbox.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errors.New("kafka down")
	}
	var a audit.Anchor
	if err := json.Unmarshal(e.Payload, &a); err != nil {
		return err
	}
	if e.Topic != outbox.TopicAuditHeads {
		return fmt.Errorf("topic %s", e.Topic)
	}
	f.got = append(f.got, a)
	return nil
}
func (f *fakePub) Close() {}
func (f *fakePub) set(down bool) {
	f.mu.Lock()
	f.down = down
	f.mu.Unlock()
}
func (f *fakePub) last() (audit.Anchor, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.got) == 0 {
		return audit.Anchor{}, false
	}
	return f.got[len(f.got)-1], true
}

// Kafka down: chaining goes on; when Kafka is back the latest head is published.
func TestKafkaDownChainingContinuesAnchorsCatchUp(t *testing.T) {
	pool := dbtest.New(t)
	pub := &fakePub{down: true}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		PublishHeads(ctx, pool, "core", pub, AnchorOptions{Poll: 20 * time.Millisecond, Interval: time.Hour})
		close(done)
	}()
	defer func() { cancel(); <-done }()

	writeAudit(t, pool, 4)
	drain(t, NewChainer(pool, ChainerOptions{}))
	time.Sleep(150 * time.Millisecond)
	if _, ok := pub.last(); ok {
		t.Fatal("published while down")
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_log`); n != 4 {
		t.Fatalf("entries = %d: chaining stopped with Kafka down", n)
	}
	pub.set(false)
	waitFor(t, func() bool { a, ok := pub.last(); return ok && a.Seq == 4 })
	// A new head goes out on its own, without waiting for the interval.
	writeAudit(t, pool, 1)
	drain(t, NewChainer(pool, ChainerOptions{}))
	waitFor(t, func() bool { a, ok := pub.last(); return ok && a.Seq == 5 && a.Source == "core" })
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func disableTriggers(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, q := range []string{`ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete`, `ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_truncate`} {
		if _, err := pool.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
}

func anchorsFile(t *testing.T, as ...audit.Anchor) string {
	t.Helper()
	var b bytes.Buffer
	for _, a := range as {
		j, _ := json.Marshal(a)
		b.Write(j)
		b.WriteByte('\n')
	}
	p := filepath.Join(t.TempDir(), "anchors.jsonl")
	if err := os.WriteFile(p, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The four ways to tamper with the chain, and what catches each. An editor with the right to turn the triggers off can do all of
// them; the first two break the chain itself, the last two leave a chain that is valid and only the anchors disagree.
func TestTamperingIsCaught(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*pgxpool.Pool, string) {
		pool := dbtest.New(t)
		writeAudit(t, pool, 10)
		drain(t, NewChainer(pool, ChainerOptions{}))
		head, err := audit.Head(ctx, pool, "core")
		if err != nil || head.Seq != 10 {
			t.Fatalf("head %+v %v", head, err)
		}
		mid := audit.Anchor{Source: "core", Seq: 6}
		var h []byte
		pool.QueryRow(ctx, `SELECT hash FROM audit_log WHERE seq=6`).Scan(&h)
		mid.Hash = fmt.Sprintf("%x", h)
		mid.At = time.Now()
		path := anchorsFile(t, mid, head)
		if err := Verify(ctx, pool, "core", path, &bytes.Buffer{}); err != nil {
			t.Fatalf("untouched chain failed: %v", err)
		}
		disableTriggers(t, pool)
		return pool, path
	}
	check := func(t *testing.T, pool *pgxpool.Pool, path, wantInErr string) {
		t.Helper()
		err := Verify(ctx, pool, "core", path, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), wantInErr) {
			t.Fatalf("err = %v, want it to say %q", err, wantInErr)
		}
	}

	t.Run("a changed row: the chain check", func(t *testing.T) {
		pool, path := setup(t)
		pool.Exec(ctx, `UPDATE audit_log SET actor='mallory' WHERE seq=4`)
		check(t, pool, path, "broken at seq 4")
	})
	t.Run("a deleted row: the chain check", func(t *testing.T) {
		pool, path := setup(t)
		pool.Exec(ctx, `DELETE FROM audit_log WHERE seq=5`)
		check(t, pool, path, "broken at seq 6")
	})
	t.Run("a truncated tail: only the anchors", func(t *testing.T) {
		pool, path := setup(t)
		pool.Exec(ctx, `DELETE FROM audit_log WHERE seq > 7`)
		mustVerify(t, pool) // still a valid chain
		check(t, pool, path, "tail was cut off")
	})
	t.Run("a rewritten chain: only the anchors", func(t *testing.T) {
		pool, path := setup(t)
		// Keep seq 1..5, then write a different, valid history from seq 6 on.
		pool.Exec(ctx, `DELETE FROM audit_log WHERE seq > 5`)
		for i := 0; i < 5; i++ {
			tx, _ := pool.Begin(ctx)
			if _, err := audit.AppendTx(ctx, tx, domain.AuditEvent{Actor: "mallory", Type: "test.event", Payload: json.RawMessage(`{"n":0}`)}, ""); err != nil {
				t.Fatal(err)
			}
			tx.Commit(ctx)
		}
		mustVerify(t, pool)
		check(t, pool, path, "was rewritten")
	})
	t.Run("an anchor file that is not anchors proves nothing", func(t *testing.T) {
		pool, _ := setup(t)
		p := filepath.Join(t.TempDir(), "bad")
		os.WriteFile(p, []byte("not json\n"), 0o600)
		check(t, pool, p, "not an anchor")
	})
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *lockedBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// A chainer that cannot chain says so at error level with the lag, keeps retrying, and skips nothing.
func TestStalledChainerAlerts(t *testing.T) {
	pool := dbtest.New(t)
	writeAudit(t, pool, 3)
	// A row the chainer cannot turn into an entry stops the chain at that row.
	tx, _ := pool.Begin(context.Background())
	tx.Exec(context.Background(), `INSERT INTO outbox (id, topic, key, payload) VALUES (gen_random_uuid(), 'qv.audit', 'bad', '{"no":"type"}')`)
	tx.Commit(context.Background())
	buf := &lockedBuf{}
	c := NewChainer(pool, ChainerOptions{Idle: 10 * time.Millisecond, Backoff: 10 * time.Millisecond, Logger: slog.New(slog.NewJSONHandler(buf, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	waitFor(t, func() bool { return strings.Contains(buf.String(), "ALERT audit chainer cannot chain") })
	cancel()
	<-done
	out := buf.String()
	if !strings.Contains(out, `"level":"ERROR"`) || !strings.Contains(out, "unchained_rows") || !strings.Contains(out, "oldest_unchained_age") {
		t.Fatalf("alert = %s", out)
	}
	if n := strings.Count(out, "ALERT"); n != 1 {
		t.Fatalf("%d alerts in a burst of retries, want 1", n)
	}
	if rows, _, err := Behind(context.Background(), pool); err != nil || rows != 4 {
		t.Fatalf("behind = %d, %v; the three good rows are held behind the bad one (all in one batch)", rows, err)
	}
}
