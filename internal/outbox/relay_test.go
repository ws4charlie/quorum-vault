package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
)

const kafkaAddr = "127.0.0.1:19092"

// fakePub records events; failAt (1-based publish count) makes that publish fail once.
type fakePub struct {
	mu     sync.Mutex
	events []Event
	failAt int
	n      int
}

func (f *fakePub) Publish(_ context.Context, e Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.n == f.failAt {
		return errors.New("broker down")
	}
	f.events = append(f.events, e)
	return nil
}
func (f *fakePub) Close() {}

func writeEvents(t *testing.T, pool *pgxpool.Pool, topic string, keys ...string) {
	t.Helper()
	ctx := context.Background()
	for i, k := range keys {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := Write(ctx, tx, topic, k, map[string]any{"n": i}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func unpublished(t *testing.T, pool *pgxpool.Pool) int {
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE published_at IS NULL`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRelayPublishesInSeqOrderAndMarks(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	writeEvents(t, pool, TopicWithdrawals, "a", "b", "a", "c", "a")
	pub := &fakePub{}
	r := NewRelay(pool, pub, RelayOptions{BatchSize: 3})
	n, err := r.RunOnce(ctx)
	if err != nil || n != 3 {
		t.Fatalf("first batch: n=%d err=%v", n, err)
	}
	if n, err = r.RunOnce(ctx); err != nil || n != 2 {
		t.Fatalf("second batch: n=%d err=%v", n, err)
	}
	if n, _ = r.RunOnce(ctx); n != 0 {
		t.Fatalf("empty outbox published %d", n)
	}
	for i := 1; i < len(pub.events); i++ {
		if pub.events[i].Seq <= pub.events[i-1].Seq {
			t.Fatal("events out of seq order")
		}
	}
	if len(pub.events) != 5 || pub.events[0].Key != "a" || pub.events[0].ID == "" || pub.events[0].Topic != TopicWithdrawals {
		t.Fatalf("events = %+v", pub.events)
	}
	if unpublished(t, pool) != 0 {
		t.Fatal("rows left unpublished")
	}
}

func TestRelayStopsBatchOnPublishError(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	writeEvents(t, pool, TopicSweeps, "k", "k", "k", "k")
	pub := &fakePub{failAt: 3}
	r := NewRelay(pool, pub, RelayOptions{BatchSize: 10})
	n, err := r.RunOnce(ctx)
	if err == nil || n != 2 {
		t.Fatalf("n=%d err=%v, want 2 published and an error", n, err)
	}
	// The third and fourth events were not sent: nothing overtook the failed one.
	if len(pub.events) != 2 || unpublished(t, pool) != 2 {
		t.Fatalf("sent %d, unpublished %d", len(pub.events), unpublished(t, pool))
	}
	// Next run (broker back) sends the rest, in order, starting with the one that failed.
	if n, err = r.RunOnce(ctx); err != nil || n != 2 {
		t.Fatalf("retry: n=%d err=%v", n, err)
	}
	for i := 1; i < len(pub.events); i++ {
		if pub.events[i].Seq <= pub.events[i-1].Seq {
			t.Fatal("order broken across the retry")
		}
	}
	if len(pub.events) != 4 || unpublished(t, pool) != 0 {
		t.Fatalf("sent %d, unpublished %d", len(pub.events), unpublished(t, pool))
	}
}

func TestRelayCrashRedeliversWithSameEventID(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	writeEvents(t, pool, TopicDeposits, "k1", "k2")
	pub := &fakePub{}
	r := NewRelay(pool, pub, RelayOptions{})
	r.beforeMark = func() error { return errors.New("crash after publish") }
	if _, err := r.RunOnce(ctx); err == nil {
		t.Fatal("expected the simulated crash")
	}
	if unpublished(t, pool) != 2 || len(pub.events) != 2 {
		t.Fatalf("after crash: unpublished %d, sent %d", unpublished(t, pool), len(pub.events))
	}
	r.beforeMark = nil
	if n, err := r.RunOnce(ctx); err != nil || n != 2 {
		t.Fatalf("restart: n=%d err=%v", n, err)
	}
	if len(pub.events) != 4 {
		t.Fatalf("sent %d, want 4 (2 repeats)", len(pub.events))
	}
	for i := 0; i < 2; i++ {
		if pub.events[i].ID != pub.events[i+2].ID {
			t.Fatalf("redelivered event %d has a new ID", i)
		}
	}
}

func TestRelayConcurrentRelaysNeverShareARow(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	keys := make([]string, 40)
	for i := range keys {
		keys[i] = fmt.Sprint("k", i)
	}
	writeEvents(t, pool, TopicAudit, keys...)
	pub := &fakePub{}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := NewRelay(pool, pub, RelayOptions{BatchSize: 5})
			for {
				n, err := r.RunOnce(ctx)
				if err != nil {
					t.Error(err)
					return
				}
				if n == 0 {
					return
				}
			}
		}()
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, e := range pub.events {
		if seen[e.ID] {
			t.Fatalf("event %s published twice by concurrent relays", e.ID)
		}
		seen[e.ID] = true
	}
	if len(seen) != 40 || unpublished(t, pool) != 0 {
		t.Fatalf("published %d of 40, unpublished %d", len(seen), unpublished(t, pool))
	}
}

func TestRelayRunBacksOffAndRecovers(t *testing.T) {
	pool := dbtest.New(t)
	writeEvents(t, pool, TopicDeposits, "k")
	pub := &fakePub{failAt: 1}
	r := NewRelay(pool, pub, RelayOptions{Idle: 10 * time.Millisecond, MinBackoff: 10 * time.Millisecond, MaxBackoff: 40 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error)
	go func() { done <- r.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for unpublished(t, pool) != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if unpublished(t, pool) != 0 {
		t.Fatal("row not published after the broker recovered")
	}
}

// --- against a real broker: QV_REQUIRE_INFRA=1 (`docker compose -p qv-p3a --profile infra up -d --wait redpanda`) ---

func requireInfra(t *testing.T) {
	t.Helper()
	if os.Getenv("QV_REQUIRE_INFRA") != "1" {
		t.Skip("QV_REQUIRE_INFRA != 1")
	}
}

func consumeAll(t *testing.T, topic string, want int, timeout time.Duration) []*kgo.Record {
	t.Helper()
	cl, err := kgo.NewClient(kgo.SeedBrokers(kafkaAddr), kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var out []*kgo.Record
	for len(out) < want {
		f := cl.PollFetches(ctx)
		if ctx.Err() != nil {
			break
		}
		f.EachRecord(func(r *kgo.Record) { out = append(out, r) })
	}
	return out
}

func header(r *kgo.Record, k string) string {
	for _, h := range r.Headers {
		if h.Key == k {
			return string(h.Value)
		}
	}
	return ""
}

func uniqueTopic(prefix string) string { return fmt.Sprintf("%s.%d", prefix, time.Now().UnixNano()) }

func TestRelayKafkaOrderAndEventIDs(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()
	pool := dbtest.New(t)
	topic := uniqueTopic("qv.relay.order")
	const n = 30
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprint("key", i%3)
	}
	writeEvents(t, pool, topic, keys...)
	pub, err := NewKafkaPublisher([]string{kafkaAddr})
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	r := NewRelay(pool, pub, RelayOptions{BatchSize: 7})
	for {
		k, err := r.RunOnce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if k == 0 {
			break
		}
	}
	recs := consumeAll(t, topic, n, 30*time.Second)
	if len(recs) != n {
		t.Fatalf("consumed %d of %d", len(recs), n)
	}
	// Per key, payload counters must arrive in write order; every record has an event ID.
	last := map[string]float64{}
	ids := map[string]bool{}
	for _, rec := range recs {
		var p struct{ N float64 }
		if err := jsonUnmarshal(rec.Value, &p); err != nil {
			t.Fatal(err)
		}
		if prev, ok := last[string(rec.Key)]; ok && p.N <= prev {
			t.Fatalf("key %s: event %v after %v", rec.Key, p.N, prev)
		}
		last[string(rec.Key)] = p.N
		id := header(rec, HeaderID)
		if id == "" || ids[id] {
			t.Fatalf("missing or duplicate event id %q", id)
		}
		ids[id] = true
	}
}

func TestRelayKafkaCrashRedeliversSameID(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()
	pool := dbtest.New(t)
	topic := uniqueTopic("qv.relay.crash")
	writeEvents(t, pool, topic, "k1", "k2", "k3")
	pub, err := NewKafkaPublisher([]string{kafkaAddr})
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	r := NewRelay(pool, pub, RelayOptions{})
	r.beforeMark = func() error { return errors.New("crash after publish") }
	if _, err := r.RunOnce(ctx); err == nil {
		t.Fatal("expected simulated crash")
	}
	r.beforeMark = nil
	if n, err := r.RunOnce(ctx); err != nil || n != 3 {
		t.Fatalf("restart: n=%d err=%v", n, err)
	}
	recs := consumeAll(t, topic, 6, 30*time.Second)
	if len(recs) != 6 {
		t.Fatalf("consumed %d, want 6 (3 repeated)", len(recs))
	}
	count := map[string]int{}
	for _, rec := range recs {
		count[header(rec, HeaderID)]++
	}
	if len(count) != 3 {
		t.Fatalf("%d distinct event IDs, want 3", len(count))
	}
	for id, c := range count {
		if c != 2 {
			t.Fatalf("event %s delivered %d times, want 2", id, c)
		}
	}
}

// Kafka unreachable, then reachable: no row is lost and nothing is marked published early.
func TestRelayKafkaDownThenUp(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()
	pool := dbtest.New(t)
	topic := uniqueTopic("qv.relay.down")
	writeEvents(t, pool, topic, "k1", "k2", "k3")

	down, err := NewKafkaPublisher([]string{"127.0.0.1:1"}, kgo.RecordDeliveryTimeout(time.Second), kgo.DialTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer down.Close()
	r := NewRelay(pool, down, RelayOptions{PublishWait: 3 * time.Second})
	if n, err := r.RunOnce(ctx); err == nil || n != 0 {
		t.Fatalf("down broker: n=%d err=%v", n, err)
	}
	if unpublished(t, pool) != 3 {
		t.Fatal("rows lost or marked while Kafka was down")
	}

	up, err := NewKafkaPublisher([]string{kafkaAddr})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	r = NewRelay(pool, up, RelayOptions{})
	if n, err := r.RunOnce(ctx); err != nil || n != 3 {
		t.Fatalf("broker back: n=%d err=%v", n, err)
	}
	if recs := consumeAll(t, topic, 3, 30*time.Second); len(recs) != 3 {
		t.Fatalf("consumed %d of 3", len(recs))
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
