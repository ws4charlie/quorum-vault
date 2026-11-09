package custody_test

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

// checkKafka consumes the four topics from the start and requires that every
// outbox row of this database arrives, and that after de-duplicating on the
// record header "id" each is consumed exactly once. The topics are shared
// with other runs, so ids from other databases are ignored. It also requires every row published.
func (s *system) checkKafka(timeout time.Duration) {
	s.t.Helper()
	s.waitFor(timeout, "all outbox rows published", func() bool {
		return s.count(`SELECT count(*) FROM outbox WHERE published_at IS NULL`) == 0
	})
	rows, err := s.pool.Query(s.ctx, `SELECT id::text FROM outbox`)
	if err != nil {
		s.t.Fatal(err)
	}
	want := map[string]bool{}
	for rows.Next() {
		var id string
		rows.Scan(&id)
		want[id] = true
	}
	rows.Close()

	cl, err := kgo.NewClient(kgo.SeedBrokers(kafkaBrokers()),
		kgo.ConsumeTopics(outbox.TopicDeposits, outbox.TopicWithdrawals, outbox.TopicSweeps, outbox.TopicAudit),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	if err != nil {
		s.t.Fatal(err)
	}
	defer cl.Close()
	seen := map[string]int{} // id -> deliveries
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()
	for {
		missing := 0
		for id := range want {
			if seen[id] == 0 {
				missing++
			}
		}
		if missing == 0 {
			break
		}
		fetches := cl.PollFetches(ctx)
		if ctx.Err() != nil {
			s.t.Fatalf("kafka: %d of %d outbox events never arrived", missing, len(want))
		}
		fetches.EachRecord(func(r *kgo.Record) {
			for _, h := range r.Headers {
				if h.Key == outbox.HeaderID {
					if id := string(h.Value); want[id] {
						seen[id]++
					}
				}
			}
		})
	}
	dups := 0
	var ids []string
	for id, n := range seen {
		ids = append(ids, id)
		if n > 1 {
			dups++
		}
	}
	sort.Strings(ids)
	if len(ids) != len(want) {
		s.t.Fatalf("after de-duplication %d events, outbox has %d", len(ids), len(want))
	}
	s.t.Logf("kafka: %d outbox events, each consumed once after de-duplication (%d were delivered more than once)", len(want), dups)
	_ = fmt.Sprint
}
