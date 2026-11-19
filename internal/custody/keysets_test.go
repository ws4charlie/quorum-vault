package custody

import (
	"context"
	"strings"
	"testing"
)

func TestBootstrapRegistersGenerationOneAndResolvesThroughIt(t *testing.T) {
	s, _ := newSvc(t)
	ctx := context.Background()
	rows, err := s.Pool.Query(ctx, `SELECT shard_id, generation, state, address FROM keysets ORDER BY shard_id`)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for rows.Next() {
		var id, state, addr string
		var gen int
		if err := rows.Scan(&id, &gen, &state, &addr); err != nil {
			t.Fatal(err)
		}
		if gen != 1 || state != "active" {
			t.Errorf("%s: generation %d state %s", id, gen, state)
		}
		got[id] = addr
	}
	rows.Close()
	if len(got) != 2 { // 2 shards; the assets of a shard share one keyset
		t.Fatalf("%d keysets, want 2: %v", len(got), got)
	}
	for i, want := range s.Cfg.HotShards {
		part := s.Cfg.PartitionKey(s.Cfg.Native, i).String()
		a, idx, err := s.ShardAddressOf(part)
		if err != nil || idx != i || a != want.Hex() {
			t.Errorf("ShardAddressOf(%s) = %s, %d, %v; config says %s", part, a, idx, err, want.Hex())
		}
		if got[string(s.Cfg.shardIDOf(i))] != want.Hex() {
			t.Errorf("registry address of shard %d = %q", i, got[string(s.Cfg.shardIDOf(i))])
		}
	}
	// a second Bootstrap adds nothing
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM keysets`).Scan(&n)
	if n != 2 {
		t.Errorf("%d keysets after a second Bootstrap", n)
	}
}

func TestBootstrapRefusesAShardWhoseAddressChanged(t *testing.T) {
	s, _ := newSvc(t)
	ctx := context.Background()
	s.Cfg.HotShards[1][0] ^= 0xff // the configuration now says another address for shard 1
	err := s.Bootstrap(ctx)
	if err == nil || !strings.Contains(err.Error(), "another address") {
		t.Fatalf("Bootstrap = %v, want a refusal for the changed address", err)
	}
}
