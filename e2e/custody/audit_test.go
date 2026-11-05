package custody_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

// auditTypes returns the event types in a chain, in order.
func auditTypes(t *testing.T, ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) []string {
	t.Helper()
	rows, err := q.Query(ctx, `SELECT type FROM audit_log ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ty string
		rows.Scan(&ty)
		out = append(out, ty)
	}
	return out
}

func has(have []string, want string) bool {
	for _, h := range have {
		if h == want {
			return true
		}
	}
	return false
}

// requireAudit waits until the chainer has chained every audit event of the flow, then requires that the core chain holds each
// wanted event type and verifies through the API.
func (s *system) requireAudit(want ...string) {
	s.t.Helper()
	s.waitFor(60*time.Second, "all audit events chained", func() bool {
		return s.count(`SELECT count(*) FROM outbox WHERE topic='qv.audit' AND chained_at IS NULL`) == 0
	})
	got := auditTypes(s.t, s.ctx, s.pool)
	for _, w := range want {
		if !has(got, w) {
			s.t.Errorf("the audit chain has no %q event; it has %v", w, got)
		}
	}
	code, out := s.call("GET", "/v2/audit/verify", nil, nil)
	if code != 200 || out["ok"] != true {
		s.t.Fatalf("/v2/audit/verify: %d %v", code, out)
	}
}

// guardPool opens the gateway's own database.
func (s *system) guardPool() *pgx.Conn {
	c, err := pgx.Connect(s.ctx, s.guardDSN)
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

// requireGatewayAudit requires the gateway's own chain to hold the wanted decision types, and the chain to verify.
func (s *system) requireGatewayAudit(want ...string) {
	s.t.Helper()
	c := s.guardPool()
	var got []string
	s.waitFor(30*time.Second, "gateway audit records", func() bool {
		got = auditTypes(s.t, s.ctx, c)
		for _, w := range want {
			if !has(got, w) {
				return false
			}
		}
		return true
	})
	if ok, bad, err := audit.VerifyChain(s.ctx, c); err != nil || !ok {
		s.t.Fatalf("gateway chain: ok=%v bad=%d err=%v", ok, bad, err)
	}
}

// requireAnchors reads the published heads back from Kafka and checks both chains against them with the verify commands of the
// binaries: the anchors of this system's core chain and gateway chain must all agree with their databases.
func (s *system) requireAnchors() {
	s.t.Helper()
	cl, err := kgo.NewClient(kgo.SeedBrokers("127.0.0.1:19092"), kgo.ConsumeTopics(outbox.TopicAuditHeads),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	if err != nil {
		s.t.Fatal(err)
	}
	defer cl.Close()
	// Wait until both chains have published a head that matches their current tail.
	coreHead, _ := audit.Head(s.ctx, s.pool, s.auditSrc+"-core")
	gwHead, _ := audit.Head(s.ctx, s.guardPool(), s.auditSrc+"-gateway")
	seenCore, seenGw := false, false
	var lines bytes.Buffer
	ctx, cancel := context.WithTimeout(s.ctx, 60*time.Second)
	defer cancel()
	for !(seenCore && seenGw) {
		fetches := cl.PollFetches(ctx)
		if ctx.Err() != nil {
			s.t.Fatalf("anchors never arrived (core %v, gateway %v)", seenCore, seenGw)
		}
		fetches.EachRecord(func(r *kgo.Record) {
			var a audit.Anchor
			if json.Unmarshal(r.Value, &a) != nil || !strings.HasPrefix(a.Source, s.auditSrc) {
				return
			}
			lines.Write(r.Value)
			lines.WriteByte('\n')
			if a.Source == coreHead.Source && a.Seq >= coreHead.Seq {
				seenCore = true
			}
			if a.Source == gwHead.Source && a.Seq >= gwHead.Seq {
				seenGw = true
			}
		})
	}
	file := filepath.Join(s.dir, "anchors.jsonl")
	if err := os.WriteFile(file, lines.Bytes(), 0o600); err != nil {
		s.t.Fatal(err)
	}
	run := func(bin, dsn, source string) {
		out, err := exec.Command(filepath.Join(binDir, bin), "verify", "-dsn", dsn, "-anchors", file, "-source", source).CombinedOutput()
		if err != nil {
			s.t.Fatalf("%s verify: %v\n%s", bin, err, out)
		}
		s.t.Logf("%s verify: %s", bin, strings.TrimSpace(string(out)))
	}
	run("qv-relay", s.bizDSN, s.auditSrc+"-core")
	run("qv-gateway", s.guardDSN, s.auditSrc+"-gateway")
}
