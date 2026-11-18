package auditchain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
)

// ---- logic without any service (these run under -short) ----

// memArchive is an Archive in a map: it has no lock, it only tests the logic around it.
type memArchive struct {
	mu   sync.Mutex
	m    map[string]audit.Anchor
	puts int
	fail atomic.Bool
}

func newMem() *memArchive { return &memArchive{m: map[string]audit.Anchor{}} }

func (m *memArchive) Put(_ context.Context, a audit.Anchor) (bool, error) {
	if m.fail.Load() {
		return false, errors.New("store down")
	}
	k, err := ArchiveKey(a)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	if _, ok := m.m[k]; ok {
		return false, nil
	}
	m.m[k] = a
	return true, nil
}

func (m *memArchive) Anchors(_ context.Context, source string) ([]audit.Anchor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []audit.Anchor
	for _, a := range m.m {
		if source == "" || a.Source == source {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *memArchive) CheckLock(context.Context, time.Duration) error { return nil }

func jsonHead(t *testing.T, a audit.Anchor) []byte {
	t.Helper()
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestArchiveKeyIsDeterministicPerHead(t *testing.T) {
	a := head("core", 12)
	k1, err := ArchiveKey(a)
	if err != nil {
		t.Fatal(err)
	}
	b := a
	b.At = a.At.Add(time.Hour) // a head published again later is the same head
	if k2, _ := ArchiveKey(b); k2 != k1 {
		t.Fatalf("same head, two keys: %s %s", k1, k2)
	}
	for name, bad := range map[string]audit.Anchor{
		"path in the source": {Source: "../core", Seq: 1, Hash: a.Hash},
		"empty source":       {Seq: 1, Hash: a.Hash},
		"short hash":         {Source: "core", Seq: 1, Hash: "ab"},
		"upper-case hash":    {Source: "core", Seq: 1, Hash: strings.Repeat("AB", 32)},
		"negative seq":       {Source: "core", Seq: -1, Hash: a.Hash},
	} {
		if _, err := ArchiveKey(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := a
	c.Hash = strings.Repeat("cd", 32)
	if k3, _ := ArchiveKey(c); k3 == k1 {
		t.Error("a different hash has the same key")
	}
}

func TestHandleStoresOnceAndSkipsWhatIsNotAHead(t *testing.T) {
	mem := newMem()
	a := NewArchiver(mem, ArchiverOptions{Retention: 24 * time.Hour})
	ctx := context.Background()
	h := head("core", 3)
	later := h
	later.At = h.At.Add(time.Minute)
	for _, v := range [][]byte{jsonHead(t, h), jsonHead(t, h), jsonHead(t, later), jsonHead(t, head("gateway", 3))} {
		if err := a.Handle(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	if len(mem.m) != 2 || a.stored.Load() != 2 || a.duplicates.Load() != 2 {
		t.Fatalf("objects %d stored %d duplicates %d, want 2 2 2", len(mem.m), a.stored.Load(), a.duplicates.Load())
	}
	for _, junk := range []string{"not json", `{"source":"core"}`, `{"source":"../x","seq":1,"hash":"` + h.Hash + `","at":"2026-01-01T00:00:00Z"}`, ""} {
		if err := a.Handle(ctx, []byte(junk)); err != nil {
			t.Errorf("%q: a value that is not a head must be skipped, got %v", junk, err)
		}
	}
	if len(mem.m) != 2 || a.badRecords.Load() != 4 {
		t.Fatalf("objects %d bad %d", len(mem.m), a.badRecords.Load())
	}
	mem.fail.Store(true)
	if err := a.Handle(ctx, jsonHead(t, head("core", 9))); err == nil {
		t.Fatal("a failed store must be returned, so the same head is tried again")
	}
	if a.storeErrors.Load() != 1 {
		t.Fatalf("store errors %d", a.storeErrors.Load())
	}
}

func TestArchiverMetrics(t *testing.T) {
	a := NewArchiver(newMem(), ArchiverOptions{})
	h := head("core", 1)
	h.At = time.Unix(1_700_000_000, 0)
	if err := a.Handle(context.Background(), jsonHead(t, h)); err != nil {
		t.Fatal(err)
	}
	a.lagRecords.Store(4)
	a.lastProgress.Store(time.Now().Add(-90 * time.Second).UnixNano())
	m := a.Metrics()
	for _, want := range []string{
		"qv_audit_archive_lag_records 4\n", "qv_audit_archive_heads_stored_total 1\n", `qv_audit_archive_errors_total{kind="store"} 0`,
		`qv_audit_archive_last_head_timestamp_seconds{source="core"} 1700000000`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %q:\n%s", want, m)
		}
	}
	if !strings.Contains(m, "qv_audit_archive_lag_seconds 90") && !strings.Contains(m, "qv_audit_archive_lag_seconds 91") {
		t.Errorf("lag seconds with 4 heads waiting for 90 s:\n%s", m)
	}
	a.lagRecords.Store(0)
	if !strings.Contains(a.Metrics(), "qv_audit_archive_lag_seconds 0\n") {
		t.Error("lag seconds must be 0 when nothing waits")
	}
}

func TestArchiveCredentialsFromEnvOrFile(t *testing.T) {
	t.Setenv("QV_ARCHIVE_ACCESS_KEY", "")
	t.Setenv("QV_ARCHIVE_ACCESS_KEY_FILE", "")
	if _, err := envOrFile("QV_ARCHIVE_ACCESS_KEY"); err == nil {
		t.Fatal("no credential must be an error")
	}
	f := filepath.Join(t.TempDir(), "ak")
	os.WriteFile(f, []byte("from-file\n"), 0o600)
	t.Setenv("QV_ARCHIVE_ACCESS_KEY_FILE", f)
	if v, err := envOrFile("QV_ARCHIVE_ACCESS_KEY"); err != nil || v != "from-file" {
		t.Fatalf("file: %q %v", v, err)
	}
	t.Setenv("QV_ARCHIVE_ACCESS_KEY", "from-env")
	if v, _ := envOrFile("QV_ARCHIVE_ACCESS_KEY"); v != "from-env" {
		t.Fatalf("env: %q", v)
	}
}

// ---- against a real store: SeaweedFS in a container the test starts ----

// A bucket that is not locked in COMPLIANCE mode with a long enough default retention is refused, before a single head is read.
func TestArchiverRefusesAWeakBucket(t *testing.T) {
	w := startStore(t)
	ctx := context.Background()
	check := func(mode string, days int32, need time.Duration) error {
		_, arc := w.bucket(t, mode, days)
		a, err := NewS3Archive(arc)
		if err != nil {
			t.Fatal(err)
		}
		// Run is what the binary calls: the refusal comes before it touches Kafka (the broker below does not exist)
		err = NewArchiver(a, ArchiverOptions{Brokers: []string{"127.0.0.1:1"}, Retention: need}).Run(ctx)
		if err == nil {
			t.Fatalf("%s %dd, need %s: the archiver started", mode, days, need)
		}
		return err
	}
	year := 365 * 24 * time.Hour
	for name, c := range map[string]struct {
		mode string
		days int32
		need time.Duration
		say  string
	}{
		"no Object Lock":       {"none", 0, year, "Object Lock"},
		"lock without default": {"", 0, year, "default retention"},
		"governance mode":      {"GOVERNANCE", 400, year, "GOVERNANCE"},
		"shorter retention":    {"COMPLIANCE", 30, year, "shorter than"},
	} {
		if err := check(c.mode, c.days, c.need); !strings.Contains(err.Error(), c.say) {
			t.Errorf("%s: %v (want it to say %q)", name, err, c.say)
		}
	}
	// the same refusals when the check is called on its own, and the accepted bucket
	_, arc := w.bucket(t, "COMPLIANCE", 400)
	a, _ := NewS3Archive(arc)
	if err := a.CheckLock(ctx, year); err != nil {
		t.Fatalf("a compliance bucket with 400 days for a year: %v", err)
	}
	if err := a.CheckLock(ctx, 401*24*time.Hour); err == nil {
		t.Fatal("400 days accepted for 401")
	}
	if err := NewArchiver(a, ArchiverOptions{}).CheckBucket(ctx); err == nil {
		t.Fatal("no retention configured must be refused")
	}
}

// A control for the test above: governance mode lets an administrator bypass the lock, so the same attempt that fails in compliance
// mode succeeds here. If this ever fails, the test of compliance mode no longer shows what it claims to.
func TestWormControlGovernanceModeCanBeBypassed(t *testing.T) {
	w := startWorm(t, "GOVERNANCE", 1)
	ctx := context.Background()
	a := head("core", 1)
	if _, err := w.archive(t).Put(ctx, a); err != nil {
		t.Fatal(err)
	}
	key, _ := ArchiveKey(a)
	rc := w.rootClient(t)
	lv, _ := rc.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &w.bucketName, Prefix: &key})
	if len(lv.Versions) != 1 {
		t.Fatalf("versions %d", len(lv.Versions))
	}
	if _, err := rc.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &w.bucketName, Key: &key, VersionId: lv.Versions[0].VersionId}); err == nil {
		t.Error("governance mode refused a delete without bypass")
	}
	if _, err := rc.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &w.bucketName, Key: &key, VersionId: lv.Versions[0].VersionId, BypassGovernanceRetention: aws.Bool(true)}); err != nil {
		t.Errorf("root could not bypass governance mode: %v (the compliance test proves nothing if even this is refused)", err)
	}
}

// ---- Verify from the archive: a chain in Postgres, heads in the store ----

// chainWithArchive builds a chain of 10 entries, archives the heads at seq 6 and 10, and returns the pool, the archive and the root client.
func chainWithArchive(t *testing.T, store *wormStore) (*pgxpool.Pool, *wormStore, *S3Archive) {
	t.Helper()
	ctx := context.Background()
	w := store.withBucket(t, "COMPLIANCE", 1) // a bucket of its own: heads of another chain would contradict this one
	pool := dbtest.New(t)
	writeAudit(t, pool, 10)
	drain(t, NewChainer(pool, ChainerOptions{}))
	arc := w.archive(t)
	var h []byte
	if err := pool.QueryRow(ctx, `SELECT hash FROM audit_log WHERE seq=6`).Scan(&h); err != nil {
		t.Fatal(err)
	}
	mid := audit.Anchor{Source: "core", Seq: 6, Hash: fmt.Sprintf("%x", h), At: time.Now().UTC()}
	top, err := audit.Head(ctx, pool, "core")
	if err != nil || top.Seq != 10 {
		t.Fatalf("head %+v %v", top, err)
	}
	for _, a := range []audit.Anchor{mid, top} {
		if _, err := arc.Put(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	return pool, w, arc
}

func verifyArchive(pool *pgxpool.Pool, arc Archive, file string) (string, error) {
	var out bytes.Buffer
	err := VerifyAgainst(context.Background(), pool, "core", file, arc, &out)
	return out.String(), err
}

func cutTail(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	disableTriggers(t, pool)
	pool.Exec(context.Background(), `DELETE FROM audit_log WHERE seq > 7`)
	mustVerify(t, pool) // a valid chain that is shorter
}

func rewriteFrom6(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	disableTriggers(t, pool)
	pool.Exec(ctx, `DELETE FROM audit_log WHERE seq > 5`)
	for i := 0; i < 5; i++ {
		tx, _ := pool.Begin(ctx)
		if _, err := audit.AppendTx(ctx, tx, domain.AuditEvent{Actor: "mallory", Type: "test.event", Payload: json.RawMessage(`{"n":0}`)}, ""); err != nil {
			t.Fatal(err)
		}
		tx.Commit(ctx)
	}
	mustVerify(t, pool)
}

func TestVerifyFromTheArchive(t *testing.T) {
	store := startStore(t)
	ctx := context.Background()

	t.Run("an untouched chain passes, from the archive alone and with a file as well", func(t *testing.T) {
		pool, _, arc := chainWithArchive(t, store)
		out, err := verifyArchive(pool, arc, "")
		if err != nil || !strings.Contains(out, "anchors checked 2 (file 0, archive 2)") {
			t.Fatalf("%q %v", out, err)
		}
		out, err = verifyArchive(pool, arc, anchorsFile(t, head("core", 0)))
		if err != nil || !strings.Contains(out, "(file 1, archive 2)") {
			t.Fatalf("%q %v", out, err)
		}
	})
	t.Run("a cut chain is caught", func(t *testing.T) {
		pool, _, arc := chainWithArchive(t, store)
		cutTail(t, pool)
		if _, err := verifyArchive(pool, arc, ""); err == nil || !strings.Contains(err.Error(), "tail was cut off") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a rewritten chain is caught", func(t *testing.T) {
		pool, _, arc := chainWithArchive(t, store)
		rewriteFrom6(t, pool)
		if _, err := verifyArchive(pool, arc, ""); err == nil || !strings.Contains(err.Error(), "was rewritten") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a delete marker over an archived head does not hide it", func(t *testing.T) {
		pool, w, arc := chainWithArchive(t, store)
		top, _ := audit.Head(ctx, pool, "core")
		key, _ := ArchiveKey(top)
		// whoever may delete can make the key look gone: the locked version stays, and verification reads versions
		if _, err := w.rootClient(t).DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &w.bucketName, Key: &key}); err != nil {
			t.Skipf("the store refuses even a delete marker: %v", err)
		}
		cutTail(t, pool)
		if _, err := verifyArchive(pool, arc, ""); err == nil || !strings.Contains(err.Error(), "tail was cut off") {
			t.Fatalf("a head behind a delete marker was not used: %v", err)
		}
	})
	t.Run("a version written over a head under its key is not trusted", func(t *testing.T) {
		pool, w, arc := chainWithArchive(t, store)
		top, _ := audit.Head(ctx, pool, "core")
		key, _ := ArchiveKey(top)
		forged := fmt.Sprintf(`{"source":"core","seq":10,"hash":%q,"at":"2026-01-01T00:00:00Z"}`, strings.Repeat("ee", 32))
		if _, err := arc.cl.PutObject(ctx, &s3.PutObjectInput{Bucket: &w.bucketName, Key: &key, Body: strings.NewReader(forged)}); err != nil {
			t.Skipf("the store refuses a new version: %v", err)
		}
		if _, err := verifyArchive(pool, arc, ""); err == nil || !strings.Contains(err.Error(), "belongs under") {
			t.Fatalf("a forged version passed or failed for another reason: %v", err)
		}
	})
}

// ---- with Kafka: QV_REQUIRE_INFRA=1 (`make infra-up`), QV_KAFKA_BROKERS if not on 19092 ----

// waitLong is waitFor for steps that take a consumer group join (a few seconds).
func waitLong(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 1200; i++ {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition not reached in 60 s")
}

func kafkaBrokersForTest(t *testing.T) []string {
	t.Helper()
	if os.Getenv("QV_REQUIRE_INFRA") != "1" {
		t.Skip("QV_REQUIRE_INFRA != 1")
	}
	b := os.Getenv("QV_KAFKA_BROKERS")
	if b == "" {
		b = "127.0.0.1:19092"
	}
	return strings.Split(b, ",")
}

func newTopic(t *testing.T, brokers []string) string {
	t.Helper()
	topic := "qv.audit.heads.test." + randHex(t, 4)
	cl, err := kgo.NewClient(kgo.DialTLSConfig(pkitest.AdminTLS("", "kafka")), kgo.SeedBrokers(brokers...))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if _, err := kadm.NewClient(cl).CreateTopic(context.Background(), 1, 1, nil, topic); err != nil {
		t.Fatal(err)
	}
	return topic
}

func produce(t *testing.T, brokers []string, topic string, values ...[]byte) {
	t.Helper()
	cl, err := kgo.NewClient(kgo.DialTLSConfig(pkitest.AdminTLS("", "kafka")), kgo.SeedBrokers(brokers...), kgo.RequiredAcks(kgo.AllISRAcks()))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	for _, v := range values {
		if err := cl.ProduceSync(context.Background(), &kgo.Record{Topic: topic, Key: []byte("core"), Value: v}).FirstErr(); err != nil {
			t.Fatal(err)
		}
	}
}

// startArchiver runs an archiver until stop is called; processed reports heads it has handled (stored or already there).
func startArchiver(t *testing.T, arch Archive, brokers []string, topic, group string) (a *Archiver, stop func()) {
	t.Helper()
	a = NewArchiver(arch, ArchiverOptions{KafkaOpts: []kgo.Opt{kgo.DialTLSConfig(pkitest.AdminTLS("", "kafka"))}, Brokers: brokers, Topic: topic, Group: group, Retention: 24 * time.Hour, Retry: 100 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("archiver: %v", err)
			}
		})
	}
	t.Cleanup(stop)
	return a, stop
}

func (a *Archiver) processed() int64 { return a.stored.Load() + a.duplicates.Load() }

func versionsOf(t *testing.T, w *wormStore) (versions, markers int) {
	t.Helper()
	pg := s3.NewListObjectVersionsPaginator(w.rootClient(t), &s3.ListObjectVersionsInput{Bucket: &w.bucketName})
	for pg.HasMorePages() {
		p, err := pg.NextPage(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		versions += len(p.Versions)
		markers += len(p.DeleteMarkers)
	}
	return
}

// A published head lands in the bucket once: also when the same head is published again, when the archiver restarts and when a new
// archiver replays the whole topic from the start.
func TestArchiverStoresEachHeadOnceAcrossReplayAndRestart(t *testing.T) {
	brokers := kafkaBrokersForTest(t)
	w := startWorm(t, "COMPLIANCE", 1)
	arc := w.archive(t)
	topic := newTopic(t, brokers)
	h1, h2, h3, h4 := head("core", 1), head("core", 2), head("gateway", 2), head("core", 3)
	h2again := h2
	h2again.At = h2.At.Add(time.Minute) // the periodic republish of an unchanged head

	produce(t, brokers, topic, jsonHead(t, h1), jsonHead(t, h2), []byte("garbage"), jsonHead(t, h2again), jsonHead(t, h3))
	a1, stop1 := startArchiver(t, arc, brokers, topic, "g1")
	waitLong(t, func() bool { return a1.processed() >= 4 })
	stop1()
	if v, m := versionsOf(t, w); v != 3 || m != 0 {
		t.Fatalf("after the first run: %d versions, %d markers, want 3 0", v, m)
	}

	// restart (same group): only what is new is handled; then a crash-like replay of everything in a new group
	produce(t, brokers, topic, jsonHead(t, h3), jsonHead(t, h4))
	a2, stop2 := startArchiver(t, arc, brokers, topic, "g1")
	waitLong(t, func() bool { return a2.processed() >= 2 })
	stop2()
	if a2.processed() != 2 {
		t.Errorf("the restarted archiver handled %d heads, want only the 2 new records (its offset was committed)", a2.processed())
	}
	a3, stop3 := startArchiver(t, arc, brokers, topic, "replay")
	waitLong(t, func() bool { return a3.processed() >= 6 })
	stop3()
	if a3.stored.Load() != 0 {
		t.Errorf("a full replay stored %d heads again", a3.stored.Load())
	}
	if v, m := versionsOf(t, w); v != 4 || m != 0 {
		t.Fatalf("after replays: %d versions, %d markers, want 4 0", v, m)
	}
	got, err := arc.Anchors(context.Background(), "")
	if err != nil || len(got) != 4 {
		t.Fatalf("anchors %v %v", got, err)
	}
}

// failingArchive refuses to store while down is set.
type failingArchive struct {
	Archive
	down  atomic.Bool
	tried atomic.Int64
}

func (f *failingArchive) Put(ctx context.Context, a audit.Anchor) (bool, error) {
	if f.down.Load() {
		f.tried.Add(1)
		return false, errors.New("archive unreachable")
	}
	return f.Archive.Put(ctx, a)
}

// The offset moves only after the head is stored: an archiver that dies while the archive is down loses nothing, the next one gets the head.
func TestArchiverCommitsOffsetOnlyAfterTheHeadIsStored(t *testing.T) {
	brokers := kafkaBrokersForTest(t)
	w := startWorm(t, "COMPLIANCE", 1)
	real := w.archive(t)
	topic := newTopic(t, brokers)
	h := head("core", 5)
	produce(t, brokers, topic, jsonHead(t, h))

	down := &failingArchive{Archive: real}
	down.down.Store(true)
	a1, stop1 := startArchiver(t, down, brokers, topic, "g")
	waitLong(t, func() bool { return down.tried.Load() >= 2 }) // it keeps trying the same head
	stop1()                                                    // the crash, with the head not stored
	if got, _ := real.Anchors(context.Background(), ""); len(got) != 0 {
		t.Fatalf("a head was stored while the archive was down: %v", got)
	}
	if a1.storeErrors.Load() < 2 {
		t.Errorf("store errors = %d", a1.storeErrors.Load())
	}

	a2, stop2 := startArchiver(t, real, brokers, topic, "g")
	waitLong(t, func() bool { return a2.stored.Load() == 1 })
	stop2()
	if got, _ := real.Anchors(context.Background(), ""); len(got) != 1 || got[0].Hash != h.Hash {
		t.Fatalf("anchors after the restart: %v", got)
	}
}

// The reason for the archive: the Kafka topic can disappear and verification still works, and still catches a cut or rewritten chain.
func TestVerifyWorksFromTheArchiveAfterTheTopicIsDeleted(t *testing.T) {
	brokers := kafkaBrokersForTest(t)
	w := startWorm(t, "COMPLIANCE", 1)
	ctx := context.Background()
	pool := dbtest.New(t)
	writeAudit(t, pool, 10)
	drain(t, NewChainer(pool, ChainerOptions{}))
	top, err := audit.Head(ctx, pool, "core")
	if err != nil {
		t.Fatal(err)
	}
	var h []byte
	pool.QueryRow(ctx, `SELECT hash FROM audit_log WHERE seq=6`).Scan(&h)
	mid := audit.Anchor{Source: "core", Seq: 6, Hash: fmt.Sprintf("%x", h), At: time.Now().UTC()}

	topic := newTopic(t, brokers)
	produce(t, brokers, topic, jsonHead(t, mid), jsonHead(t, top))
	arc := w.archive(t)
	a, stop := startArchiver(t, arc, brokers, topic, "g")
	waitLong(t, func() bool { return a.stored.Load() == 2 })
	stop()

	cl, err := kgo.NewClient(kgo.DialTLSConfig(pkitest.AdminTLS("", "kafka")), kgo.SeedBrokers(brokers...))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if _, err := kadm.NewClient(cl).DeleteTopics(ctx, topic); err != nil {
		t.Fatal(err)
	}
	if out, err := verifyArchive(pool, arc, ""); err != nil || !strings.Contains(out, "archive 2") {
		t.Fatalf("with the topic gone: %q %v", out, err)
	}
	cutTail(t, pool)
	if _, err := verifyArchive(pool, arc, ""); err == nil || !strings.Contains(err.Error(), "tail was cut off") {
		t.Fatalf("cut chain with the topic gone: %v", err)
	}
}
