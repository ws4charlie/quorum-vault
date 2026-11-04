package server_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// flakySealer wraps the test sealer and fails like a token that went away.
type flakySealer struct {
	*testenv.StaticSealer
	down atomic.Bool
}

func (f *flakySealer) Open(aad, ct []byte) ([]byte, error) {
	if f.down.Load() {
		return nil, &server.UnavailableError{Msg: "hsm: C_Decrypt: CKR_DEVICE_ERROR"}
	}
	return f.StaticSealer.Open(aad, ct)
}

// An HSM error while unsealing at run time is UNAVAILABLE and the service keeps running.
func TestHSMErrorAtRuntimeIsUnavailableNotACrash(t *testing.T) {
	fs := &flakySealer{StaticSealer: testenv.NewStaticSealer(t)}
	p := startPair(t, pairOpts{sealerA: fs})
	ctx := ctx30(t)
	p.dkg(t, "ks", pb.Curve_CURVE_ED25519)
	d := p.derive(t, "ks", []uint32{1}, []uint32{0})
	// a refresh drops the cached keyset, so the next use must unseal again
	_, err := p.Client.Refresh(ctx, &pb.RefreshRequest{KeysetId: "ks", Admin: p.Env.Admin("refresh", "ks")})
	mustOK(t, err)
	fs.down.Store(true)
	req := &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("m"), JobId: "hsm-down"}
	_, err = p.Client.Sign(ctx, req)
	wantKind(t, err, codes.Unavailable, pb.ErrorKind_ERROR_KIND_UNAVAILABLE)
	if _, err := p.Client.Health(ctx, &pb.HealthRequest{}); err != nil {
		t.Fatalf("service died: %v", err)
	}
	fs.down.Store(false)
	req.JobId = "hsm-up"
	_, err = p.Client.Sign(ctx, req)
	mustOK(t, err)
}

// Concurrent Refresh on one keyset is refused. Signs that run while a refresh runs are never a cryptographic failure: they
// either complete on the old generation or wait/answer UNAVAILABLE (retry), and the keyset is not frozen.
func TestConcurrentRefreshRefusedAndSignsSurviveRefresh(t *testing.T) {
	p := startPair(t, pairOpts{})
	ctx := ctx30(t)
	p.dkg(t, "ks", pb.Curve_CURVE_ED25519)
	d := p.derive(t, "ks", []uint32{1}, []uint32{0})

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = p.Client.Refresh(ctx, &pb.RefreshRequest{KeysetId: "ks", Admin: p.Env.Admin("refresh", "ks")})
		}(i)
	}
	// signs while the refreshes run
	var bad atomic.Int32
	stop := make(chan struct{})
	var sw sync.WaitGroup
	var n atomic.Int32
	for w := 0; w < 4; w++ {
		sw.Add(1)
		go func(w int) {
			defer sw.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				_, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("m"),
					JobId: "during-" + string(rune('a'+w)) + "-" + string(rune('a'+i%26)) + string(rune('a'+i/26))})
				n.Add(1)
				if err != nil {
					if k, _ := server.KindOfStatus(err); k != pb.ErrorKind_ERROR_KIND_UNAVAILABLE && k != pb.ErrorKind_ERROR_KIND_LIMIT {
						t.Errorf("sign during refresh: %v", err)
						bad.Add(1)
					}
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	sw.Wait()
	ok, refused := 0, 0
	for _, e := range errs {
		if e == nil {
			ok++
		} else if k, _ := server.KindOfStatus(e); k == pb.ErrorKind_ERROR_KIND_LIMIT {
			refused++
		}
	}
	if ok != 1 || refused != 1 {
		t.Fatalf("two concurrent refreshes: %v / %v (want one success, one refused as already running)", errs[0], errs[1])
	}
	h, _ := p.Client.Health(ctx, &pb.HealthRequest{})
	for _, k := range h.Keysets {
		if k.Frozen || k.Generation != 2 {
			t.Fatalf("keyset after a refresh under load: %+v", k)
		}
	}
	t.Logf("%d signs ran while the refresh ran; none was a cryptographic failure", n.Load())
	// and signing works afterwards
	_, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: d.KeyId, Algorithm: pb.Algorithm_ALGORITHM_ED25519, Digest: []byte("m"), JobId: "after"})
	mustOK(t, err)
}

// Nothing secret in logs, in the records on disk, or in error messages during a full flow with failures.
func TestNoShareBytesInLogsRecordsOrErrors(t *testing.T) {
	var logA, logB syncBuf
	p := startPair(t, pairOpts{logA: &logA, logB: &logB})
	ctx := ctx30(t)
	var msgs []string
	note := func(err error) {
		if err != nil {
			msgs = append(msgs, err.Error())
		}
	}
	for _, c := range []pb.Curve{pb.Curve_CURVE_SECP256K1, pb.Curve_CURVE_ED25519} {
		id := "ks-" + c.String()
		p.dkg(t, id, c)
		d := p.derive(t, id, []uint32{44, 60, 0}, []uint32{0})
		alg, dg := pb.Algorithm_ALGORITHM_ED25519, []byte("message")
		if c == pb.Curve_CURVE_SECP256K1 {
			alg, dg = pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, digest(1)
		}
		_, err := p.Client.Sign(ctx, &pb.SignRequest{KeyId: d.KeyId, Algorithm: alg, Digest: dg, JobId: "j-" + id})
		mustOK(t, err)
		_, err = p.Client.Refresh(ctx, &pb.RefreshRequest{KeysetId: id, Admin: p.Env.Admin("refresh", id)})
		mustOK(t, err)
		// failures: wrong digest for the job, unknown key, bad input, bad admin signature, unknown keyset
		_, err = p.Client.Sign(ctx, &pb.SignRequest{KeyId: d.KeyId, Algorithm: alg, Digest: append(dg, 1), JobId: "j-" + id})
		note(err)
		_, err = p.Client.Sign(ctx, &pb.SignRequest{KeyId: "nope", Algorithm: alg, Digest: dg, JobId: "x-" + id})
		note(err)
		_, err = p.Client.Refresh(ctx, &pb.RefreshRequest{KeysetId: id})
		note(err)
		_, err = p.Client.Derive(ctx, &pb.DeriveRequest{KeysetId: "missing", HardenedPath: []uint32{1}})
		note(err)
		_, err = p.Client.DKG(ctx, &pb.DKGRequest{KeysetId: id, Curve: c, Admin: p.Env.Admin("dkg", id)})
		note(err)
	}
	// plaintext keysets, taken from the same stores the parties use
	var needles [][]byte
	for _, role := range []string{"A", "B"} {
		for _, id := range []string{"ks-" + pb.Curve_CURVE_SECP256K1.String(), "ks-" + pb.Curve_CURVE_ED25519.String()} {
			blob := p.PlainKeyset(t, role, id)
			for off := 0; off+24 <= len(blob); off += 48 {
				w := blob[off : off+24]
				needles = append(needles, append([]byte(nil), w...), []byte(hex.EncodeToString(w)), []byte(base64.StdEncoding.EncodeToString(w)), []byte(base64.RawStdEncoding.EncodeToString(w)))
			}
		}
	}
	if len(needles) < 40 {
		t.Fatalf("too few needles (%d)", len(needles))
	}
	haystacks := map[string][]byte{"log A": []byte(logA.String()), "log B": []byte(logB.String()), "errors": []byte(strings.Join(msgs, "\n"))}
	for _, role := range []string{"A", "B"} {
		filepath.Walk(filepath.Join(p.Env.Dir, "data-"+role), func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(p.Env.Dir, path)
			if strings.Contains(rel, "keysets/") && strings.HasSuffix(rel, ".json") && !strings.HasSuffix(rel, "state.json") {
				return nil // the sealed generations: checked below that they do NOT contain the plaintext either
			}
			raw, _ := os.ReadFile(path)
			haystacks[rel] = raw
			return nil
		})
	}
	sealedFiles := 0
	for _, role := range []string{"A", "B"} {
		filepath.Walk(filepath.Join(p.Env.Dir, "data-"+role, "keysets"), func(path string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() && !strings.HasSuffix(path, "state.json") {
				raw, _ := os.ReadFile(path)
				haystacks["sealed "+path] = raw
				sealedFiles++
			}
			return nil
		})
	}
	for name, h := range haystacks {
		for _, n := range needles {
			if bytes.Contains(h, n) {
				t.Fatalf("share bytes found in %s", name)
			}
		}
	}
	t.Logf("checked %d needles against logs, %d error messages, job/key/state/backup records and %d sealed files: no share bytes", len(needles), len(msgs), sealedFiles)
}
