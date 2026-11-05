package cosigner_test

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/cosigner"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/gateway/gatewaytest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

type env struct {
	t   *testing.T
	h   *gatewaytest.Harness
	c   *cosigner.Cosigner
	pub []byte // compressed hot key
	hot common.Address
}

func newEnv(t *testing.T) *env {
	t.Helper()
	key, _ := crypto.GenerateKey()
	hot := crypto.PubkeyToAddress(key.PublicKey)
	h := gatewaytest.New(t, 31337, hot)
	pool, _ := gatewaytest.NewGuardDB(t)
	guard, err := gateway.OpenGuard(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cosigner.New(h.Cfg, guard, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, h: h, c: c, pub: crypto.CompressPubkey(&key.PublicKey), hot: hot}
}

func (e *env) req(j signjob.Job) wire.Request {
	pkg, err := gateway.EncodePackage(j)
	if err != nil {
		e.t.Fatal(err)
	}
	return wire.Request{JobID: j.ID, KeyID: "k", KeysetID: "ks", Algorithm: int32(pb.Algorithm_ALGORITHM_ECDSA_SECP256K1),
		Digest: j.Digest, IntentPackage: pkg, PublicKey: e.pub}
}

func (e *env) allow(j signjob.Job) {
	e.t.Helper()
	if r := e.c.Decide(context.Background(), e.req(j)); !r.Allow {
		e.t.Fatalf("job %s refused: %s", j.ID, r.Reason)
	}
}

func (e *env) refuse(r wire.Request, code string) {
	e.t.Helper()
	got := e.c.Decide(context.Background(), r)
	if got.Allow || !strings.HasPrefix(got.Reason, code+":") {
		e.t.Fatalf("want refusal %q, got allow=%v reason=%q", code, got.Allow, got.Reason)
	}
}

func TestCosignerAllowsApprovedAndRetries(t *testing.T) {
	e := newEnv(t)
	j := e.h.Withdrawal("w1", gatewaytest.AddrUser, 500, 0, "alice")
	e.allow(j)
	e.allow(j) // an identical repeat of an allowed digest is a retry
	e.allow(j)
}

func TestCosignerDecisions(t *testing.T) {
	t.Run("no approval", func(t *testing.T) {
		e := newEnv(t)
		e.refuse(e.req(e.h.Withdrawal("w", gatewaytest.AddrUser, 500, 0)), gateway.ReasonApprovals)
	})
	t.Run("disabled and unknown approvers", func(t *testing.T) {
		e := newEnv(t)
		e.refuse(e.req(e.h.Withdrawal("w", gatewaytest.AddrUser, 500, 0, "dave")), gateway.ReasonApprovals)
		j := e.h.Withdrawal("w2", gatewaytest.AddrUser, 500, 0, "alice")
		j.Approvals[0].Actor = "mallory"
		e.refuse(e.req(j), gateway.ReasonApprovals)
	})
	t.Run("not enough approvals for the tier", func(t *testing.T) {
		e := newEnv(t)
		e.refuse(e.req(e.h.Withdrawal("w", gatewaytest.AddrUser, 2000, 0, "alice")), gateway.ReasonTier)
		e.allow(e.h.Withdrawal("w2", gatewaytest.AddrUser, 2000, 1, "alice", "bob"))
	})
	t.Run("approved intent, changed destination in the payload", func(t *testing.T) {
		e := newEnv(t)
		j := e.h.Withdrawal("w", gatewaytest.AddrUser, 500, 0, "alice")
		evil := e.h.Withdrawal("w-evil", gatewaytest.AddrEvil, 500, 0, "alice") // same nonce, other destination
		j.Payload, j.Digest = evil.Payload, evil.Digest
		e.refuse(e.req(j), gateway.ReasonTx)
	})
	t.Run("approved intent, changed amount", func(t *testing.T) {
		e := newEnv(t)
		j := e.h.Withdrawal("w", gatewaytest.AddrUser, 500, 0, "alice")
		big := e.h.Withdrawal("w-big", gatewaytest.AddrUser, 4000, 0, "alice")
		j.Payload, j.Digest = big.Payload, big.Digest
		e.refuse(e.req(j), gateway.ReasonTx)
	})
	t.Run("digest of the request differs from the package", func(t *testing.T) {
		e := newEnv(t)
		j := e.h.Withdrawal("w", gatewaytest.AddrUser, 500, 0, "alice")
		r := e.req(j)
		r.Digest = bytes.Repeat([]byte{7}, 32)
		e.refuse(r, gateway.ReasonTx)
	})
	t.Run("package for another job id", func(t *testing.T) {
		e := newEnv(t)
		r := e.req(e.h.Withdrawal("w", gatewaytest.AddrUser, 500, 0, "alice"))
		r.JobID = "other"
		e.refuse(r, gateway.ReasonIntent)
	})
	t.Run("garbage or missing package", func(t *testing.T) {
		e := newEnv(t)
		r := e.req(e.h.Withdrawal("w", gatewaytest.AddrUser, 500, 0, "alice"))
		r.IntentPackage = []byte("{}")
		e.refuse(r, gateway.ReasonIntent)
		r.IntentPackage = nil
		e.refuse(r, gateway.ReasonIntent)
		r.IntentPackage = bytes.Repeat([]byte("x"), 1000)
		e.refuse(r, gateway.ReasonIntent)
	})
	t.Run("replay at nonce+1 of an approved, signed intent", func(t *testing.T) {
		e := newEnv(t)
		e.allow(e.h.Withdrawal("w", gatewaytest.AddrUser, 500, 0, "alice"))
		again := e.h.Withdrawal("w", gatewaytest.AddrUser, 500, 1, "alice") // same intent id and hash, new nonce
		e.refuse(e.req(again), gateway.ReasonNonceChanged)
	})
	t.Run("another intent at a used nonce", func(t *testing.T) {
		e := newEnv(t)
		e.allow(e.h.Withdrawal("a", gatewaytest.AddrUser, 500, 0, "alice"))
		e.refuse(e.req(e.h.Withdrawal("b", gatewaytest.AddrUser, 600, 0, "alice")), gateway.ReasonNonceTaken)
	})
	t.Run("fee above the cap", func(t *testing.T) {
		e := newEnv(t)
		in := signjob.Intent{Kind: "withdrawal", ID: "w-fee", Asset: "ETH", To: gatewaytest.AddrUser.Hex(), Amount: "500"}
		spec := gatewaytest.ETH(gatewaytest.AddrUser, 500, 0)
		spec.Gas, spec.FeeCap, spec.Tip = 21000, big.NewInt(1e12), big.NewInt(1e12) // 21000 * 1e12 = 2.1e16 > 3e14
		e.refuse(e.req(e.h.Job("fee", in, spec, "alice")), gateway.ReasonTx)
	})
	t.Run("splitting past the daily cap", func(t *testing.T) {
		e := newEnv(t)
		e.allow(e.h.Withdrawal("s1", gatewaytest.AddrUser, 4000, 0, "alice", "bob"))
		e.allow(e.h.Withdrawal("s2", gatewaytest.AddrUser, 4000, 1, "alice", "bob"))
		e.refuse(e.req(e.h.Withdrawal("s3", gatewaytest.AddrUser, 4000, 2, "alice", "bob")), gateway.ReasonDailyCap)
	})
	t.Run("over the per-transaction cap", func(t *testing.T) {
		e := newEnv(t)
		e.refuse(e.req(e.h.Withdrawal("big", gatewaytest.AddrUser, 5001, 0, "alice", "bob")), gateway.ReasonPerTxCap)
	})
	t.Run("expired or open-ended approval", func(t *testing.T) {
		e := newEnv(t)
		in := signjob.Intent{Kind: "withdrawal", ID: "w-old", Asset: "ETH", To: gatewaytest.AddrUser.Hex(), Amount: "500", NotAfter: time.Now().Add(-time.Minute).Unix()}
		e.refuse(e.req(e.h.Job("old", in, gatewaytest.ETH(gatewaytest.AddrUser, 500, 0), "alice")), gateway.ReasonExpired)
	})
	t.Run("the key to sign with is not the sender's", func(t *testing.T) {
		e := newEnv(t)
		other, _ := crypto.GenerateKey()
		r := e.req(e.h.Withdrawal("w", gatewaytest.AddrUser, 500, 0, "alice"))
		r.PublicKey = crypto.CompressPubkey(&other.PublicKey)
		got := e.c.Decide(context.Background(), r)
		if got.Allow || !strings.HasPrefix(got.Reason, "signer_key_mismatch") {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("missing or malformed key, wrong algorithm, wrong digest size", func(t *testing.T) {
		e := newEnv(t)
		r := e.req(e.h.Withdrawal("w", gatewaytest.AddrUser, 500, 0, "alice"))
		for name, mut := range map[string]func(*wire.Request){
			"no key":       func(r *wire.Request) { r.PublicKey = nil },
			"bad key":      func(r *wire.Request) { r.PublicKey = bytes.Repeat([]byte{2}, 33) },
			"ed25519":      func(r *wire.Request) { r.Algorithm = int32(pb.Algorithm_ALGORITHM_ED25519) },
			"short digest": func(r *wire.Request) { r.Digest = r.Digest[:31] },
			"no job id":    func(r *wire.Request) { r.JobID = "" },
		} {
			x := r
			mut(&x)
			if got := e.c.Decide(context.Background(), x); got.Allow {
				t.Errorf("%s: allowed", name)
			}
		}
	})
}

// The cosigner's guard is its own: what the gateway's guard recorded is invisible to it, and vice versa.
func TestCosignerCountsFromItsOwnStore(t *testing.T) {
	a, b := newEnv(t), newEnv(t)
	a.allow(a.h.Withdrawal("s1", gatewaytest.AddrUser, 4000, 0, "alice", "bob"))
	a.allow(a.h.Withdrawal("s2", gatewaytest.AddrUser, 4000, 1, "alice", "bob"))
	// b has its own database: no history, so a request that a's guard would refuse is allowed by b's.
	b.allow(b.h.Withdrawal("s3", gatewaytest.AddrUser, 4000, 0, "alice", "bob"))
}

func TestSocketHandlerAndMode(t *testing.T) {
	e := newEnv(t)
	sock := filepath.Join(t.TempDir(), "cosigner.sock")
	ln, err := cosigner.ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: e.c.Handler()}
	go srv.Serve(ln)
	defer srv.Close()
	fi, err := os.Stat(sock)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v err %v", fi.Mode(), err)
	}
	cl := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	post := func(body []byte) (int, wire.Response) {
		resp, err := cl.Post("http://cosigner"+wire.Path, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out wire.Response
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	good, _ := json.Marshal(e.req(e.h.Withdrawal("w", gatewaytest.AddrUser, 500, 0, "alice")))
	if code, r := post(good); code != 200 || !r.Allow {
		t.Fatalf("%d %+v", code, r)
	}
	if code, _ := post([]byte(`{"nonsense":1}`)); code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", code)
	}
	if code, _ := post([]byte(`not json`)); code != http.StatusBadRequest {
		t.Fatalf("junk: %d", code)
	}
	// a stale socket file is replaced; a regular file at the path is not clobbered
	file := filepath.Join(t.TempDir(), "regular")
	os.WriteFile(file, []byte("x"), 0o600)
	if _, err := cosigner.ListenUnix(file); err == nil {
		t.Fatal("ListenUnix replaced a regular file")
	}
}

// A guard database failure is an outage, not a refusal: no decision field is set, Unavailable is.
func TestGuardDatabaseDownIsUnavailableNotRefused(t *testing.T) {
	key, _ := crypto.GenerateKey()
	hot := crypto.PubkeyToAddress(key.PublicKey)
	h := gatewaytest.New(t, 31337, hot)
	pool, _ := gatewaytest.NewGuardDB(t)
	guard, err := gateway.OpenGuard(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cosigner.New(h.Cfg, guard, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, h: h, c: c, pub: crypto.CompressPubkey(&key.PublicKey), hot: hot}
	e.allow(h.Withdrawal("up", gatewaytest.AddrUser, 100, 0, "alice"))
	pool.Close() // the guard database goes away
	got := c.Decide(context.Background(), e.req(h.Withdrawal("down", gatewaytest.AddrUser, 100, 1, "alice")))
	if got.Allow || !got.Unavailable {
		t.Fatalf("want unavailable and not allowed, got %+v", got)
	}
	// A refusal needs its audit record first: with the guard database gone it cannot be recorded, so it is an outage too
	// (the answer is still "no"). With the database up, a refusal is a decision.
	got = c.Decide(context.Background(), wire.Request{JobID: "x", Algorithm: int32(pb.Algorithm_ALGORITHM_ED25519)})
	if got.Allow || !got.Unavailable {
		t.Fatalf("a refusal that cannot be recorded is unavailable, got %+v", got)
	}
	pool2, _ := gatewaytest.NewGuardDB(t)
	guard2, err := gateway.OpenGuard(context.Background(), pool2)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := cosigner.New(h.Cfg, guard2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got = c2.Decide(context.Background(), wire.Request{JobID: "x", Algorithm: int32(pb.Algorithm_ALGORITHM_ED25519)})
	if got.Allow || got.Unavailable {
		t.Fatalf("a malformed request is a refusal, got %+v", got)
	}
}

// Party B's own gate repeats the hot-to-cold rules from its own config and store: a rogue party A (or a gateway that was
// talked into it) cannot get B to take part in a move to any other address, or past the rate and the daily cap.
func TestCosignerToCold(t *testing.T) {
	t.Run("to the configured cold address, no approvals", func(t *testing.T) {
		e := newEnv(t)
		e.allow(e.h.ToCold("c1", gatewaytest.AddrCold, gatewaytest.AddrCold, 2000, 0))
	})
	t.Run("another destination", func(t *testing.T) {
		e := newEnv(t)
		e.refuse(e.req(e.h.ToCold("c2", gatewaytest.AddrEvil, gatewaytest.AddrEvil, 100, 0)), gateway.ReasonTx)
		e.refuse(e.req(e.h.ToCold("c3", gatewaytest.AddrCold, gatewaytest.AddrEvil, 100, 0)), gateway.ReasonTx)
		e.refuse(e.req(e.h.ToCold("c4", gatewaytest.AddrEvil, gatewaytest.AddrEvil, 100, 0, "alice", "bob")), gateway.ReasonTx)
	})
	t.Run("rate and daily cap from its own store", func(t *testing.T) {
		e := newEnv(t)
		e.allow(e.h.ToCold("r1", gatewaytest.AddrCold, gatewaytest.AddrCold, 4000, 0))
		e.refuse(e.req(e.h.ToCold("r2", gatewaytest.AddrCold, gatewaytest.AddrCold, 3000, 1, "alice", "bob")), gateway.ReasonToColdCap)
		e.allow(e.h.ToCold("r3", gatewaytest.AddrCold, gatewaytest.AddrCold, 1000, 1))
		e.refuse(e.req(e.h.ToCold("r4", gatewaytest.AddrCold, gatewaytest.AddrCold, 100, 2)), gateway.ReasonToColdRate)
	})
}

// Party B's own gate repeats the rebalance rules from its own config and store: a rogue party A cannot get B to take part in a move
// to an address that is not another hot shard of the pool, or past the rate and the daily cap.
func TestCosignerRebalance(t *testing.T) {
	t.Run("to another shard, no approvals", func(t *testing.T) {
		e := newEnv(t)
		e.allow(e.h.Rebalance("b1", gatewaytest.AddrShard2, gatewaytest.AddrShard2, 2000, 0))
	})
	t.Run("destination outside the pinned shards", func(t *testing.T) {
		e := newEnv(t)
		e.refuse(e.req(e.h.Rebalance("b2", gatewaytest.AddrEvil, gatewaytest.AddrEvil, 100, 0)), gateway.ReasonTx)
		e.refuse(e.req(e.h.Rebalance("b3", gatewaytest.AddrShard2, gatewaytest.AddrEvil, 100, 0)), gateway.ReasonTx)
		e.refuse(e.req(e.h.Rebalance("b4", gatewaytest.AddrEvil, gatewaytest.AddrEvil, 100, 0, "alice", "bob")), gateway.ReasonTx)
		e.refuse(e.req(e.h.Rebalance("b5", gatewaytest.AddrOtherPl, gatewaytest.AddrOtherPl, 100, 0)), gateway.ReasonTx)
		e.refuse(e.req(e.h.Rebalance("b6", gatewaytest.AddrCold, gatewaytest.AddrCold, 100, 0)), gateway.ReasonTx)
	})
	t.Run("rate and daily cap from its own store", func(t *testing.T) {
		e := newEnv(t)
		e.allow(e.h.Rebalance("r1", gatewaytest.AddrShard2, gatewaytest.AddrShard2, 4000, 0))
		e.refuse(e.req(e.h.Rebalance("r2", gatewaytest.AddrShard2, gatewaytest.AddrShard2, 3000, 1, "alice", "bob")), gateway.ReasonRebalanceCap)
		e.allow(e.h.Rebalance("r3", gatewaytest.AddrShard2, gatewaytest.AddrShard2, 1000, 1))
		e.refuse(e.req(e.h.Rebalance("r4", gatewaytest.AddrShard2, gatewaytest.AddrShard2, 100, 2)), gateway.ReasonRebalanceRate)
	})
}

// The cosigner keeps its own audit chain in its own guard database: what it allowed, and every refusal with its reason,
// including the ones it makes before the shared decision code runs.
func TestCosignerAuditsEveryDecision(t *testing.T) {
	key, _ := crypto.GenerateKey()
	hot := crypto.PubkeyToAddress(key.PublicKey)
	h := gatewaytest.New(t, 31337, hot)
	pool, _ := gatewaytest.NewGuardDB(t)
	guard, err := gateway.OpenGuard(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cosigner.New(h.Cfg, guard, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, h: h, c: c, pub: crypto.CompressPubkey(&key.PublicKey), hot: hot}
	e.allow(h.Withdrawal("ok", gatewaytest.AddrUser, 100, 0, "alice"))
	e.refuse(e.req(h.Withdrawal("noapp", gatewaytest.AddrUser, 100, 1)), gateway.ReasonApprovals)
	if r := c.Decide(context.Background(), wire.Request{JobID: "x", Algorithm: int32(pb.Algorithm_ALGORITHM_ED25519)}); r.Allow || r.Unavailable {
		t.Fatalf("got %+v", r)
	}
	rows, err := pool.Query(context.Background(), `SELECT actor, type, coalesce(payload->>'reason', '') FROM audit_log ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var a, ty, reason string
		if err := rows.Scan(&a, &ty, &reason); err != nil {
			t.Fatal(err)
		}
		if a != "qv-cosigner" {
			t.Errorf("actor %q", a)
		}
		got = append(got, ty+":"+reason)
	}
	if len(got) != 3 || got[0] != "sign.allowed:" || !strings.HasPrefix(got[1], "sign.refused:"+gateway.ReasonApprovals) ||
		!strings.HasPrefix(got[2], "sign.refused:cosigner: only secp256k1") {
		t.Fatalf("audit = %q", got)
	}
}
