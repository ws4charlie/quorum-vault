package keys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/db/dbtest"
	"github.com/ws4charlie/quorum-vault/internal/domain"
)

// fakeAuditor records events in memory.
type fakeAuditor struct {
	mu  sync.Mutex
	evs []domain.AuditEvent
}

func (a *fakeAuditor) Append(_ context.Context, ev domain.AuditEvent) (domain.AuditEvent, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ev.Seq = int64(len(a.evs) + 1)
	a.evs = append(a.evs, ev)
	return ev, nil
}

func (a *fakeAuditor) types() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var ts []string
	for _, ev := range a.evs {
		ts = append(ts, ev.Type)
	}
	return ts
}

// fakeMPC stands in for T3's MPC generator: software keys, no destroy.
type fakeMPC struct{}

func (fakeMPC) Backend() domain.Backend { return domain.BackendMPC }

func (fakeMPC) Generate(_ context.Context, walletID string, version int) (domain.Key, error) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		return domain.Key{}, err
	}
	return domain.Key{
		Curve:     domain.CurveSecp256k1,
		Backend:   domain.BackendMPC,
		MPCKeyRef: fmt.Sprintf("%s-v%d", walletID, version),
		PublicKey: crypto.FromECDSAPub(&priv.PublicKey),
		Address:   crypto.PubkeyToAddress(priv.PublicKey).Hex(),
	}, nil
}

// brokenHSM generates keys the DB rejects (no public key) and records destroys.
type brokenHSM struct {
	mu        sync.Mutex
	destroyed []string
}

func (*brokenHSM) Backend() domain.Backend { return domain.BackendHSM }
func (*brokenHSM) Generate(_ context.Context, walletID string, version int) (domain.Key, error) {
	return domain.Key{ID: fmt.Sprintf("00000000-0000-0000-0000-%012d", version), Curve: domain.CurveSecp256k1, HSMKeyID: []byte{1}}, nil
}
func (b *brokenHSM) DestroyKey(_ context.Context, k domain.Key) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.destroyed = append(b.destroyed, k.ID)
	return nil
}

func newRegistry(t *testing.T, gens ...domain.KeyGenerator) (*Registry, *fakeAuditor, *pgxpool.Pool) {
	t.Helper()
	pool := dbtest.New(t)
	aud := &fakeAuditor{}
	return New(pool, aud, gens...), aud, pool
}

func TestCheckTransition(t *testing.T) {
	states := []domain.KeyState{domain.KeyStateActive, domain.KeyStateSignOnly, domain.KeyStateRetired}
	for _, from := range states {
		for _, to := range states {
			err := checkTransition(from, to)
			ok := (from == domain.KeyStateActive && to == domain.KeyStateSignOnly) ||
				(from == domain.KeyStateSignOnly && to == domain.KeyStateRetired)
			if ok && err != nil {
				t.Errorf("%s -> %s: %v", from, to, err)
			}
			if !ok && !errors.Is(err, ErrInvalidTransition) {
				t.Errorf("%s -> %s: err = %v, want ErrInvalidTransition", from, to, err)
			}
		}
	}
}

func TestAuthorizeSign(t *testing.T) {
	r := New(nil, nil)
	rot := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	before, after := rot.Add(-time.Second), rot.Add(time.Second)
	key := func(state domain.KeyState) domain.Key {
		k := domain.Key{ID: "k1", WalletID: "w1", State: state}
		if state != domain.KeyStateActive {
			k.SignOnlyAt = &rot
		}
		return k
	}
	cases := []struct {
		state   domain.KeyState
		bound   bool
		created time.Time
		ok      bool
	}{
		{domain.KeyStateActive, true, before, true},
		{domain.KeyStateActive, true, after, true},
		{domain.KeyStateActive, false, before, false},
		{domain.KeyStateActive, false, after, false},
		{domain.KeyStateSignOnly, true, before, true},
		{domain.KeyStateSignOnly, true, after, false},
		{domain.KeyStateSignOnly, true, rot, false}, // "before" is strict
		{domain.KeyStateSignOnly, false, before, false},
		{domain.KeyStateSignOnly, false, after, false},
		{domain.KeyStateRetired, true, before, false},
		{domain.KeyStateRetired, true, after, false},
		{domain.KeyStateRetired, false, before, false},
		{domain.KeyStateRetired, false, after, false},
	}
	for _, c := range cases {
		name := fmt.Sprintf("%s/bound=%v/created=%s", c.state, c.bound, c.created.Sub(rot))
		t.Run(name, func(t *testing.T) {
			req := domain.SignRequest{ID: "r1", WalletID: "w1", KeyID: "k1", CreatedAt: c.created}
			if !c.bound {
				req.KeyID = "k2"
			}
			err := r.AuthorizeSign(key(c.state), req)
			if c.ok && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if !c.ok && !errors.Is(err, ErrKeyNotUsable) {
				t.Fatalf("err = %v, want ErrKeyNotUsable", err)
			}
		})
	}
	// sign_only without a sign_only_at (corrupt row) is never usable.
	k := key(domain.KeyStateSignOnly)
	k.SignOnlyAt = nil
	if err := r.AuthorizeSign(k, domain.SignRequest{KeyID: "k1", CreatedAt: before}); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("sign_only without sign_only_at: err = %v", err)
	}
	// A request of another wallet is refused even if the key id matches.
	if err := r.AuthorizeSign(key(domain.KeyStateActive), domain.SignRequest{KeyID: "k1", WalletID: "w2"}); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("wrong wallet: err = %v", err)
	}
}

func TestMPCWalletLifecycle(t *testing.T) {
	ctx := context.Background()
	r, aud, _ := newRegistry(t, fakeMPC{})

	w, k1, err := r.CreateWallet(ctx, "alice", "mpc-hot", domain.TierHot, domain.BackendMPC)
	if err != nil {
		t.Fatal(err)
	}
	if k1.Version != 1 || k1.State != domain.KeyStateActive || k1.ActivatedAt == nil || k1.MPCKeyRef != w.ID+"-v1" {
		t.Fatalf("k1 = %+v", k1)
	}
	if got, err := r.GetWallet(ctx, w.ID); err != nil || got.Name != "mpc-hot" || got.Backend != domain.BackendMPC {
		t.Fatalf("GetWallet = %+v, %v", got, err)
	}
	if ws, err := r.ListWallets(ctx); err != nil || len(ws) != 1 {
		t.Fatalf("ListWallets = %v, %v", ws, err)
	}
	if got, err := r.Get(ctx, k1.ID); err != nil || got.Address != k1.Address || got.HSMKeyID != nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}

	if _, err := r.Retire(ctx, "alice", k1.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("retire active: err = %v, want ErrInvalidTransition", err)
	}

	k2, old, err := r.Rotate(ctx, "alice", w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if old.ID != k1.ID || old.State != domain.KeyStateSignOnly || old.SignOnlyAt == nil {
		t.Fatalf("old = %+v", old)
	}
	if k2.Version != 2 || k2.State != domain.KeyStateActive {
		t.Fatalf("k2 = %+v", k2)
	}
	if act, err := r.ActiveKey(ctx, w.ID); err != nil || act.ID != k2.ID {
		t.Fatalf("ActiveKey = %+v, %v", act, err)
	}

	ret, err := r.Retire(ctx, "alice", k1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ret.State != domain.KeyStateRetired || ret.RetiredAt == nil {
		t.Fatalf("retired = %+v", ret)
	}
	if _, err := r.Retire(ctx, "alice", k1.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("retire retired: err = %v, want ErrInvalidTransition", err)
	}
	if ks, err := r.ListKeys(ctx, w.ID); err != nil || len(ks) != 2 || ks[0].State != domain.KeyStateRetired {
		t.Fatalf("ListKeys = %+v, %v", ks, err)
	}

	want := []string{
		domain.EventWalletCreated, domain.EventKeyGenerated,
		domain.EventKeyGenerated, domain.EventKeyStateChanged, domain.EventKeyRotated,
		domain.EventKeyStateChanged, // MPC retire: no key.destroyed
	}
	if got := aud.types(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("audit = %v, want %v", got, want)
	}
}

func TestNotFound(t *testing.T) {
	ctx := context.Background()
	r, _, _ := newRegistry(t, fakeMPC{})
	missing := "11111111-1111-1111-1111-111111111111"
	for name, err := range map[string]error{
		"GetWallet": second(r.GetWallet(ctx, missing)),
		"Get":       second(r.Get(ctx, missing)),
		"Get bad":   second(r.Get(ctx, "not-a-uuid")),
		"ActiveKey": second(r.ActiveKey(ctx, missing)),
		"Retire":    second(r.Retire(ctx, "a", missing)),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", name, err)
		}
	}
	if _, _, err := r.Rotate(ctx, "a", missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("Rotate: err = %v, want ErrNotFound", err)
	}
	if _, _, err := r.CreateWallet(ctx, "a", "x", domain.TierHot, domain.BackendHSM); err == nil {
		t.Error("CreateWallet without an HSM generator succeeded")
	}
}

func second[T any](_ T, err error) error { return err }

// A failed DB transaction must destroy the key material generated for it.
func TestFailedTxDestroysNewKey(t *testing.T) {
	gen := &brokenHSM{}
	r, aud, _ := newRegistry(t, gen)
	_, _, err := r.CreateWallet(context.Background(), "alice", "broken", domain.TierCold, domain.BackendHSM)
	if err == nil {
		t.Fatal("CreateWallet with an invalid key succeeded")
	}
	if len(gen.destroyed) != 1 {
		t.Fatalf("destroyed = %v, want the generated key", gen.destroyed)
	}
	if len(aud.types()) != 0 {
		t.Fatalf("audit = %v, want nothing", aud.types())
	}
}

func TestConcurrentRotate(t *testing.T) {
	ctx := context.Background()
	r, _, pool := newRegistry(t, fakeMPC{})
	w, _, err := r.CreateWallet(ctx, "alice", "race", domain.TierHot, domain.BackendMPC)
	if err != nil {
		t.Fatal(err)
	}
	const n = 4
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, errs[i] = r.Rotate(ctx, "alice", w.ID)
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatalf("Rotate: %v", err)
		}
	}
	if ok == 0 {
		t.Fatal("no rotation succeeded")
	}
	var active, versions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state = 'active'), count(*) FROM keys WHERE wallet_id = $1`, w.ID).
		Scan(&active, &versions); err != nil {
		t.Fatal(err)
	}
	if active != 1 || versions != 1+ok {
		t.Fatalf("active = %d, keys = %d; want 1 active and %d keys", active, versions, 1+ok)
	}
	ks, _ := r.ListKeys(ctx, w.ID)
	for i, k := range ks {
		if k.Version != i+1 {
			t.Fatalf("versions not contiguous: %+v", ks)
		}
		if want := domain.KeyStateSignOnly; i < len(ks)-1 && k.State != want {
			t.Fatalf("key v%d state %s, want %s", k.Version, k.State, want)
		}
	}
}

// insertRequest stores a sign request bound to key so created_at comes from
// the same clock (Postgres now()) as the key's sign_only_at.
func insertRequest(t *testing.T, pool *pgxpool.Pool, key domain.Key) domain.SignRequest {
	t.Helper()
	req := domain.SignRequest{WalletID: key.WalletID, KeyID: key.ID, ChainID: 11155111, To: "0x0000000000000000000000000000000000000001",
		ValueWei: big.NewInt(1), GasLimit: 21000, MaxFeePerGas: big.NewInt(1), MaxPriorityFeePerGas: big.NewInt(1),
		Requester: "bob", Status: domain.StatusApproved}
	err := pool.QueryRow(context.Background(), `INSERT INTO sign_requests
		(wallet_id, key_id, chain_id, to_address, value_wei, nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas, requester, status)
		VALUES ($1, $2, $3, $4, $5, 0, $6, $7, $8, $9, $10) RETURNING id::text, created_at`,
		req.WalletID, req.KeyID, req.ChainID, req.To, req.ValueWei.String(), req.GasLimit,
		req.MaxFeePerGas.String(), req.MaxPriorityFeePerGas.String(), req.Requester, req.Status).Scan(&req.ID, &req.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func payload(t *testing.T, ev domain.AuditEvent) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(ev.Payload, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
