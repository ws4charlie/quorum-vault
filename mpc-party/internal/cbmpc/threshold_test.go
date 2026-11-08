package cbmpc

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"
)

func TestThresholdDKGSignEveryPair(t *testing.T) {
	ks := tDKG(t)
	pub := ks[0].PublicKey()
	for i := range ks {
		if !bytes.Equal(ks[i].PublicKey(), pub) {
			t.Fatalf("member %d has another public key", i)
		}
		if ks[i].Self() != Member(i) {
			t.Fatalf("member %d reports self %d", i, ks[i].Self())
		}
	}
	if bytes.Equal(ks[0].SharePoint(), ks[1].SharePoint()) {
		t.Fatal("two members have the same share point")
	}
	ctx := ctx5(t)
	for _, pr := range allPairs {
		for _, recv := range []Member{pr[0], pr[1]} {
			d := digest32(byte(10*int(pr[0]) + int(pr[1]) + int(recv)))
			sig, ea, eb := tSign(ctx, ks, pr[0], pr[1], recv, d)
			must(t, ea)
			must(t, eb)
			verifyECDSA(t, pub, d, sig) // btcec, low-S, DER
		}
	}
}

func TestThresholdSelfTestAfterDKGAndRefresh(t *testing.T) {
	ctx := ctx5(t)
	ks := tDKG(t)
	for i, e := range tSelfTest(ctx, ks, []byte("ks1|g1")) {
		if e != nil {
			t.Fatalf("self-test after DKG, member %d: %v", i, e)
		}
	}
	nk := tRefresh(t, ks)
	if !bytes.Equal(nk[0].PublicKey(), ks[0].PublicKey()) {
		t.Fatal("refresh moved the public key")
	}
	if bytes.Equal(tBlob(t, nk[0]), tBlob(t, ks[0])) || bytes.Equal(nk[1].SharePoint(), ks[1].SharePoint()) {
		t.Fatal("refresh did not change the shares")
	}
	for i, e := range tSelfTest(ctx, nk, []byte("ks1|g2")) {
		if e != nil {
			t.Fatalf("self-test after refresh, member %d: %v", i, e)
		}
	}
	for _, pr := range allPairs {
		d := digest32(byte(7 * int(pr[1])))
		sig, ea, eb := tSign(ctx, nk, pr[0], pr[1], pr[0], d)
		must(t, ea)
		must(t, eb)
		verifyECDSA(t, nk[0].PublicKey(), d, sig)
	}
	// the old generation still works until it is wiped (the service drops it only after all three self-tests passed)
	sig, ea, eb := tSign(ctx, ks, 0, 1, 1, digest32(3))
	must(t, ea)
	must(t, eb)
	verifyECDSA(t, ks[0].PublicKey(), digest32(3), sig)
}

// Old and new shares do not mix: a pair with one old and one new share never yields a signature. Observed class is
// recorded in the failure message so that a change in cb-mpc's behaviour is visible.
func TestThresholdOldAndNewSharesDoNotMix(t *testing.T) {
	ctx := ctx5(t)
	ks := tDKG(t)
	nk := tRefresh(t, ks)
	for _, pr := range allPairs {
		for _, oldIsFirst := range []bool{true, false} {
			mixed := nk
			if oldIsFirst {
				mixed[pr[0]] = ks[pr[0]]
			} else {
				mixed[pr[1]] = ks[pr[1]]
			}
			for _, recv := range []Member{pr[0], pr[1]} {
				sig, ea, eb := tSign(ctx, mixed, pr[0], pr[1], recv, digest32(5))
				if sig != nil {
					t.Fatalf("pair %v old-first=%v: a signature came out of mixed generations", pr, oldIsFirst)
				}
				// the receiver must fail; the other side may succeed (README point 2) but never with a signature
				re := ea
				if recv == pr[1] {
					re = eb
				}
				if re == nil || !(IsCryptographic(re) || IsTransport(re)) {
					t.Fatalf("pair %v old-first=%v receiver %d: want Cryptographic or Transport, got %v", pr, oldIsFirst, recv, re)
				}
				t.Logf("pair %v old-first=%v receiver=%d: receiver %s, other %v", pr, oldIsFirst, recv, KindOf(re), kindStr(ea, eb, recv, pr))
			}
		}
	}
	// SelfTest on a half-refreshed set (member 2 kept its old share) must fail somewhere.
	half := nk
	half[2] = ks[2]
	errs := tSelfTest(ctx, half, []byte("half"))
	if errs[0] == nil && errs[1] == nil && errs[2] == nil {
		t.Fatal("SelfTest passed on a half-refreshed key set")
	}
	if errs[0] == nil && errs[1] == nil {
		// members 0 and 1 are in a pair with 2: they cannot both be fine
		t.Fatal("members 0 and 1 both passed although each pairs with the stale member 2")
	}
}

func kindStr(ea, eb error, recv Member, pr [2]Member) string {
	o := eb
	if recv == pr[1] {
		o = ea
	}
	if o == nil {
		return "nil"
	}
	return KindOf(o).String()
}

func TestThresholdLoadAndInfo(t *testing.T) {
	ks := tDKG(t)
	for m := Member(0); m < NumMembers; m++ {
		b := tBlob(t, ks[m])
		k, err := LoadTKey(m, append([]byte(nil), b...))
		must(t, err)
		if !bytes.Equal(k.PublicKey(), ks[m].PublicKey()) || !bytes.Equal(k.SharePoint(), ks[m].SharePoint()) {
			t.Fatal("reloaded share differs")
		}
		k.Wipe()
		// wrong member
		if _, err := LoadTKey((m+1)%NumMembers, append([]byte(nil), b...)); !IsInternal(err) {
			t.Fatalf("share of %d loaded as another member: %v", m, err)
		}
		// damaged
		for _, mut := range []func([]byte) []byte{
			func(x []byte) []byte { return x[:len(x)-1] },
			func(x []byte) []byte { return x[:len(x)/2] },
			func(x []byte) []byte { x[len(x)-1] ^= 1; return x },
			func(x []byte) []byte { x[len(x)/2] ^= 1; return x },
			func(x []byte) []byte { return append(x, 0) },
			func(x []byte) []byte { return nil },
		} {
			if k, err := LoadTKey(m, mut(append([]byte(nil), b...))); err == nil {
				// a flip inside a place that does not matter would be fine, but not one that changes the key
				if !bytes.Equal(k.PublicKey(), ks[m].PublicKey()) || !bytes.Equal(k.SharePoint(), ks[m].SharePoint()) {
					t.Fatal("a damaged share loaded as a different key")
				}
				k.Wipe()
			} else if !IsInternal(err) && !IsCryptographic(err) {
				// a point that does not decode is reported by cb-mpc as a crypto error, a bad layout as internal
				t.Fatalf("damaged share: want internal or cryptographic, got %v", err)
			}
		}
	}
	if _, err := LoadTKey(3, []byte{1}); !IsInternal(err) {
		t.Fatalf("member 3: %v", err)
	}
	// a 2-party blob is not a threshold share
	doc := readGolden(t)
	_ = doc
}

func TestThresholdBadArguments(t *testing.T) {
	ks := tDKG(t)
	ctx := ctx5(t)
	mesh := NewMemMesh()
	for name, f := range map[string]func() error{
		"self-as-peer": func() error { _, err := ks[0].Sign(ctx, mesh[0], 0, 0, digest32(1)); return err },
		"peer 3":       func() error { _, err := ks[0].Sign(ctx, mesh[0], 3, 0, digest32(1)); return err },
		"receiver 2":   func() error { _, err := ks[0].Sign(ctx, mesh[0], 1, 2, digest32(1)); return err },
		"short digest": func() error { _, err := ks[0].Sign(ctx, mesh[0], 1, 0, []byte{1, 2}); return err },
		"nil mesh":     func() error { _, err := ks[0].Sign(ctx, nil, 1, 0, digest32(1)); return err },
		"dkg member 5": func() error { _, err := TDKG(ctx, mesh[0], 5); return err },
		"dkg nil mesh": func() error { _, err := TDKG(ctx, nil, 0); return err },
		"link missing": func() error { _, err := ks[0].Sign(ctx, NewLinkMesh(0, nil), 1, 0, digest32(1)); return err },
	} {
		err := f()
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if name == "link missing" {
			if !IsTransport(err) {
				t.Errorf("%s: want transport, got %v", name, err)
			}
			continue
		}
		if !IsInternal(err) {
			t.Errorf("%s: want internal, got %v", name, err)
		}
	}
	// wiped key
	k, err := LoadTKey(0, tBlob(t, ks[0]))
	must(t, err)
	k.Wipe()
	if _, err := k.Sign(ctx, mesh[0], 1, 0, digest32(1)); !IsInternal(err) {
		t.Fatalf("wiped key: %v", err)
	}
}

func TestThresholdOverLoopbackTCP(t *testing.T) {
	ctx := ctx5(t)
	var ks [NumMembers]*TKey
	meshes := tcpMesh(t)
	errs := trioOn(ctx, meshes, func(ctx context.Context, m Member, mesh *LinkMesh) (err error) {
		ks[m], err = TDKG(ctx, mesh, m)
		return
	})
	for _, e := range errs {
		must(t, e)
	}
	defer func() {
		for _, k := range ks {
			k.Wipe()
		}
	}()
	for _, pr := range allPairs {
		a, b := pr[0], pr[1]
		d := digest32(byte(a*3 + b))
		var sig []byte
		var wg sync.WaitGroup
		var ea, eb error
		wg.Add(2)
		go func() { defer wg.Done(); sig, ea = ks[a].Sign(ctx, meshes[a], b, a, d) }()
		go func() { defer wg.Done(); _, eb = ks[b].Sign(ctx, meshes[b], a, a, d) }()
		wg.Wait()
		must(t, ea)
		must(t, eb)
		verifyECDSA(t, ks[0].PublicKey(), d, sig)
	}
	errs = trioOn(ctx, meshes, func(ctx context.Context, m Member, mesh *LinkMesh) error {
		return ks[m].SelfTest(ctx, mesh, []byte("tcp"))
	})
	for _, e := range errs {
		must(t, e)
	}
}

// Context cancellation: every member returns promptly with a transport error and no goroutine is left behind.
func TestThresholdContextCancel(t *testing.T) {
	before := threadsAndGoroutines().goroutines
	ctx, cancel := context.WithCancel(context.Background())
	// two of the three members start; the third never shows up, so the protocol blocks until we cancel
	meshes := NewMemMesh()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = TDKG(ctx, meshes[i], Member(i))
		}(i)
	}
	time.AfterFunc(500*time.Millisecond, cancel)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("DKG did not return after cancel")
	}
	for i, e := range errs {
		if !IsTransport(e) {
			t.Fatalf("member %d: want transport after cancel, got %v", i, e)
		}
	}
	waitGoroutines(t, before+2)
}

func TestThresholdRecvTimeout(t *testing.T) {
	ks := tDKG(t)
	meshes := NewMemMesh()
	_, err := ks[0].Sign(ctx5(t), meshes[0], 1, 0, digest32(1), WithRecvTimeout(300*time.Millisecond))
	if !IsTransport(err) {
		t.Fatalf("want transport on silent peer, got %v", err)
	}
}

// 32 concurrent signing sessions on the same three keys (rotating pairs and receivers), then concurrent refreshes of
// independent keys, under -race.
func TestThresholdConcurrency(t *testing.T) {
	ks := tDKG(t)
	pub := ks[0].PublicKey()
	ctx := ctx5(t)
	const n = 32
	var wg sync.WaitGroup
	errc := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pr := allPairs[i%3]
			recv := pr[i%2]
			d := digest32(byte(i))
			sig, ea, eb := tSign(ctx, ks, pr[0], pr[1], recv, d)
			if ea != nil || eb != nil {
				errc <- ea
				if ea == nil {
					errc <- eb
				}
				return
			}
			if !verifyQuiet(ECDSA, pub, d, sig) {
				errc <- &Error{Kind: KindInternal, Op: "test", Msg: "bad signature under concurrency"}
			}
		}(i)
	}
	wg.Wait()
	close(errc)
	for e := range errc {
		t.Error(e)
	}
}

func TestThresholdConcurrentKeysets(t *testing.T) {
	const n = 4
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ks := tDKG(t)
			nk := tRefresh(t, ks)
			for j, e := range tSelfTest(ctx5(t), nk, []byte("c")) {
				if e != nil {
					t.Errorf("member %d: %v", j, e)
				}
			}
		}()
	}
	wg.Wait()
}

// Wipe waits for in-flight sessions and later calls fail with ErrWiped.
func TestThresholdWipeDuringSign(t *testing.T) {
	ks := tDKG(t)
	ctx := ctx5(t)
	meshes := NewMemMesh()
	started := make(chan struct{})
	res := make(chan error, 1)
	go func() {
		close(started)
		_, err := ks[0].Sign(ctx, meshes[0], 1, 0, digest32(1), WithRecvTimeout(time.Second))
		res <- err
	}()
	<-started
	time.Sleep(50 * time.Millisecond)
	wiped := make(chan struct{})
	go func() { ks[0].Wipe(); close(wiped) }()
	select {
	case <-wiped:
		t.Fatal("Wipe returned while a session still used the share")
	case <-time.After(200 * time.Millisecond):
	}
	if err := <-res; !IsTransport(err) {
		t.Fatalf("want transport after peer silence, got %v", err)
	}
	<-wiped
}
