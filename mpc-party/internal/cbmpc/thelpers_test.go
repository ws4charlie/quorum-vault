package cbmpc

import (
	"context"
	"net"
	"sync"
	"testing"
)

// trio runs f for each of the three members concurrently over fresh in-memory links. When a member fails, its links are
// closed (as the service closes a failed session) and ctx is left alone, so the others see a Transport error.
func trio(ctx context.Context, f func(ctx context.Context, m Member, mesh *LinkMesh) error) (errs [NumMembers]error) {
	meshes := NewMemMesh()
	var wg sync.WaitGroup
	for i := 0; i < NumMembers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if errs[i] = f(ctx, Member(i), meshes[i]); errs[i] != nil {
				meshes[i].Close()
			}
		}(i)
	}
	wg.Wait()
	return
}

func tDKG(t testing.TB) (ks [NumMembers]*TKey) {
	t.Helper()
	ctx := ctx5(t)
	errs := trio(ctx, func(ctx context.Context, m Member, mesh *LinkMesh) (err error) {
		ks[m], err = TDKG(ctx, mesh, m)
		return
	})
	for _, e := range errs {
		must(t, e)
	}
	t.Cleanup(func() {
		for _, k := range ks {
			k.Wipe()
		}
	})
	return
}

// tSignPair signs msg with members a<b over fresh links; the receiver gets the signature.
func tSign(ctx context.Context, ks [NumMembers]*TKey, a, b, receiver Member, msg []byte) (sig []byte, ea, eb error) {
	meshes := NewMemMesh()
	var wg sync.WaitGroup
	wg.Add(2)
	run := func(me, peer Member, e *error) {
		defer wg.Done()
		s, err := ks[me].Sign(ctx, meshes[me], peer, receiver, msg)
		if me == receiver {
			sig = s
		}
		if err != nil {
			*e = err
			meshes[me].Close()
		}
	}
	go run(a, b, &ea)
	go run(b, a, &eb)
	wg.Wait()
	return
}

var allPairs = [][2]Member{{0, 1}, {0, 2}, {1, 2}}

// tcpMesh builds the three members' meshes over loopback TCP, one connection per pair, each wrapped in a ConnTransport
// (length-prefixed frames). Cleanup closes everything.
func tcpMesh(t testing.TB) [NumMembers]*LinkMesh {
	t.Helper()
	var out [NumMembers]*LinkMesh
	for i := range out {
		out[i] = NewLinkMesh(Member(i), map[Member]Transport{})
	}
	for a := 0; a < NumMembers; a++ {
		for b := a + 1; b < NumMembers; b++ {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			must(t, err)
			ch := make(chan net.Conn, 1)
			go func() { c, _ := ln.Accept(); ch <- c }()
			cb, err := net.Dial("tcp", ln.Addr().String())
			must(t, err)
			ca := <-ch
			ln.Close()
			out[a].links[Member(b)] = NewConnTransport(ca, 0)
			out[b].links[Member(a)] = NewConnTransport(cb, 0)
		}
	}
	t.Cleanup(func() {
		for _, m := range out {
			m.Close()
		}
	})
	return out
}

// trioOn is trio over caller-supplied meshes.
func trioOn(ctx context.Context, meshes [NumMembers]*LinkMesh, f func(ctx context.Context, m Member, mesh *LinkMesh) error) (errs [NumMembers]error) {
	var wg sync.WaitGroup
	for i := 0; i < NumMembers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if errs[i] = f(ctx, Member(i), meshes[i]); errs[i] != nil {
				meshes[i].Close()
			}
		}(i)
	}
	wg.Wait()
	return
}

func tRefresh(t testing.TB, ks [NumMembers]*TKey) (nk [NumMembers]*TKey) {
	t.Helper()
	ctx := ctx5(t)
	errs := trio(ctx, func(ctx context.Context, m Member, mesh *LinkMesh) (err error) {
		nk[m], err = ks[m].Refresh(ctx, mesh)
		return
	})
	for _, e := range errs {
		must(t, e)
	}
	t.Cleanup(func() {
		for _, k := range nk {
			k.Wipe()
		}
	})
	return
}

func tSelfTest(ctx context.Context, ks [NumMembers]*TKey, label []byte) [NumMembers]error {
	return trio(ctx, func(ctx context.Context, m Member, mesh *LinkMesh) error {
		if ks[m] == nil {
			return errNilKey
		}
		return ks[m].SelfTest(ctx, mesh, label)
	})
}

var errNilKey = &Error{Kind: KindInternal, Op: "test", Msg: "nil key"}

func tBlob(t testing.TB, k *TKey) []byte {
	t.Helper()
	b, err := k.Secret.Bytes()
	must(t, err)
	return b
}
