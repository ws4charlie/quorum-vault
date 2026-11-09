package hsm_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/pkcs11"

	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
)

func TestOpenTokenByLabel(t *testing.T) {
	tok := hsmtest.Token(t, "quorumvault")
	if tok.Label() != "quorumvault" {
		t.Fatalf("label = %q", tok.Label())
	}
	err := tok.WithSession(context.Background(), func(p *pkcs11.Ctx, s pkcs11.SessionHandle) error {
		info, err := p.GetSessionInfo(s)
		if err != nil {
			return err
		}
		if info.State != pkcs11.CKS_RW_USER_FUNCTIONS {
			t.Errorf("session state = %d, want RW user", info.State)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnknownLabel(t *testing.T) {
	lib := hsmtest.Lib(t)
	_, err := lib.OpenToken("no-such-token", hsmtest.PIN(t))
	if !errors.Is(err, hsm.ErrTokenNotFound) {
		t.Fatalf("err = %v, want ErrTokenNotFound", err)
	}
	if !strings.Contains(err.Error(), "no-such-token") {
		t.Fatalf("error %q does not name the label", err)
	}
}

func TestLibSharedAcrossTokens(t *testing.T) {
	a := hsmtest.Lib(t)
	b := hsmtest.Lib(t)
	if a != b {
		t.Fatal("LoadLib returned different *Lib for the same path")
	}
	t1, err := a.OpenToken("qv-party-1", hsmtest.PIN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer t1.Close()
	t2, err := b.OpenToken("qv-party-2", hsmtest.PIN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer t2.Close()
	// Same label twice: second login hits CKR_USER_ALREADY_LOGGED_IN, tolerated.
	t1b, err := a.OpenToken("qv-party-1", hsmtest.PIN(t))
	if err != nil {
		t.Fatal(err)
	}
	t1b.Close()
	// t1 still usable after another Token on the same slot closed.
	if err := t1.WithSession(context.Background(), func(p *pkcs11.Ctx, s pkcs11.SessionHandle) error {
		_, err := p.GetSessionInfo(s)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWithSessionConcurrent(t *testing.T) {
	tok := hsmtest.Token(t, "quorumvault")
	var wg sync.WaitGroup
	errs := make(chan error, 8*20)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				errs <- tok.WithSession(context.Background(), func(p *pkcs11.Ctx, s pkcs11.SessionHandle) error {
					_, err := p.GenerateRandom(s, 32)
					return err
				})
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestClosedToken(t *testing.T) {
	lib := hsmtest.Lib(t)
	tok, err := lib.OpenToken("qv-party-2", hsmtest.PIN(t))
	if err != nil {
		t.Fatal(err)
	}
	tok.Close()
	err = tok.WithSession(context.Background(), func(*pkcs11.Ctx, pkcs11.SessionHandle) error { return nil })
	if !errors.Is(err, hsm.ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
}
