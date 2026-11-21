package auth_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/auth"
	"github.com/ws4charlie/quorum-vault/internal/auth/authtest"
)

// clocked is a verifier and an issuer that share a settable clock and a one-nanosecond skew, so the limits can be crossed in seconds.
func clocked(t *testing.T) (*authtest.Issuer, *auth.Authenticator, *time.Time) {
	t.Helper()
	now := time.Now()
	is := authtest.New(iss, aud)
	is.Now = func() time.Time { return now }
	cfg := is.Config()
	cfg.ClockSkew = time.Nanosecond
	cfg.Now = func() time.Time { return now }
	a, err := auth.New(cfg, auth.Test, false)
	if err != nil {
		t.Fatal(err)
	}
	return is, a, &now
}

func counts(t *testing.T, a *auth.Authenticator) (hits, misses int) {
	t.Helper()
	var b bytes.Buffer
	a.WriteMetrics(&b)
	for _, l := range strings.Split(b.String(), "\n") {
		if _, err := fmt.Sscanf(l, "qv_core_auth_sigcache_hits_total %d", &hits); err == nil {
			continue
		}
		_, _ = fmt.Sscanf(l, "qv_core_auth_sigcache_misses_total %d", &misses)
	}
	return
}

func verify(a *auth.Authenticator, tok string) (*auth.Principal, error) {
	return a.Verify(context.Background(), tok)
}

func TestSecondUseSkipsTheSignatureCheck(t *testing.T) {
	is, a, _ := clocked(t)
	tok := is.Token(authtest.Spec{Sub: "u", Roles: []string{"approver"}})
	for i := 0; i < 3; i++ {
		p, err := verify(a, tok)
		if err != nil || p.Sub != "u" || !p.Has(auth.Approver) {
			t.Fatal(p, err)
		}
	}
	if h, m := counts(t, a); h != 2 || m != 1 {
		t.Fatalf("hits %d misses %d, want 2 and 1", h, m)
	}
}

func TestACachedTokenStillMeetsEveryClaimLimit(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		is, a, now := clocked(t)
		tok := is.Token(authtest.Spec{Sub: "u", Lifetime: 30 * time.Second})
		if _, err := verify(a, tok); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(20 * time.Second)
		if _, err := verify(a, tok); err != nil {
			t.Fatal(err)
		}
		if h, _ := counts(t, a); h != 1 {
			t.Fatal("the second use was not a hit")
		}
		*now = now.Add(11 * time.Second)
		if _, err := verify(a, tok); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("a token past exp was accepted: %v", err)
		}
	})
	t.Run("not before", func(t *testing.T) {
		is, a, now := clocked(t)
		t0 := *now
		tok := is.Token(authtest.Spec{Sub: "u", NotBefore: 10 * time.Second})
		*now = t0.Add(20 * time.Second)
		if _, err := verify(a, tok); err != nil {
			t.Fatal(err)
		}
		*now = t0 // the clock steps back: the cached token is not valid yet again
		if _, err := verify(a, tok); err == nil || !strings.Contains(err.Error(), "not valid yet") {
			t.Fatalf("nbf was not checked on a hit: %v", err)
		}
		if h, _ := counts(t, a); h != 1 {
			t.Fatal("the second use was not a hit")
		}
	})
	t.Run("session limit", func(t *testing.T) {
		is, a, now := clocked(t)
		tok := is.Token(authtest.Spec{Sub: "u", AuthAge: 12*time.Hour - 30*time.Second})
		if _, err := verify(a, tok); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(45 * time.Second)
		if _, err := verify(a, tok); err == nil || !strings.Contains(err.Error(), "older than the overall limit") {
			t.Fatalf("the session limit was not checked on a hit: %v", err)
		}
		if h, _ := counts(t, a); h != 1 {
			t.Fatal("the second use was not a hit")
		}
	})
	t.Run("step-up login age", func(t *testing.T) {
		is, a, now := clocked(t)
		tok := is.Token(authtest.Spec{Sub: "u", Roles: []string{"approver"}, AuthAge: 4*time.Minute + 30*time.Second})
		rule := auth.Rule{Roles: []auth.Role{auth.Approver}, StepUp: true}
		p, err := verify(a, tok)
		if err != nil || a.Authorize(p, rule) != nil {
			t.Fatal(err, a.Authorize(p, rule))
		}
		*now = now.Add(45 * time.Second)
		p, err = verify(a, tok)
		if err != nil {
			t.Fatal(err)
		}
		if h, _ := counts(t, a); h != 1 {
			t.Fatal("the second use was not a hit")
		}
		if f := a.Authorize(p, rule); f == nil || f.Status != 401 {
			t.Fatalf("step-up was not enforced on a hit: %v", f)
		}
	})
	t.Run("a hit returns a fresh principal", func(t *testing.T) {
		is, a, _ := clocked(t)
		tok := is.Token(authtest.Spec{Sub: "u", Roles: []string{"approver"}})
		p1, _ := verify(a, tok)
		p1.Roles = append(p1.Roles, auth.Admin)
		p2, err := verify(a, tok)
		if err != nil || p2.Has(auth.Admin) {
			t.Fatal("a caller's change of its principal reached the next request", err)
		}
	})
}

func TestAnEntryDiesAtTheTimeLimit(t *testing.T) {
	is, a, now := clocked(t)
	tok := is.Token(authtest.Spec{Sub: "u"})
	verify(a, tok)
	*now = now.Add(59 * time.Second)
	verify(a, tok)
	*now = now.Add(2 * time.Second) // 61 s after the first full check
	if _, err := verify(a, tok); err != nil {
		t.Fatal(err)
	}
	if h, m := counts(t, a); h != 1 || m != 2 {
		t.Fatalf("hits %d misses %d, want 1 and 2", h, m)
	}
}

func TestFailuresAreNeverCached(t *testing.T) {
	is, a, _ := clocked(t)
	bad := map[string]string{
		"bad signature": is.TokenWithForeignKey(authtest.Spec{Sub: "u"}, "x"),
		"wrong aud":     is.Token(authtest.Spec{Sub: "u", Audience: "other"}),
		"wrong issuer":  is.Token(authtest.Spec{Sub: "u", Issuer: "https://evil.example"}),
		"no sub":        is.Token(authtest.Spec{}),
	}
	for name, tok := range bad {
		for i := 0; i < 3; i++ {
			if _, err := verify(a, tok); err == nil {
				t.Fatalf("%s accepted", name)
			}
		}
	}
	if h, m := counts(t, a); h != 0 || m != 12 {
		t.Fatalf("hits %d misses %d, want 0 and 12", h, m)
	}
}

func TestATamperedSignatureMissesTheCache(t *testing.T) {
	is, a, _ := clocked(t)
	tok := is.Token(authtest.Spec{Sub: "u"})
	if _, err := verify(a, tok); err != nil {
		t.Fatal(err)
	}
	// Same header and payload, the signature of a different token of the same key.
	other := is.Token(authtest.Spec{Sub: "v"})
	parts, op := strings.Split(tok, "."), strings.Split(other, ".")
	forged := parts[0] + "." + parts[1] + "." + op[2]
	if _, err := verify(a, forged); err == nil {
		t.Fatal("a token with another signature was accepted")
	}
	// A flipped first character of the signature too (the last one has unused bits, so it may not change the bytes).
	flip := byte('A')
	if parts[2][0] == 'A' {
		flip = 'B'
	}
	if _, err := verify(a, parts[0]+"."+parts[1]+"."+string(flip)+parts[2][1:]); err == nil {
		t.Fatal("a token with a damaged signature was accepted")
	}
	if h, _ := counts(t, a); h != 0 {
		t.Fatalf("hits %d: a different token was served from the cache", h)
	}
	if _, err := verify(a, tok); err != nil { // the real one still works, and is a hit
		t.Fatal(err)
	}
}

func TestARemovedKeyStopsBeingHonouredAfterARefetch(t *testing.T) {
	is := authtest.New(iss, aud)
	srv := is.Serve()
	defer srv.Close()
	now := time.Now()
	clock := &now
	is.Now = func() time.Time { return *clock }
	a, err := auth.New(auth.Config{Issuer: iss, Audience: aud, JWKSURL: srv.URL + "/jwks", JWKSMinRefresh: time.Second, Now: func() time.Time { return *clock }}, auth.Test, false)
	if err != nil {
		t.Fatal(err)
	}
	old := is.Token(authtest.Spec{Sub: "u"})
	for i := 0; i < 3; i++ { // the first use fetches the key set, so it is not stored; the second stores; the third hits
		if _, err := verify(a, old); err != nil {
			t.Fatal(err)
		}
	}
	if h, _ := counts(t, a); h != 1 {
		t.Fatal("not cached")
	}
	is.Rotate(false) // the provider drops the old key
	*clock = clock.Add(2 * time.Second)
	if _, err := verify(a, is.Token(authtest.Spec{Sub: "u2"})); err != nil { // a token of the new key makes the verifier refetch
		t.Fatal(err)
	}
	if _, err := verify(a, old); err == nil {
		t.Fatal("a token of a removed key is still accepted after the key set was refetched")
	}
}

func TestConcurrentUse(t *testing.T) {
	is, a, _ := clocked(t)
	toks := make([]string, 20)
	for i := range toks {
		toks[i] = is.Token(authtest.Spec{Sub: fmt.Sprintf("u-%d", i), Roles: []string{"approver"}})
	}
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				n := (g + i) % len(toks)
				p, err := verify(a, toks[n])
				if err != nil || p.Sub != fmt.Sprintf("u-%d", n) || !p.Has(auth.Approver) {
					t.Error(p, err)
					return
				}
				if i%50 == 0 {
					if _, err := verify(a, toks[n]+"x"); err == nil {
						t.Error("damaged token accepted")
					}
				}
			}
		}(g)
	}
	wg.Wait()
	if h, _ := counts(t, a); h == 0 {
		t.Fatal("no hits")
	}
}

func BenchmarkVerifyOneToken(b *testing.B) {
	is := authtest.New(iss, aud)
	a, _ := auth.New(is.Config(), auth.Test, false)
	tok := is.Token(authtest.Spec{Sub: "u", Roles: []string{"approver"}})
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := a.Verify(ctx, tok); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerifyManyTokens(b *testing.B) {
	is := authtest.New(iss, aud)
	a, _ := auth.New(is.Config(), auth.Test, false)
	toks := make([]string, 1000)
	for i := range toks {
		toks[i] = is.Token(authtest.Spec{Sub: fmt.Sprintf("u-%d", i), Roles: []string{"approver"}})
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			if _, err := a.Verify(ctx, toks[i%len(toks)]); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// aFullCache fills the cache of a verifier with live tokens and returns one more token that does not fit.
func aFullCache(tb testing.TB) (*auth.Authenticator, string, string) {
	tb.Helper()
	is := authtest.New(iss, aud)
	a, err := auth.New(is.Config(), auth.Test, false)
	if err != nil {
		tb.Fatal(err)
	}
	first := is.Token(authtest.Spec{Sub: "u-first", Roles: []string{"approver"}})
	ctx := context.Background()
	a.Verify(ctx, first)
	a.Verify(ctx, first) // the first use of a static-key verifier stores nothing only for a fetched set; here it stores
	for i := 0; i < 8192+100; i++ {
		if _, err := a.Verify(ctx, is.Token(authtest.Spec{Sub: fmt.Sprintf("u-%d", i), Lifetime: time.Hour + time.Duration(i)*time.Second})); err != nil {
			tb.Fatal(err)
		}
	}
	return a, first, is.Token(authtest.Spec{Sub: "u-extra"})
}

func TestAFullCacheStillServesStoredTokensAndVerifiesTheOthers(t *testing.T) {
	a, first, extra := aFullCache(t)
	ctx := context.Background()
	h0, _ := counts(t, a)
	for i := 0; i < 3; i++ {
		if _, err := a.Verify(ctx, first); err != nil {
			t.Fatal(err)
		}
	}
	if h1, _ := counts(t, a); h1 != h0+3 {
		t.Fatal("a stored token stopped being a hit when the cache filled")
	}
	for i := 0; i < 3; i++ { // a token that does not fit is verified in full each time, correctly
		if p, err := a.Verify(ctx, extra); err != nil || p.Sub != "u-extra" {
			t.Fatal(p, err)
		}
	}
	if h2, _ := counts(t, a); h2 != h0+3 {
		t.Fatal("a token that did not fit was counted as a hit")
	}
}

func BenchmarkVerifyOneToken_FullCache(b *testing.B) {
	a, first, _ := aFullCache(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := a.Verify(ctx, first); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Many more distinct live tokens than the bound: most are misses, none may make the others wait on a scan.
func BenchmarkVerifyAboveTheBound(b *testing.B) {
	is := authtest.New(iss, aud)
	a, _ := auth.New(is.Config(), auth.Test, false)
	toks := make([]string, 3*8192)
	for i := range toks {
		toks[i] = is.Token(authtest.Spec{Sub: fmt.Sprintf("u-%d", i), Lifetime: time.Hour + time.Duration(i)*time.Second})
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			if _, err := a.Verify(ctx, toks[i%len(toks)]); err != nil {
				b.Fatal(err)
			}
		}
	})
}
