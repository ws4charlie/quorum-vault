package broker

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"sync"
	"time"
)

// Refusal codes of the nonce rules.
const (
	nonceUnknown     = "unknown"
	nonceReused      = "reused"
	nonceExpired     = "expired"
	nonceWrongCaller = "wrong_caller"
)

const (
	maxNonces          = 20000
	maxNoncesPerCaller = 64
)

type nonceRec struct {
	pin     [32]byte
	expires time.Time
	used    bool
}

// nonceStore holds the challenges this process issued. A nonce is random, bound to the caller's TLS key pin, valid for ttl and consumable
// once (a failed release consumes it too). It is kept after use until it would have expired so a reuse is told apart from an unknown value.
// State is in memory: a restart voids every open challenge (callers ask again), and a second broker replica would not know the first one's
// nonces, so the broker runs as one replica (see the runbook).
type nonceStore struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]*nonceRec
}

func newNonceStore(ttl time.Duration) *nonceStore {
	return &nonceStore{ttl: ttl, m: map[string]*nonceRec{}}
}

func (s *nonceStore) prune(now time.Time) {
	for k, r := range s.m {
		if now.After(r.expires.Add(s.ttl)) {
			delete(s.m, k)
		}
	}
}

func (s *nonceStore) issue(pin [32]byte, now time.Time) (nonce []byte, expires time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	open := 0
	for _, r := range s.m {
		if !r.used && r.pin == pin && now.Before(r.expires) {
			open++
		}
	}
	if len(s.m) >= maxNonces || open >= maxNoncesPerCaller {
		return nil, time.Time{}, errors.New("too many open challenges")
	}
	nonce = make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, time.Time{}, err
	}
	expires = now.Add(s.ttl)
	s.m[string(nonce)] = &nonceRec{pin: pin, expires: expires}
	return nonce, expires, nil
}

// consume uses the nonce up. It returns one of the nonce* codes as an error.
func (s *nonceStore) consume(nonce []byte, pin [32]byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[string(nonce)]
	switch {
	case !ok:
		return errors.New(nonceUnknown)
	case subtle.ConstantTimeCompare(r.pin[:], pin[:]) != 1:
		// another caller's challenge: refuse, and burn it so it cannot be tried again by its owner after being exposed
		r.used = true
		return errors.New(nonceWrongCaller)
	case r.used:
		return errors.New(nonceReused)
	case now.After(r.expires):
		r.used = true
		return errors.New(nonceExpired)
	}
	r.used = true
	return nil
}
