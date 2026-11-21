package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/brokerclient"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/kmsrelease"
)

// The attested sealer (research/TEE.md, task TEE-T3). The party holds NO long-lived key. At start it proves what it runs (evidence from an
// Attester, bound to a broker nonce, to the request and to the TLS key of its link to the broker) and the broker (cmd/qv-attest-broker) hands
// back one AES-256 data key per (party, keyset, generation), encrypted to a key made in this process. The keys live in locked memory and are
// wiped at shutdown; neither they nor the evidence private key are ever written to disk or to a log. What sits on disk is only ciphertext plus the
// broker's wrapped form of each data key: useless without the broker's HSM, and the broker releases only to an allowlisted measurement.

// AttestedSealerType is the sealer.type of this sealer.
const AttestedSealerType = "attested"

// localKeyset is the keyset name of the data key for local state (state.json, freeze, jobs, key metadata). It contains a character that is not
// valid in a keyset id (validID), so it can never collide with a real keyset. One key, generation 1.
const localKeyset = "~local"

// SealScope names the data key a blob is sealed under: one key per (party, keyset, generation). The party is the sealer's own role.
type SealScope struct {
	Keyset     string
	Generation uint64
}

// LocalScope is the scope of local state.
var LocalScope = SealScope{Keyset: localKeyset, Generation: 1}

func (s SealScope) kid() string { return fmt.Sprintf("%s/%d", s.Keyset, s.Generation) }

// ScopedSealer is a Sealer whose key depends on the keyset and generation. FileStore uses it when the sealer provides it.
type ScopedSealer interface {
	SealScoped(ctx context.Context, sc SealScope, aad, plaintext []byte) ([]byte, error)
	OpenScoped(ctx context.Context, sc SealScope, aad, sealed []byte) ([]byte, error)
	// Forget drops (wipes) the data key of a scope that is no longer needed: a dropped candidate, a deleted old generation.
	Forget(sc SealScope)
}

var (
	// ErrSealedV1 is a blob sealed by the PKCS#11 sealer (envelope v1): the attested sealer does not read it, and nothing migrates it at start.
	ErrSealedV1 = errors.New("sealer attested: this data is sealed by the PKCS#11 sealer (envelope v1); it is not read here. Stop the party and run `mpc-party migrate-seal` once (docs/runbooks/tee-broker.md)")
	// ErrKeyRefused is a data key the broker did not release.
	ErrKeyRefused = errors.New("sealer attested: the broker did not release the data key")
)

// envelopeV2 is the sealed form: AES-256-GCM under the generation's data key, plus the broker's wrapped form of that key so a restart can ask for
// it again. kid names the scope and is inside the associated data.
type envelopeV2 struct {
	V       int    `json:"v"`
	KID     string `json:"kid"`
	Wrapped []byte `json:"wrapped_dek"`
	IV      []byte `json:"iv"`
	CT      []byte `json:"ct"`
}

const envV2 = 2

func parseEnvelopeV2(sealed []byte) (envelopeV2, error) {
	var probe struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(sealed, &probe); err != nil {
		return envelopeV2{}, fmt.Errorf("%w: bad envelope: %v", ErrOpen, err)
	}
	if probe.V == envelopeVersion {
		return envelopeV2{}, ErrSealedV1
	}
	var e envelopeV2
	if err := json.Unmarshal(sealed, &e); err != nil || e.V != envV2 || len(e.IV) != envelopeIVLen || len(e.CT) < envelopeTagBits/8 || len(e.Wrapped) == 0 || e.KID == "" {
		return envelopeV2{}, fmt.Errorf("%w: bad envelope (v=%d)", ErrOpen, probe.V)
	}
	return e, nil
}

// sealAAD binds party, keyset, generation (kid) and what the caller binds (role, id, generation, blob kind) so a blob cannot be moved.
func sealAAD(party, kid string, aad []byte) []byte {
	out := []byte("qv-attested-seal-v2\n" + party + "\n" + kid + "\n")
	return append(out, aad...)
}

// BrokerAPI is the part of the broker client the sealer uses (a fake in unit tests).
type BrokerAPI interface {
	Challenge(ctx context.Context) (attest.ChallengeResponse, error)
	Release(ctx context.Context, req attest.ReleaseRequest) (attest.ReleaseResponse, error)
	NewKey(ctx context.Context, req attest.ReleaseRequest) (attest.ReleaseResponse, error)
}

var _ BrokerAPI = (*brokerclient.Client)(nil)

type dataKey struct {
	buf  *secretBuf
	blob []byte
}

// AttestedSealer implements ScopedSealer. It also implements Sealer, but the plain Seal and Open refuse: a key needs a scope.
type AttestedSealer struct {
	party     string
	api       BrokerAPI
	att       attest.Attester
	callerPin [32]byte
	log       *slog.Logger

	mu     sync.Mutex
	keys   map[SealScope]*dataKey
	closed bool

	netMu sync.Mutex // one broker exchange at a time: a challenge is single use, and the broker rate-limits the party

	ready atomic.Bool
	stats sealerStats
}

// sealerStats are the counters of the sealer (WriteMetrics): what the party did with the broker, by outcome. No secrets.
type sealerStats struct {
	mu sync.Mutex
	n  map[string]uint64
}

func (s *sealerStats) add(k string) {
	s.mu.Lock()
	if s.n == nil {
		s.n = map[string]uint64{}
	}
	s.n[k]++
	s.mu.Unlock()
}

func (s *sealerStats) snapshot() map[string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint64, len(s.n))
	for k, v := range s.n {
		out[k] = v
	}
	return out
}

// NewAttestedSealerWith builds a sealer on a given broker client and attester. callerPin is the pin of the TLS key of the link to the broker (the
// evidence is bound to it). Tests use it directly; NewAttestedSealer builds the real client.
func NewAttestedSealerWith(party string, api BrokerAPI, att attest.Attester, callerPin [32]byte, log *slog.Logger) (*AttestedSealer, error) {
	if party == "" || api == nil || att == nil {
		return nil, errors.New("sealer attested: party, broker client and attester are required")
	}
	if log == nil {
		log = slog.Default()
	}
	// Locked memory must work before the party goes on: a key that can be swapped out is not kept.
	probe, err := newSecretBuf(32)
	if err != nil {
		return nil, err
	}
	probe.wipe()
	return &AttestedSealer{party: party, api: api, att: att, callerPin: callerPin, log: log, keys: map[SealScope]*dataKey{}}, nil
}

// attesterFactories are registered by build-tagged files: the simulated attester only under -tags teesim; the Nitro device attester (sealer_attested_nitro.go,
// Linux) registers itself here. The production build has "nitro" and no "mock".
var attesterFactories = map[string]func(AttesterConfig) (attest.Attester, error){}

// NewAttestedSealer reads the config: broker address and pinned key, the party's certificate for the link, and the attester.
func NewAttestedSealer(role string, c SealerConfig) (*AttestedSealer, error) {
	if err := c.validateAttested(); err != nil {
		return nil, err
	}
	f, ok := attesterFactories[c.Attester.Type]
	if !ok {
		var have []string
		for k := range attesterFactories {
			have = append(have, k)
		}
		sort.Strings(have)
		if len(have) == 0 {
			return nil, fmt.Errorf("sealer attested: attester %q is not available: this build contains no attester (the Nitro attester needs Linux; the simulated one exists only in builds made with -tags teesim). A party with sealer.type \"attested\" refuses to start without one; it never falls back to another sealer", c.Attester.Type)
		}
		return nil, fmt.Errorf("sealer attested: attester %q is not available in this build (have: %s)", c.Attester.Type, strings.Join(have, ", "))
	}
	att, err := f(c.Attester)
	if err != nil {
		return nil, fmt.Errorf("sealer attested: attester: %w", err)
	}
	if c.Release.Type == "kms" {
		api, err := newKMSReleaser(c.Release.KMS)
		if err != nil {
			return nil, err
		}
		return NewAttestedSealerWith(role, api, att, [32]byte{}, slog.Default()) // no broker link, so no TLS pin to bind: KMS binds by encryption context
	}
	cert, err := tls.LoadX509KeyPair(c.BrokerCertFile, c.BrokerKeyFile)
	if err != nil {
		return nil, fmt.Errorf("sealer attested: the party's certificate for the broker link: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("sealer attested: broker_cert_file: %w", err)
	}
	pins, err := parsePins(c.BrokerPins)
	if err != nil {
		return nil, err
	}
	cl := brokerclient.NewClient(c.BrokerURL, cert, pins)
	return NewAttestedSealerWith(role, cl, att, sha256.Sum256(leaf.RawSubjectPublicKeyInfo), slog.Default())
}

// ---- Sealer (plain): refused ----

func (s *AttestedSealer) Seal(aad, plaintext []byte) ([]byte, error) {
	return nil, errors.New("sealer attested: a scope (keyset and generation) is required; use SealScoped")
}

func (s *AttestedSealer) Open(aad, sealed []byte) ([]byte, error) {
	return nil, errors.New("sealer attested: a scope (keyset and generation) is required; use OpenScoped")
}

var _ Sealer = (*AttestedSealer)(nil)
var _ ScopedSealer = (*AttestedSealer)(nil)

// ---- the exchange with the broker ----

type brokerError struct {
	Kind string // "refused", "unreachable", "protocol"
	Code string // the broker's refusal code, if any
	Err  error
}

func (e *brokerError) Error() string { return e.Err.Error() }
func (e *brokerError) Unwrap() error { return e.Err }

// Allowlist says whether the broker refused because the measurement is not (or no longer) allowed.
func (e *brokerError) Allowlist() bool { return strings.HasPrefix(e.Code, "allowlist:") }

// classify turns any error of an exchange into a brokerError (and counts it).
func (s *AttestedSealer) classify(err error) *brokerError {
	var ke *kmsrelease.RefusedError
	if errors.As(err, &ke) { // AWS KMS: an AccessDenied is the key policy refusing the image, the same case as the broker's allowlist
		code := "kms:" + ke.Code
		if ke.Code == "AccessDeniedException" {
			code = "allowlist:kms_access_denied"
		}
		s.stats.add("refused:" + refusalClass(code))
		return &brokerError{Kind: "refused", Code: code, Err: fmt.Errorf("%w: %s", ErrKeyRefused, err.Error())}
	}
	var re *brokerclient.RefusedError
	if errors.As(err, &re) {
		s.stats.add("refused:" + refusalClass(re.Code))
		return &brokerError{Kind: "refused", Code: re.Code, Err: fmt.Errorf("%w: %s", ErrKeyRefused, err.Error())}
	}
	var ne net.Error
	if errors.As(err, &ne) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || isConnErr(err) {
		s.stats.add("unreachable")
		return &brokerError{Kind: "unreachable", Err: fmt.Errorf("sealer attested: broker unreachable: %w", err)}
	}
	s.stats.add("error")
	return &brokerError{Kind: "protocol", Err: fmt.Errorf("sealer attested: %w", err)}
}

func isConnErr(err error) bool {
	m := err.Error()
	for _, w := range []string{"connection refused", "connection reset", "EOF", "no such host", "tls:", "i/o timeout", "broken pipe"} {
		if strings.Contains(m, w) {
			return true
		}
	}
	return false
}

// refusalClass groups the broker's refusal codes for the metric: the measurement is not allowlisted, the evidence did not verify, the call was
// rate limited, other.
func refusalClass(code string) string {
	switch {
	case strings.HasPrefix(code, "allowlist:"):
		return "allowlist"
	case strings.HasPrefix(code, "verify:"):
		return "verify"
	case strings.HasPrefix(code, "nonce:"):
		return "nonce"
	case code == "rate_limited":
		return "rate_limited"
	}
	return "other"
}

// exchange runs one challenge + release/newkey for one keyset and opens every returned key with the key made here for this call. It returns the
// keys (in locked memory) and, for newkey, the wrapped blobs.
func (s *AttestedSealer) exchange(ctx context.Context, purpose, keyset string, gens []uint64, blobs [][]byte) (keys []*secretBuf, newBlobs [][]byte, err error) {
	s.netMu.Lock()
	defer s.netMu.Unlock()
	rc := attest.RequestContext{Party: s.party, Keyset: keyset, Generations: gens, Purpose: purpose}
	if err := rc.Validate(); err != nil {
		return nil, nil, fmt.Errorf("sealer attested: %w", err)
	}
	ch, err := s.api.Challenge(ctx)
	if err != nil {
		return nil, nil, s.classify(err)
	}
	var open func(aad, sealed []byte) ([]byte, error) // opens a released key with the key made here for this call
	var pub []byte
	if rk, ok := s.api.(attest.RecipientKeyMaker); ok { // AWS KMS needs an RSA key and answers with CMS
		if pub, open, err = rk.NewRecipient(); err != nil {
			return nil, nil, err
		}
	} else {
		priv, p, err := attest.NewReleaseKey() // lives in this process only, for this call
		if err != nil {
			return nil, nil, err
		}
		pub, open = p, func(aad, sealed []byte) ([]byte, error) { return attest.OpenFrom(priv, aad, sealed) }
	}
	ud := rc.UserData(blobs, s.callerPin)
	ev, err := s.att.Attest(ch.Nonce, pub, ud)
	if err != nil {
		s.stats.add("evidence_failed")
		return nil, nil, &brokerError{Kind: "protocol", Err: fmt.Errorf("sealer attested: cannot produce evidence: %w", err)}
	}
	req := attest.ReleaseRequest{Nonce: ch.Nonce, Evidence: ev, Context: rc, Blobs: blobs}
	var resp attest.ReleaseResponse
	if purpose == attest.PurposeUnseal {
		resp, err = s.api.Release(ctx, req)
	} else {
		resp, err = s.api.NewKey(ctx, req)
	}
	if err != nil {
		return nil, nil, s.classify(err)
	}
	if len(resp.Keys) != len(gens) {
		s.stats.add("error")
		return nil, nil, &brokerError{Kind: "protocol", Err: fmt.Errorf("sealer attested: the broker returned %d keys for %d generations", len(resp.Keys), len(gens))}
	}
	defer func() {
		if err != nil {
			for _, k := range keys {
				k.wipe()
			}
			keys, newBlobs = nil, nil
		}
	}()
	for i, k := range resp.Keys {
		if k.Generation != gens[i] {
			s.stats.add("error")
			return keys, nil, &brokerError{Kind: "protocol", Err: fmt.Errorf("sealer attested: the broker answered generation %d where %d was asked", k.Generation, gens[i])}
		}
		pt, oerr := open(attest.ResponseAAD(ud, ch.Nonce, k.Generation), k.Sealed)
		if oerr != nil {
			s.stats.add("error")
			return keys, nil, &brokerError{Kind: "protocol", Err: fmt.Errorf("sealer attested: the released key for generation %d does not open under this process's key: %w", k.Generation, oerr)}
		}
		if len(pt) != 32 {
			wipeBytes(pt)
			s.stats.add("error")
			return keys, nil, &brokerError{Kind: "protocol", Err: fmt.Errorf("sealer attested: the released key for generation %d has %d bytes", k.Generation, len(pt))}
		}
		buf, serr := newSecretBuf(32)
		if serr != nil {
			wipeBytes(pt)
			return keys, nil, serr
		}
		copy(buf.bytes(), pt)
		wipeBytes(pt)
		keys = append(keys, buf)
		if purpose == attest.PurposeCreate {
			if len(k.Blob) == 0 {
				s.stats.add("error")
				return keys, nil, &brokerError{Kind: "protocol", Err: fmt.Errorf("sealer attested: newkey returned no wrapped key for generation %d", k.Generation)}
			}
			newBlobs = append(newBlobs, k.Blob)
		}
	}
	s.stats.add("exchange_ok:" + purpose)
	return keys, newBlobs, nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// install puts a key in the cache; if one is already there (another goroutine was faster) the new one is wiped and the cached one wins.
func (s *AttestedSealer) install(sc SealScope, k *secretBuf, blob []byte) *dataKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		k.wipe()
		return nil
	}
	if old, ok := s.keys[sc]; ok {
		k.wipe()
		return old
	}
	dk := &dataKey{buf: k, blob: append([]byte(nil), blob...)}
	s.keys[sc] = dk
	return dk
}

func (s *AttestedSealer) cached(sc SealScope) *dataKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys[sc]
}

// release asks the broker for the keys of the given generations of one keyset (blobs in the same order) and caches them.
func (s *AttestedSealer) release(ctx context.Context, keyset string, gens []uint64, blobs [][]byte) error {
	for len(gens) > 0 {
		n := len(gens)
		if n > attest.MaxGenerations {
			n = attest.MaxGenerations
		}
		keys, _, err := s.exchange(ctx, attest.PurposeUnseal, keyset, gens[:n], blobs[:n])
		if err != nil {
			return err
		}
		for i, k := range keys {
			s.install(SealScope{keyset, gens[i]}, k, blobs[i])
		}
		gens, blobs = gens[n:], blobs[n:]
	}
	return nil
}

// newKey asks the broker for a new data key for one generation, caches it and returns it.
func (s *AttestedSealer) newKey(ctx context.Context, sc SealScope) (*dataKey, error) {
	keys, blobs, err := s.exchange(ctx, attest.PurposeCreate, sc.Keyset, []uint64{sc.Generation}, nil)
	if err != nil {
		return nil, err
	}
	dk := s.install(sc, keys[0], blobs[0])
	if dk == nil {
		return nil, errors.New("sealer attested: closed")
	}
	return dk, nil
}

// ---- seal and open ----

func gcmOf(k *dataKey) (cipher.AEAD, error) {
	// The AES key schedule built here lives on the Go heap for the duration of the call; the key itself stays in locked memory.
	b, err := aes.NewCipher(k.buf.bytes())
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// SealScoped seals under the data key of sc. If this process has no key for sc yet, the broker makes a new one (attested), which is how a new
// generation (DKG, refresh candidate) gets its key. The sealed bytes carry the broker's wrapped form of the key.
func (s *AttestedSealer) SealScoped(ctx context.Context, sc SealScope, aad, plaintext []byte) ([]byte, error) {
	dk := s.cached(sc)
	if dk == nil && !s.ready.Load() {
		return nil, &UnavailableError{Msg: "attested sealer: the data keys have not been released yet"}
	}
	if dk == nil {
		var err error
		if dk, err = s.newKey(ctx, sc); err != nil {
			return nil, &UnavailableError{Msg: "attested sealer: no data key for " + sc.kid() + ": " + err.Error()}
		}
	}
	g, err := gcmOf(dk)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, envelopeIVLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct := g.Seal(nil, iv, plaintext, sealAAD(s.party, sc.kid(), aad))
	return json.Marshal(envelopeV2{V: envV2, KID: sc.kid(), Wrapped: dk.blob, IV: iv, CT: ct})
}

// OpenScoped opens a sealed blob of sc. A blob that names another scope, was sealed for another party or has other associated data does not open.
// If the key is not in memory (a generation the start-up did not preload) it is released on demand, from the blob's wrapped form.
func (s *AttestedSealer) OpenScoped(ctx context.Context, sc SealScope, aad, sealed []byte) ([]byte, error) {
	e, err := parseEnvelopeV2(sealed)
	if err != nil {
		return nil, err
	}
	if e.KID != sc.kid() {
		return nil, fmt.Errorf("%w: the blob is for %s, not for %s", ErrOpen, e.KID, sc.kid())
	}
	dk := s.cached(sc)
	if dk == nil && !s.ready.Load() {
		return nil, &UnavailableError{Msg: "attested sealer: the data keys have not been released yet"}
	}
	if dk == nil {
		if err := s.release(ctx, sc.Keyset, []uint64{sc.Generation}, [][]byte{e.Wrapped}); err != nil {
			return nil, &UnavailableError{Msg: "attested sealer: no data key for " + sc.kid() + ": " + err.Error()}
		}
		if dk = s.cached(sc); dk == nil {
			return nil, errors.New("sealer attested: closed")
		}
	}
	g, err := gcmOf(dk)
	if err != nil {
		return nil, err
	}
	pt, err := g.Open(nil, e.IV, e.CT, sealAAD(s.party, sc.kid(), aad))
	if err != nil {
		return nil, fmt.Errorf("%w: %s does not open under this party's data key and associated data", ErrOpen, sc.kid())
	}
	return pt, nil
}

// Forget wipes the data key of sc.
func (s *AttestedSealer) Forget(sc SealScope) {
	s.mu.Lock()
	dk := s.keys[sc]
	delete(s.keys, sc)
	s.mu.Unlock()
	if dk != nil {
		dk.buf.wipe()
	}
}

// Held lists the scopes whose key is in memory (tests; no key material).
func (s *AttestedSealer) Held() []SealScope {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []SealScope
	for k := range s.keys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Keyset != out[j].Keyset {
			return out[i].Keyset < out[j].Keyset
		}
		return out[i].Generation < out[j].Generation
	})
	return out
}

// Close wipes every key. Later seals and opens fail.
func (s *AttestedSealer) Close() {
	s.mu.Lock()
	s.closed = true
	keys := s.keys
	s.keys = map[SealScope]*dataKey{}
	s.mu.Unlock()
	for _, k := range keys {
		k.buf.wipe()
	}
	s.ready.Store(false)
}

// ---- start-up ----

// UnlockSet is what is on disk: the wrapped local key (nil when there is none) and the wrapped key of every generation file, by keyset.
type UnlockSet struct {
	Local   []byte
	Fresh   bool // the data directory holds nothing yet: a local key is made
	Keysets map[string]map[uint64][]byte
}

// Preload asks the broker for every key the set names (those already held are skipped, so a retry only fetches what is missing) and, for a fresh
// directory, makes the local key and returns its wrapped form for the store to write. It marks the sealer ready when everything is held.
func (s *AttestedSealer) Preload(ctx context.Context, set UnlockSet) (newLocal []byte, err error) {
	switch {
	case set.Local != nil:
		if s.cached(LocalScope) == nil {
			if err := s.release(ctx, LocalScope.Keyset, []uint64{LocalScope.Generation}, [][]byte{set.Local}); err != nil {
				return nil, err
			}
		}
	case set.Fresh:
		dk := s.cached(LocalScope)
		if dk == nil {
			var err error
			if dk, err = s.newKey(ctx, LocalScope); err != nil {
				return nil, err
			}
		}
		newLocal = append([]byte(nil), dk.blob...)
	default:
		return nil, errors.New("sealer attested: this data directory has state but no local key file (local.key.json): it was deleted, or it is PKCS#11-sealed (v1) data that has to be migrated (docs/runbooks/tee-broker.md)")
	}
	ids := make([]string, 0, len(set.Keysets))
	for id := range set.Keysets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		var gens []uint64
		var blobs [][]byte
		var gl []uint64
		for g := range set.Keysets[id] {
			gl = append(gl, g)
		}
		sort.Slice(gl, func(i, j int) bool { return gl[i] < gl[j] })
		for _, g := range gl {
			if s.cached(SealScope{id, g}) == nil {
				gens, blobs = append(gens, g), append(blobs, set.Keysets[id][g])
			}
		}
		if len(gens) == 0 {
			continue
		}
		if err := s.release(ctx, id, gens, blobs); err != nil {
			return newLocal, fmt.Errorf("keyset %q: %w", id, err)
		}
	}
	s.ready.Store(true)
	return newLocal, nil
}

// Ready says whether the start-up preload finished.
func (s *AttestedSealer) Ready() bool { return s.ready.Load() }

// Stats returns the counters of the sealer.
func (s *AttestedSealer) Stats() map[string]uint64 { return s.stats.snapshot() }

// brokerKinds is exposed for the unlock loop's log lines.
func brokerKindOf(err error) (kind, code string, allowlist bool) {
	var be *brokerError
	if errors.As(err, &be) {
		return be.Kind, be.Code, be.Allowlist()
	}
	return "other", "", false
}
