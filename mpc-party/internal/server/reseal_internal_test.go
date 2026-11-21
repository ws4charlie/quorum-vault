package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// resealRig is a party's data directory with shares sealed by a PKCS#11 sealer on the fake token of one profile.
type resealRig struct {
	t      *testing.T
	pc     profileCase
	hsm    *fakeHSM
	cfg    *Config
	shares map[string][]byte // "<id>/g<N>.json" -> the plaintext share
}

func newResealRig(t *testing.T, pc profileCase) *resealRig {
	t.Helper()
	r := &resealRig{t: t, pc: pc, hsm: pc.newFake("qv-party-1"), shares: map[string][]byte{}}
	r.cfg = &Config{Role: "A", DataDir: t.TempDir(), Sealer: SealerConfig{Type: "pkcs11", Token: "qv-party-1", Provider: pc.name}}
	s := r.sealer("")
	for _, c := range []struct {
		id  string
		gen uint64
	}{{"k1", 1}, {"k1", 2}, {"k2", 1}, {"ed", 3}} {
		share := make([]byte, 500+int(c.gen)*70)
		if pc.chunked && c.id == "k2" {
			share = make([]byte, 2*cloudhsmChunk+9) // several parts
		}
		rand.Read(share)
		aad := aadTKeyset("A", c.id, c.gen)
		sealed, err := s.Seal(aad, share)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(keysetFile{V: 3, Scheme: 1, Role: "A", Gen: c.gen, Sealed: sealed})
		p := filepath.Join(r.cfg.DataDir, "keysets", c.id, fmt.Sprintf("g%d.json", c.gen))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		r.shares[filepath.Join(c.id, fmt.Sprintf("g%d.json", c.gen))] = share
	}
	return r
}

func (r *resealRig) sealer(label string) *PKCS11Sealer {
	r.t.Helper()
	s, err := newPKCS11SealerLabel(r.hsm, r.pc.prof, "fake.so", r.hsm.label, "user:"+randHex(8), label)
	if err != nil {
		r.t.Fatal(err)
	}
	s.sleep = func(time.Duration) {}
	return s
}

func (r *resealRig) mk(label string) (*PKCS11Sealer, error) {
	s, err := newPKCS11SealerLabel(r.hsm, r.pc.prof, "fake.so", r.hsm.label, "user:"+randHex(8), label)
	if err == nil {
		s.sleep = func(time.Duration) {}
	}
	return s, err
}

func (r *resealRig) reseal(label string, o ResealOptions) (ResealReport, error) {
	return resealWrapKey(context.Background(), r.cfg, label, r.mk, o)
}

// openAll opens every share with a sealer that seals under `label` (any key an envelope names is found) and compares it with what was sealed.
func (r *resealRig) openAll(label string) map[string]int {
	r.t.Helper()
	s := r.sealer(label)
	by := map[string]int{}
	for rel, want := range r.shares {
		id, file := filepath.Split(rel)
		raw, err := os.ReadFile(filepath.Join(r.cfg.DataDir, "keysets", filepath.Clean(id), file))
		if err != nil {
			r.t.Fatal(err)
		}
		var kf keysetFile
		if err := json.Unmarshal(raw, &kf); err != nil {
			r.t.Fatal(err)
		}
		var gen uint64
		fmt.Sscanf(file, "g%d.json", &gen)
		got, err := s.Open(aadTKeyset("A", filepath.Clean(id), gen), kf.Sealed)
		if err != nil || !bytes.Equal(got, want) {
			r.t.Fatalf("%s does not open or differs: %v", rel, err)
		}
		by[envelopeKeyLabel(kf.Sealed)]++
	}
	return by
}

const newWrapLabel = "qv-share-wrap-2"

func TestResealMovesEverySharePerProfile(t *testing.T) {
	for _, pc := range profileCases {
		t.Run(pc.name, func(t *testing.T) {
			r := newResealRig(t, pc)
			if by := r.openAll(""); by[pkcs11WrapKeyLabel] != 4 {
				t.Fatalf("before: %v", by)
			}
			// an envelope under the default key carries no label (files written before this feature are byte-compatible)
			raw, _ := os.ReadFile(filepath.Join(r.cfg.DataDir, "keysets", "k1", "g1.json"))
			var kf0 keysetFile
			json.Unmarshal(raw, &kf0)
			if bytes.Contains(kf0.Sealed, []byte(`"k":`)) {
				t.Fatalf("a default-key envelope names its key: %s", kf0.Sealed)
			}
			rep, err := r.reseal(newWrapLabel, ResealOptions{})
			if err != nil || rep.Moved != 4 || rep.Generations != 4 || rep.Before[pkcs11WrapKeyLabel] != 4 {
				t.Fatalf("reseal: %+v %v", rep, err)
			}
			if by := r.openAll(newWrapLabel); by[newWrapLabel] != 4 || len(by) != 1 {
				t.Fatalf("after: %v", by)
			}
			if _, err := os.Stat(filepath.Join(r.cfg.DataDir, resealStagingDir)); err == nil {
				t.Error("the staging directory was left behind")
			}

			// the old sealer (default label) still opens them: the envelope names its key
			r.openAll("")
			// once more with the same label: nothing to move
			if rep, err := r.reseal(newWrapLabel, ResealOptions{}); err != nil || rep.Moved != 0 || rep.Generations != 4 {
				t.Fatalf("second run: %+v %v", rep, err)
			}
			// a refresh after the switch seals under the new label (the party runs with it), and mixed directories open
			s := r.sealer(newWrapLabel)
			share := []byte("a refreshed share")
			sealed, err := s.Seal(aadTKeyset("A", "k1", 3), share)
			if err != nil || envelopeKeyLabel(sealed) != newWrapLabel {
				t.Fatalf("seal after the switch: %v %s", err, envelopeKeyLabel(sealed))
			}
		})
	}
}

// The party can die at any point of the re-seal: before the marker the old files are untouched, after it the moves are finished by running the command
// again; in between the directory is a mixture that opens in full.
func TestResealCrashAtEveryPoint(t *testing.T) {
	for _, pc := range profileCases {
		for _, at := range []string{"staged", "verified", "committed", "moved:1", "moved:2", "moved:3"} {
			t.Run(pc.name+"/"+at, func(t *testing.T) {
				r := newResealRig(t, pc)
				boom := errors.New("crash at " + at)
				_, err := r.reseal(newWrapLabel, ResealOptions{Stage: func(n string) error {
					if n == at {
						return boom
					}
					return nil
				}})
				if !errors.Is(err, boom) {
					t.Fatalf("stopped at %s: %v", at, err)
				}
				by := r.openAll(newWrapLabel) // a party started in the middle opens everything
				wantMoved := 0
				fmt.Sscanf(at, "moved:%d", &wantMoved) // before the marker, and at it, no file has been replaced
				if by[newWrapLabel] != wantMoved || by[pkcs11WrapKeyLabel] != 4-wantMoved {
					t.Fatalf("at %s the directory is %v, want %d file(s) under the new key", at, by, wantMoved)
				}
				rep, err := r.reseal(newWrapLabel, ResealOptions{})
				if err != nil {
					t.Fatalf("run again: %v", err)
				}
				if at != "staged" && at != "verified" && !rep.Resumed {
					t.Errorf("after the marker the command must only finish the moves: %+v", rep)
				}
				if by := r.openAll(newWrapLabel); by[newWrapLabel] != 4 || len(by) != 1 {
					t.Fatalf("after the second run: %v", by)
				}
			})
		}
	}
}

func TestDestroyWrapKeyOnlyWhenNothingNeedsIt(t *testing.T) {
	for _, pc := range profileCases {
		t.Run(pc.name, func(t *testing.T) {
			r := newResealRig(t, pc)
			destroy := func(label string) error { return destroyWrapKey(r.cfg, label, r.mk) }
			// nothing re-sealed yet: the default key is under every file, and is the configured one
			if err := destroy(pkcs11WrapKeyLabel); err == nil || !strings.Contains(err.Error(), "seals under") {
				t.Fatalf("the configured key: %v", err)
			}
			if _, err := r.reseal(newWrapLabel, ResealOptions{}); err != nil {
				t.Fatal(err)
			}
			// the configuration still names the old key: destroying it is refused, and so is destroying the new one
			if err := destroy(pkcs11WrapKeyLabel); err == nil || !strings.Contains(err.Error(), "seals under") {
				t.Fatalf("old key while the configuration still names it: %v", err)
			}
			r.cfg.Sealer.WrapKeyLabel = newWrapLabel
			if err := destroy(newWrapLabel); err == nil || !strings.Contains(err.Error(), "seals under") {
				t.Fatalf("the new key: %v", err)
			}
			// a file still under the old key stops the destroy
			p := filepath.Join(r.cfg.DataDir, "keysets", "k1", "g9.json")
			old := r.sealer("")
			sealed, _ := old.Seal(aadTKeyset("A", "k1", 9), []byte("late"))
			raw, _ := json.Marshal(keysetFile{V: 3, Scheme: 1, Role: "A", Gen: 9, Sealed: sealed})
			os.WriteFile(p, raw, 0o600)
			if err := destroy(pkcs11WrapKeyLabel); err == nil || !strings.Contains(err.Error(), "still sealed under") {
				t.Fatalf("a file under the old key: %v", err)
			}
			os.Remove(p)
			// an unfinished reseal stops it too
			os.MkdirAll(filepath.Join(r.cfg.DataDir, resealStagingDir), 0o700)
			if err := destroy(pkcs11WrapKeyLabel); err == nil || !strings.Contains(err.Error(), "did not finish") {
				t.Fatalf("an unfinished reseal: %v", err)
			}
			os.RemoveAll(filepath.Join(r.cfg.DataDir, resealStagingDir))
			if err := destroy("no-such-key"); err == nil || !strings.Contains(err.Error(), "no wrap key") {
				t.Fatalf("a label the token does not have: %v", err)
			}
			if err := destroy(pkcs11WrapKeyLabel); err != nil {
				t.Fatalf("destroy: %v", err)
			}
			s := r.sealer(newWrapLabel)
			if ok, _ := s.HasKey(pkcs11WrapKeyLabel); ok {
				t.Error("the old key is still in the token")
			}
			if ok, _ := s.HasKey(newWrapLabel); !ok {
				t.Error("the new key is gone")
			}
			if by := r.openAll(newWrapLabel); by[newWrapLabel] != 4 {
				t.Fatalf("after destroying the old key: %v", by)
			}
		})
	}
}

func TestResealRefusals(t *testing.T) {
	r := newResealRig(t, profileCases[0])
	att := *r.cfg
	att.Sealer = SealerConfig{Type: AttestedSealerType}
	if _, err := resealWrapKey(context.Background(), &att, newWrapLabel, r.mk, ResealOptions{}); err == nil || !strings.Contains(err.Error(), "only a PKCS#11 party") {
		t.Errorf("attested config: %v", err)
	}
	if _, err := r.reseal("bad label!", ResealOptions{}); err == nil {
		t.Error("a label with a space and a bang")
	}
	// a share the token cannot open (another party's token) stops the run before anything is staged over the files
	other := newResealRig(t, profileCases[0])
	r2 := *other
	r2.hsm = profileCases[0].newFake("qv-party-1") // a token that does not have the key
	if _, err := r2.reseal(newWrapLabel, ResealOptions{}); err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Errorf("a token without the key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(other.cfg.DataDir, resealStagingDir, committedMarker)); err == nil {
		t.Error("a marker was written")
	}
	by, _ := WrapKeysInUse(other.cfg.DataDir)
	if by[pkcs11WrapKeyLabel] != 4 {
		t.Errorf("the files were touched: %v", by)
	}
}

func TestWrapKeyLabelInConfig(t *testing.T) {
	c := &Config{Sealer: SealerConfig{Type: "pkcs11", WrapKeyLabel: "bad label"}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "wrap_key_label") {
		t.Errorf("validate: %v", err)
	}
	c = &Config{Sealer: SealerConfig{Type: AttestedSealerType, WrapKeyLabel: "x"}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "only for sealer.type pkcs11") {
		t.Errorf("attested with a label: %v", err)
	}
}
