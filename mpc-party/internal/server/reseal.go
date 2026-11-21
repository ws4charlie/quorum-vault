package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// ResealWrapKey moves every share of a party from the wrap keys it is sealed under now to ONE new wrap key in the same PKCS#11 token (the token is the
// party's own HSM; sealer.type pkcs11, either profile). It is the planned answer to "the wrap key must be replaced" (a custodian leaves the HSM, the
// HSM's key policy changes, a suspected exposure of the token's key that did not reach the shares): no keyset changes, no public key, no refresh.
// What it does NOT cure is a wrap key that an attacker could USE (the same token access opens the new key too); that is a replacement of the keysets.
//
// It follows the structure of MigrateSeal. It runs OFFLINE (the party is stopped; it takes the data directory lock). Every generation file is opened
// with the key its envelope names and sealed again under the new key into <data_dir>/.reseal-wrap; each staged file is opened again with the new key
// and compared with what the old key opened; only then is the marker COMMITTED written, and only after the marker are the files moved over the old
// ones (rename, one by one). Until the marker exists the old files are untouched and the command can be run again (it throws the staging directory
// away). After the marker it only finishes the moves. Envelopes name their key, so a directory in between (some files moved, some not) opens in full:
// the party may even start in that state.
//
// A resumed run never overwrites a file that changed after staging: the hash of every live file is recorded before the marker, and a staged file is
// moved only over a live file that still has it. Between the runs a party may have started, discarded an undecided refresh candidate and written a newer
// share at the same generation number; the staged copy of the discarded one is dropped (reported in Skipped) and the newer file stays, still under
// whatever key it names. Run the command again to move what was skipped.
//
// After it: set sealer.wrap_key_label to the new label in the party's configuration and restart; when every keyset is resolved, remove the old key from
// the token with DestroyWrapKey (it refuses while anything is still sealed under it).
type ResealOptions struct {
	// Stage is called at named points ("staged", "verified", "committed", "moved:<n>"); an error aborts the command there, as a crash would (tests).
	Stage func(name string) error
}

// ResealReport says what was done.
type ResealReport struct {
	Generations int            // generation files now under the new key
	Moved       int            // of them, the ones that were under another key
	Before      map[string]int // wrap key label -> generation files that were sealed under it before the run
	Resumed     bool           // the marker existed: only the moves were run
	Skipped     []string       // staged files NOT moved because the live file changed since staging (a party ran in between): run the command again
}

const resealStagingDir = ".reseal-wrap"

// ResealWrapKey with the real token. cfg is the party's configuration (sealer pkcs11); newLabel is the label of the new key, created in the token when
// it does not exist.
func ResealWrapKey(ctx context.Context, cfg *Config, newLabel string, opt ResealOptions) (ResealReport, error) {
	return resealWrapKey(ctx, cfg, newLabel, func(label string) (*PKCS11Sealer, error) {
		c := cfg.Sealer
		c.WrapKeyLabel = label
		return NewPKCS11Sealer(c)
	}, opt)
}

func resealWrapKey(ctx context.Context, cfg *Config, newLabel string, mk func(label string) (*PKCS11Sealer, error), opt ResealOptions) (ResealReport, error) {
	var rep ResealReport
	stage := func(n string) error {
		if opt.Stage != nil {
			return opt.Stage(n)
		}
		return nil
	}
	if cfg.Sealer.Type != "pkcs11" {
		return rep, fmt.Errorf("reseal: the configuration has sealer.type %q: only a PKCS#11 party has a wrap key of its own (the attested sealer's keys are the broker's)", cfg.Sealer.Type)
	}
	if !wrapKeyLabelRE.MatchString(newLabel) {
		return rep, fmt.Errorf("reseal: label %q: letters, digits, dot, dash and underscore, 1 to 64 characters", newLabel)
	}
	lock, err := acquireDataLock(cfg.DataDir)
	if err != nil {
		return rep, err
	}
	defer lock.release()
	stg := filepath.Join(cfg.DataDir, resealStagingDir)
	if _, err := os.Stat(filepath.Join(stg, committedMarker)); err == nil {
		rep.Resumed = true
		err := finishMoves(stg, cfg.DataDir, stage, func(rel string) error { rep.Skipped = append(rep.Skipped, rel); return nil })
		return rep, err
	}
	sealer, err := mk(newLabel) // makes the key when the token has none under this label
	if err != nil {
		return rep, fmt.Errorf("reseal: %w", err)
	}
	if err := os.RemoveAll(stg); err != nil {
		return rep, err
	}
	role, dir := cfg.Role, cfg.DataDir
	rep.Before = map[string]int{}
	sums := map[string][32]byte{} // staged file (<id>/g<N>.json) -> digest of the plaintext share

	ents, err := os.ReadDir(filepath.Join(dir, "keysets"))
	if err != nil {
		return rep, err
	}
	for _, e := range ents {
		if !e.IsDir() || !validID(e.Name()) {
			continue
		}
		id := e.Name()
		files, err := os.ReadDir(filepath.Join(dir, "keysets", id))
		if err != nil {
			return rep, err
		}
		for _, f := range files {
			m := genFileRe.FindStringSubmatch(f.Name())
			if m == nil {
				continue
			}
			gen, _ := strconv.ParseUint(m[1], 10, 64)
			raw, err := os.ReadFile(filepath.Join(dir, "keysets", id, f.Name()))
			if err != nil {
				return rep, err
			}
			var kf keysetFile
			if err := json.Unmarshal(raw, &kf); err != nil || kf.Role != role || kf.Gen != gen {
				return rep, fmt.Errorf("reseal: keyset %s generation %d: bad file", id, gen)
			}
			aad, err := shareAAD(role, id, gen, kf)
			if err != nil {
				return rep, err
			}
			label := envelopeKeyLabel(kf.Sealed)
			if label == "" {
				return rep, fmt.Errorf("reseal: keyset %s generation %d is not sealed by the PKCS#11 sealer (the attested sealer's data? run it with the party's own configuration)", id, gen)
			}
			rep.Before[label]++
			rep.Generations++
			if label == newLabel {
				continue // already under the new key
			}
			plain, err := sealer.Open(aad, kf.Sealed)
			if err != nil {
				return rep, fmt.Errorf("reseal: keyset %s generation %d does not open with the token's key %q (is this the party's own configuration?): %w", id, gen, label, err)
			}
			nsealed, err := sealer.Seal(aad, plain)
			if err != nil {
				wipeBytes(plain)
				return rep, fmt.Errorf("reseal: keyset %s generation %d: %w", id, gen, err)
			}
			sums[filepath.Join(id, f.Name())] = sha256.Sum256(plain)
			wipeBytes(plain)
			kf.Sealed = nsealed
			out, _ := json.Marshal(kf)
			if err := os.MkdirAll(filepath.Join(stg, "keysets", id), 0o700); err != nil {
				return rep, err
			}
			if err := writeAtomic(filepath.Join(stg, "keysets", id, f.Name()), out); err != nil {
				return rep, err
			}
			rep.Moved++
		}
	}
	if rep.Moved == 0 { // everything is under the new key already: nothing to stage, nothing to commit
		return rep, os.RemoveAll(stg)
	}
	if err := stage("staged"); err != nil {
		return rep, err
	}
	// verify: every staged file opens under the new key and holds what the old file held
	for rel, want := range sums {
		id, file := filepath.Split(rel)
		id = filepath.Clean(id)
		gen, _ := strconv.ParseUint(genFileRe.FindStringSubmatch(file)[1], 10, 64)
		raw, err := os.ReadFile(filepath.Join(stg, "keysets", id, file))
		if err != nil {
			return rep, err
		}
		var kf keysetFile
		if err := json.Unmarshal(raw, &kf); err != nil {
			return rep, err
		}
		if l := envelopeKeyLabel(kf.Sealed); l != newLabel {
			return rep, fmt.Errorf("reseal: verification: keyset %s generation %d is sealed under %q, not %q", id, gen, l, newLabel)
		}
		aad, err := shareAAD(role, id, gen, kf)
		if err != nil {
			return rep, err
		}
		plain, err := sealer.Open(aad, kf.Sealed)
		if err != nil {
			return rep, fmt.Errorf("reseal: verification: keyset %s generation %d does not open under the new key: %w", id, gen, err)
		}
		got := sha256.Sum256(plain)
		wipeBytes(plain)
		if !bytes.Equal(got[:], want[:]) {
			return rep, fmt.Errorf("reseal: verification: keyset %s generation %d differs after sealing", id, gen)
		}
	}
	if err := stage("verified"); err != nil {
		return rep, err
	}
	if err := writeManifest(stg, dir); err != nil {
		return rep, err
	}
	if err := writeAtomic(filepath.Join(stg, committedMarker), []byte("verified "+newLabel+"\n")); err != nil {
		return rep, err
	}
	if err := stage("committed"); err != nil {
		return rep, err
	}
	err = finishMoves(stg, dir, stage, func(rel string) error { rep.Skipped = append(rep.Skipped, rel); return nil })
	return rep, err
}

func shareAAD(role, id string, gen uint64, kf keysetFile) ([]byte, error) {
	switch kf.V {
	case 2:
		return aadKeyset(role, id, gen, kf.Alg), nil
	case 3:
		return aadTKeyset(role, id, gen), nil
	}
	return nil, fmt.Errorf("reseal: keyset %s generation %d: unknown file version %d", id, gen, kf.V)
}

// WrapKeysInUse counts the generation files of a data directory by the wrap key label their envelope names.
func WrapKeysInUse(dataDir string) (map[string]int, error) {
	use := map[string]int{}
	ents, err := os.ReadDir(filepath.Join(dataDir, "keysets"))
	if errors.Is(err, os.ErrNotExist) {
		return use, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if !e.IsDir() || !validID(e.Name()) {
			continue
		}
		files, err := os.ReadDir(filepath.Join(dataDir, "keysets", e.Name()))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if genFileRe.FindStringSubmatch(f.Name()) == nil {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dataDir, "keysets", e.Name(), f.Name()))
			if err != nil {
				return nil, err
			}
			var kf keysetFile
			if err := json.Unmarshal(raw, &kf); err != nil {
				return nil, fmt.Errorf("keyset %s %s: bad file", e.Name(), f.Name())
			}
			l := envelopeKeyLabel(kf.Sealed)
			if l == "" {
				l = "(not a PKCS#11 envelope)"
			}
			use[l]++
		}
	}
	return use, nil
}

// DestroyWrapKey removes the wrap key with this label from the party's token. It refuses, in this order: a label the party still seals new envelopes
// under (the configuration's wrap_key_label), a label a staging directory of an unfinished reseal may still need, a label any generation file is
// sealed under, and a label the token does not have. The party need not be stopped: nothing is written to the data directory, and a party that is
// running seals under its configured label only.
func DestroyWrapKey(ctx context.Context, cfg *Config, label string) error {
	return destroyWrapKey(cfg, label, func(l string) (*PKCS11Sealer, error) {
		c := cfg.Sealer
		c.WrapKeyLabel = l
		return NewPKCS11Sealer(c)
	})
}

func destroyWrapKey(cfg *Config, label string, mk func(label string) (*PKCS11Sealer, error)) error {
	if cfg.Sealer.Type != "pkcs11" {
		return fmt.Errorf("reseal: the configuration has sealer.type %q: nothing to destroy", cfg.Sealer.Type)
	}
	cur := cfg.Sealer.WrapKeyLabel
	if cur == "" {
		cur = pkcs11WrapKeyLabel
	}
	if label == cur {
		return fmt.Errorf("reseal: %q is the key this party's configuration seals under (sealer.wrap_key_label): set it to the NEW label first and restart", label)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, resealStagingDir)); err == nil {
		return fmt.Errorf("reseal: %s exists: a reseal did not finish; run `mpc-party reseal` again first", filepath.Join(cfg.DataDir, resealStagingDir))
	}
	use, err := WrapKeysInUse(cfg.DataDir)
	if err != nil {
		return err
	}
	if n := use[label]; n > 0 {
		return fmt.Errorf("reseal: %d generation file(s) are still sealed under %q: they would be lost; run `mpc-party reseal` first", n, label)
	}
	for l, n := range use {
		if l == "(not a PKCS#11 envelope)" {
			return fmt.Errorf("reseal: %d generation file(s) are not PKCS#11 envelopes: this data directory is not sealed by this token's keys", n)
		}
	}
	s, err := mk(cur) // a sealer on the CURRENT label: it never creates the key it is asked to destroy
	if err != nil {
		return err
	}
	return s.DestroyKey(label)
}

// ResealStatus says which keys a data directory is sealed under, sorted.
func ResealStatus(dataDir string) ([]string, error) {
	use, err := WrapKeysInUse(dataDir)
	if err != nil {
		return nil, err
	}
	var l []string
	for k, n := range use {
		l = append(l, fmt.Sprintf("%s: %d generation file(s)", k, n))
	}
	sort.Strings(l)
	return l, nil
}
