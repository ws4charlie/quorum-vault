package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// MigrateSeal moves the data directory of a party from the PKCS#11 sealer (envelope v1, plain local state) to the attested sealer (envelope v2, sealed
// local state). It is the only way: the attested sealer never reads v1 data, and nothing migrates at start. It runs OFFLINE (the party is stopped; it
// takes the data directory lock) and is one-way.
//
// Crash safety: the whole new set is built in <data_dir>/.migrate-v2, then every file of it is opened with the new sealer and compared with what
// the old sealer opens from the old file; only then is the marker COMMITTED written, and only after the marker are the files moved over the old ones
// (rename, one by one, local.key.json last). Until the marker exists the old files are untouched and the command can simply be run again (it throws
// the staging directory away). After the marker the command only finishes the moves, and can be run again until it reports success. In between
// (after the marker, before the last move) the directory holds a mixture of both formats and no sealer starts on it: run the command again.
type MigrateOptions struct {
	// Stage is called at named points ("staged", "verified", "committed", "moved:<n>"); an error aborts the command there, as a crash would (tests).
	Stage func(name string) error
}

// MigrateReport says what was moved.
type MigrateReport struct {
	Keysets     int
	Generations int
	Keys        int
	Jobs        int
	Freezes     int
	Resumed     bool // the marker existed: only the moves were run
}

const stagingDir = ".migrate-v2"
const committedMarker = "COMMITTED"

var jobFileRe = regexp.MustCompile(`^[0-9a-f]{64}\.json$`)

// MigrateSeal: from is the party's current config (sealer pkcs11), to the same party with sealer attested; role and data_dir must be equal.
func MigrateSeal(ctx context.Context, from, to *Config, opt MigrateOptions) (MigrateReport, error) {
	var rep MigrateReport
	stage := func(n string) error {
		if opt.Stage != nil {
			return opt.Stage(n)
		}
		return nil
	}
	if from.Role != to.Role || from.DataDir != to.DataDir {
		return rep, errors.New("migrate-seal: the two configs must name the same role and data_dir")
	}
	if to.Sealer.Type != AttestedSealerType {
		return rep, fmt.Errorf("migrate-seal: the target config has sealer.type %q, want %q", to.Sealer.Type, AttestedSealerType)
	}
	if from.Sealer.Type == AttestedSealerType {
		return rep, errors.New("migrate-seal: the source config already has sealer.type attested; give the config the party runs with today (pkcs11)")
	}
	lock, err := acquireDataLock(from.DataDir)
	if err != nil {
		return rep, err
	}
	defer lock.release()
	stg := filepath.Join(from.DataDir, stagingDir)

	if _, err := os.Stat(filepath.Join(stg, committedMarker)); err == nil {
		rep.Resumed = true
		return rep, finishMoves(stg, from.DataDir, stage)
	}

	oldSealer, err := NewSealerForRole(from.Role, from.Sealer)
	if err != nil {
		return rep, fmt.Errorf("migrate-seal: old sealer: %w", err)
	}
	newSealerAny, err := NewSealerForRole(to.Role, to.Sealer)
	if err != nil {
		return rep, fmt.Errorf("migrate-seal: new sealer: %w", err)
	}
	newSealer := newSealerAny.(*AttestedSealer)
	defer newSealer.Close()

	if err := os.RemoveAll(stg); err != nil {
		return rep, err
	}
	ns, err := NewFileStore(stg, to.Role, newSealer)
	if err != nil {
		return rep, err
	}
	if err := ns.PrepareSealer(ctx); err != nil {
		return rep, fmt.Errorf("migrate-seal: the broker did not release a key for the new data: %w", err)
	}
	role, dir := from.Role, from.DataDir
	sums := map[string][32]byte{} // staged generation file -> digest of the plaintext share, for the verification

	// keysets
	ents, err := os.ReadDir(filepath.Join(dir, "keysets"))
	if err != nil {
		return rep, err
	}
	for _, e := range ents {
		if !e.IsDir() || !validID(e.Name()) {
			continue
		}
		id := e.Name()
		kdir := filepath.Join(dir, "keysets", id)
		if err := os.MkdirAll(filepath.Join(stg, "keysets", id), 0o700); err != nil {
			return rep, err
		}
		files, err := os.ReadDir(kdir)
		if err != nil {
			return rep, err
		}
		for _, f := range files {
			m := genFileRe.FindStringSubmatch(f.Name())
			if m == nil {
				continue
			}
			gen, _ := strconv.ParseUint(m[1], 10, 64)
			raw, err := os.ReadFile(filepath.Join(kdir, f.Name()))
			if err != nil {
				return rep, err
			}
			var kf keysetFile
			if err := json.Unmarshal(raw, &kf); err != nil || kf.Role != role || kf.Gen != gen {
				return rep, fmt.Errorf("migrate-seal: keyset %s generation %d: bad file", id, gen)
			}
			var aad []byte
			switch kf.V {
			case 2:
				aad = aadKeyset(role, id, gen, kf.Alg)
			case 3:
				aad = aadTKeyset(role, id, gen)
			default:
				return rep, fmt.Errorf("migrate-seal: keyset %s generation %d: unknown file version %d", id, gen, kf.V)
			}
			plain, err := oldSealer.Open(aad, kf.Sealed)
			if err != nil {
				return rep, fmt.Errorf("migrate-seal: keyset %s generation %d does not open with the old sealer (is this config the one the party runs with?): %w", id, gen, err)
			}
			nsealed, err := ns.seal(ctx, id, gen, aad, plain)
			if err != nil {
				wipeBytes(plain)
				return rep, fmt.Errorf("migrate-seal: keyset %s generation %d: %w", id, gen, err)
			}
			sums[filepath.Join(id, f.Name())] = sha256.Sum256(plain)
			wipeBytes(plain)
			kf.Sealed = nsealed
			out, _ := json.Marshal(kf)
			if err := writeAtomic(filepath.Join(stg, "keysets", id, f.Name()), out); err != nil {
				return rep, err
			}
			rep.Generations++
		}
		// state.json (plain JSON in v1)
		sraw, err := os.ReadFile(filepath.Join(kdir, "state.json"))
		if err != nil {
			return rep, fmt.Errorf("migrate-seal: keyset %s: %w", id, err)
		}
		var st KeysetState
		if json.Unmarshal(sraw, &st) != nil {
			return rep, fmt.Errorf("migrate-seal: keyset %s: bad state file", id)
		}
		if err := ns.writeState(id, st); err != nil {
			return rep, err
		}
		rep.Keysets++
	}
	// plain local records: key metadata, jobs, freeze
	for _, d := range []struct {
		dir, kind string
		count     *int
		name      func(file string) (string, bool)
	}{
		{"keys", "key", &rep.Keys, func(f string) (string, bool) { n := strings.TrimSuffix(f, ".json"); return n, strings.HasSuffix(f, ".json") && validID(n) }},
		{"jobs", "job", &rep.Jobs, func(f string) (string, bool) { return strings.TrimSuffix(f, ".json"), jobFileRe.MatchString(f) }},
		{"freeze", "freeze", &rep.Freezes, func(f string) (string, bool) { n := strings.TrimSuffix(f, ".json"); return n, strings.HasSuffix(f, ".json") && validID(n) }},
	} {
		files, err := os.ReadDir(filepath.Join(dir, d.dir))
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return rep, err
		}
		for _, f := range files {
			name, ok := d.name(f.Name())
			if !ok {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, d.dir, f.Name()))
			if err != nil {
				return rep, err
			}
			sealed, err := ns.sealLocal(ctx, d.kind, name, raw)
			if err != nil {
				return rep, err
			}
			if err := os.MkdirAll(filepath.Join(stg, d.dir), 0o700); err != nil {
				return rep, err
			}
			if err := writeAtomic(filepath.Join(stg, d.dir, f.Name()), sealed); err != nil {
				return rep, err
			}
			*d.count++
		}
	}
	if err := stage("staged"); err != nil {
		return rep, err
	}

	// verify the new set: every share opens with the new sealer and equals what the old one opened; local records open.
	for rel, want := range sums {
		parts := strings.SplitN(rel, string(filepath.Separator), 2)
		id, file := parts[0], parts[1]
		gen, _ := strconv.ParseUint(genFileRe.FindStringSubmatch(file)[1], 10, 64)
		raw, err := os.ReadFile(filepath.Join(stg, "keysets", id, file))
		if err != nil {
			return rep, err
		}
		var kf keysetFile
		if err := json.Unmarshal(raw, &kf); err != nil {
			return rep, err
		}
		aad := aadKeyset(role, id, gen, kf.Alg)
		if kf.V == 3 {
			aad = aadTKeyset(role, id, gen)
		}
		plain, err := ns.open(ctx, id, gen, aad, kf.Sealed)
		if err != nil {
			return rep, fmt.Errorf("migrate-seal: verification: keyset %s generation %d does not open with the new sealer: %w", id, gen, err)
		}
		got := sha256.Sum256(plain)
		wipeBytes(plain)
		if !bytes.Equal(got[:], want[:]) {
			return rep, fmt.Errorf("migrate-seal: verification: keyset %s generation %d differs after sealing", id, gen)
		}
		if _, err := ns.readState(id); err != nil {
			return rep, fmt.Errorf("migrate-seal: verification: keyset %s: %w", id, err)
		}
	}
	if err := verifyLocal(ctx, ns, stg, rep); err != nil {
		return rep, err
	}
	if err := stage("verified"); err != nil {
		return rep, err
	}
	if err := writeAtomic(filepath.Join(stg, committedMarker), []byte("verified\n")); err != nil {
		return rep, err
	}
	if err := stage("committed"); err != nil {
		return rep, err
	}
	return rep, finishMoves(stg, dir, stage)
}

func verifyLocal(ctx context.Context, ns *FileStore, stg string, rep MigrateReport) error {
	for _, d := range []struct{ dir, kind string }{{"keys", "key"}, {"jobs", "job"}, {"freeze", "freeze"}} {
		files, err := os.ReadDir(filepath.Join(stg, d.dir))
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(stg, d.dir, f.Name()))
			if err != nil {
				return err
			}
			if _, err := ns.openLocal(ctx, d.kind, strings.TrimSuffix(f.Name(), ".json"), raw); err != nil {
				return fmt.Errorf("migrate-seal: verification: %s/%s: %w", d.dir, f.Name(), err)
			}
		}
	}
	return nil
}

// finishMoves renames every staged file over the data directory (local.key.json last) and removes the staging directory. Safe to repeat.
func finishMoves(stg, dir string, stage func(string) error) error {
	var rels []string
	err := filepath.WalkDir(stg, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(stg, p)
		if rel != committedMarker && !strings.HasPrefix(filepath.Base(rel), ".tmp-") {
			rels = append(rels, rel)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.SliceStable(rels, func(i, j int) bool { return rank(rels[i]) < rank(rels[j]) })
	for i, rel := range rels {
		dst := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		if err := os.Rename(filepath.Join(stg, rel), dst); err != nil {
			return err
		}
		if d, err := os.Open(filepath.Dir(dst)); err == nil {
			d.Sync()
			d.Close()
		}
		if err := stage(fmt.Sprintf("moved:%d", i+1)); err != nil {
			return err
		}
	}
	return os.RemoveAll(stg)
}

// rank orders the moves: shares first, then the other records, the state files, and local.key.json last.
func rank(rel string) int {
	switch {
	case rel == localKeyFile:
		return 4
	case filepath.Base(rel) == "state.json":
		return 3
	case genFileRe.MatchString(filepath.Base(rel)):
		return 0
	}
	return 1
}
