package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// Local state under the attested sealer. What an attacker with the data directory could edit, delete or roll back is sealed as well as the shares:
// the keyset state (generations, candidate, decision), the freeze records, the idempotency records of Sign and the key metadata. They are sealed
// under the party's LOCAL data key (scope "~local", generation 1), with associated data that names the party, the kind of record and its name, so a
// record cannot be moved to another place or another party. Sealing makes a record unforgeable and unreadable; it does NOT stop deletion or a
// rollback to an older sealed copy: that is the rollback analysis in docs/runbooks/tee-broker.md.
//
//	file                           sealed   why
//	keysets/<id>/g<N>.json         yes      the share; its own key per generation
//	keysets/<id>/state.json        yes      generation pointers and the commit decision: a forged pointer could make a party sign with a stale share
//	freeze/<id>.json               yes      an unreadable or forged record is treated as frozen (fail closed)
//	jobs/<hash>.json               yes      a forged record would be returned as the signature of a job
//	keys/<id>.json                 yes      the public key a sign is checked against
//	local.key.json                 no       only the wrapped local key: useless without the broker's HSM and an allowlisted measurement
//	backups/<id>.json              no       a public note of the last verified backup (shown by Health); a forged one misreports and signs nothing
//	.lock                          no       the data directory lock

const localKeyFile = "local.key.json"

// ErrLocalUnsealed: a local state file is plain JSON where the attested sealer expects a sealed one (data of a party that ran with another sealer).
var ErrLocalUnsealed = errors.New("sealer attested: this local state file is not sealed (it was written by a party with another sealer); run `mpc-party migrate-seal` (docs/runbooks/tee-broker.md)")

func aadLocal(role, kind, name string) []byte {
	return []byte(fmt.Sprintf("qv-mpc-party|local|v1|%s|%s|%s", role, kind, name))
}

func (s *FileStore) sealLocal(ctx context.Context, kind, name string, raw []byte) ([]byte, error) {
	if s.scoped == nil {
		return raw, nil
	}
	return s.scoped.SealScoped(ctx, LocalScope, aadLocal(s.role, kind, name), raw)
}

// ErrLocalSealed: a local state file is an attested-sealer envelope where a sealer without sealed local state (pkcs11) expects plain JSON. Reading it as
// plain JSON would give an empty record, so it is refused: the data directory has been migrated and only the attested sealer reads it.
var ErrLocalSealed = errors.New("this local state file is sealed by the attested sealer (the data directory was migrated); a party with another sealer cannot read it")

func isEnvelope(data []byte) bool {
	var probe struct {
		KID string `json:"kid"`
	}
	return json.Unmarshal(data, &probe) == nil && probe.KID != ""
}

func (s *FileStore) openLocal(ctx context.Context, kind, name string, data []byte) ([]byte, error) {
	if s.scoped == nil {
		if isEnvelope(data) {
			return nil, ErrLocalSealed
		}
		return data, nil
	}
	if !isEnvelope(data) {
		return nil, ErrLocalUnsealed
	}
	return s.scoped.OpenScoped(ctx, LocalScope, aadLocal(s.role, kind, name), data)
}

type localKeyDoc struct {
	V       int    `json:"v"`
	KID     string `json:"kid"`
	Wrapped []byte `json:"wrapped_dek"`
}

var genFileRe = regexp.MustCompile(`^g(\d+)\.json$`)

// unlockSet reads what the sealer has to ask the broker for: the wrapped local key and the wrapped key inside every generation file.
func (s *FileStore) unlockSet() (UnlockSet, error) {
	set := UnlockSet{Keysets: map[string]map[uint64][]byte{}}
	if b, err := os.ReadFile(filepath.Join(s.dir, localKeyFile)); err == nil {
		var d localKeyDoc
		if json.Unmarshal(b, &d) != nil || d.V != envV2 || d.KID != LocalScope.kid() || len(d.Wrapped) == 0 {
			return set, fmt.Errorf("%s is not a valid local key file", localKeyFile)
		}
		set.Local = d.Wrapped
	} else if !errors.Is(err, os.ErrNotExist) {
		return set, err
	}
	ents, err := os.ReadDir(filepath.Join(s.dir, "keysets"))
	if err != nil {
		return set, err
	}
	for _, e := range ents {
		if !e.IsDir() || !validID(e.Name()) {
			continue
		}
		files, err := os.ReadDir(s.kdir(e.Name()))
		if err != nil {
			return set, err
		}
		for _, f := range files {
			m := genFileRe.FindStringSubmatch(f.Name())
			if m == nil {
				continue
			}
			gen, _ := strconv.ParseUint(m[1], 10, 64)
			raw, err := os.ReadFile(filepath.Join(s.kdir(e.Name()), f.Name()))
			if err != nil {
				return set, err
			}
			var kf keysetFile
			if err := json.Unmarshal(raw, &kf); err != nil {
				return set, fmt.Errorf("keyset %s generation %d: bad file", e.Name(), gen)
			}
			env, err := parseEnvelopeV2(kf.Sealed)
			if err != nil {
				return set, fmt.Errorf("keyset %s generation %d: %w", e.Name(), gen, err)
			}
			if env.KID != (SealScope{e.Name(), gen}).kid() {
				continue // a blob moved here from another generation or keyset: not asked for, and it will not open
			}
			if set.Keysets[e.Name()] == nil {
				set.Keysets[e.Name()] = map[uint64][]byte{}
			}
			set.Keysets[e.Name()][gen] = env.Wrapped
		}
	}
	if set.Local == nil {
		empty := len(set.Keysets) == 0
		for _, d := range []string{"keysets", "keys", "jobs", "freeze"} {
			if es, err := os.ReadDir(filepath.Join(s.dir, d)); err == nil && len(es) > 0 {
				empty = false
			}
		}
		set.Fresh = empty
	}
	return set, nil
}

// PrepareSealer is the start-up of the attested sealer: it asks the broker for the data key of every generation on disk (and makes the local key
// in a fresh data directory, writing its wrapped form to local.key.json). A store whose sealer needs nothing does nothing. It can be called again
// after a failure: only what is still missing is fetched.
func (s *FileStore) PrepareSealer(ctx context.Context) error {
	as, ok := s.sealer.(*AttestedSealer)
	if !ok {
		return nil
	}
	set, err := s.unlockSet()
	if err != nil {
		return err
	}
	newLocal, err := as.Preload(ctx, set)
	if err != nil {
		return err
	}
	if newLocal != nil {
		raw, _ := json.Marshal(localKeyDoc{V: envV2, KID: LocalScope.kid(), Wrapped: newLocal})
		if err := writeAtomic(filepath.Join(s.dir, localKeyFile), raw); err != nil {
			return fmt.Errorf("cannot write %s: %w", localKeyFile, err)
		}
	}
	return nil
}
