package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/backup"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

const backupUsage = `usage: mpc-party backup <command> [flags]

  gen-recovery-key -private FILE -public FILE
        OFFLINE machine only. Creates the recovery key pair. The private file (mode 0400) belongs to the cold ceremony and
        never goes to a party host; the public file is what 'export' and 'verify' need.
  export  -config CFG -keyset ID -recovery-public FILE -out FILE
        On the party's host: unseals the current generation through the party's HSM, writes the backup file, then verifies it
        automatically and records the verified generation and the recovery key it is under (shown by Health). Refuses a recovery key
        the party's registry has RETIRED, or another one than the registry's current key (qv-party-admin recovery-key).
  verify  -file FILE -recovery-public FILE
        Public data only. Checks the backup without any secret.
  restore -config CFG -recovery-private FILE -file FILE (-records FILE | -no-records) [-registry FILE]
        OFFLINE. With -registry (written by qv-party-admin recovery-key registry) a backup under a retired or not-current recovery key is
        refused; without it the tool says it cannot tell. -records (qv-party-admin records export) brings back the admin set and registry the other
        parties hold; -no-records says the deployment never changed them. Decrypts the backup with the recovery private key and writes a keyset sealed for the TARGET party's HSM
        (the config names its token and an empty data directory). On start the party reconciles with its peer and proves the
        keyset with a self-test before it serves.
`

func backupMain(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, backupUsage)
		os.Exit(2)
	}
	var err error
	switch args[0] {
	case "gen-recovery-key":
		err = cmdGenKey(args[1:])
	case "export":
		err = cmdExport(args[1:])
	case "verify":
		err = cmdVerify(args[1:])
	case "restore":
		err = cmdRestore(args[1:])
	default:
		fmt.Fprint(os.Stderr, backupUsage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("%s: %w (refusing to overwrite)", path, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

func cmdGenKey(args []string) error {
	fs := flag.NewFlagSet("gen-recovery-key", flag.ContinueOnError)
	priv := fs.String("private", "", "path for the recovery PRIVATE key (mode 0400)")
	pub := fs.String("public", "", "path for the recovery public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *priv == "" || *pub == "" {
		return fmt.Errorf("-private and -public are required")
	}
	p, q, err := backup.GenRecoveryKey()
	if err != nil {
		return err
	}
	if err := writeNew(*priv, p, 0o400); err != nil {
		return err
	}
	if err := writeNew(*pub, q, 0o644); err != nil {
		return err
	}
	fmt.Printf("recovery key written. PRIVATE: %s (keep OFFLINE under the cold ceremony); public: %s\n", *priv, *pub)
	return nil
}

func openStore(cfgPath string) (*server.Config, *server.FileStore, error) {
	// The simulated attester measures the binary and the config file the party runs with: this command is run with that same file.
	server.RunningConfigPath = cfgPath
	cfg, err := server.LoadConfig(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	sealer, err := server.NewSealerForRole(cfg.Role, cfg.Sealer)
	if err != nil {
		return nil, nil, err
	}
	st, err := server.NewFileStore(cfg.DataDir, cfg.Role, sealer)
	if err != nil {
		return nil, nil, err
	}
	// the attested sealer first asks the broker for the data keys (nothing for the other sealers)
	if err := st.PrepareSealer(context.Background()); err != nil {
		return nil, nil, fmt.Errorf("the sealer cannot get its keys: %w", err)
	}
	return cfg, st, nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "this party's config")
	id := fs.String("keyset", "", "keyset id")
	pubPath := fs.String("recovery-public", "", "recovery public key file")
	out := fs.String("out", "", "backup file to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *id == "" || *pubPath == "" || *out == "" {
		return fmt.Errorf("-config, -keyset, -recovery-public and -out are required")
	}
	cfg, st, err := openStore(*cfgPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	state, err := st.State(ctx, *id)
	if err != nil || state.Current == 0 {
		return fmt.Errorf("keyset %q has no current generation on this party", *id)
	}
	pub, err := os.ReadFile(*pubPath)
	if err != nil {
		return err
	}
	// The party's registry of recovery keys (changed only by a quorum-signed admin request) decides which key a backup may be made under. An
	// unreadable registry stops the export: a damaged record must not become permission.
	fpr, err := admin.RecoveryFingerprint(pub)
	if err != nil {
		return fmt.Errorf("%s: %w", *pubPath, err)
	}
	reg, err := server.ReadRecoveryRegistry(st)
	if err != nil {
		return fmt.Errorf("the recovery-key registry of this party cannot be read, so no backup is made: %w", err)
	}
	if err := reg.Allows(fpr); err != nil {
		return fmt.Errorf("refusing to export: %w", err)
	}
	var f *backup.File
	if state.Scheme == 1 || state.Scheme == 2 { // a 2-of-3 share (ECDSA or Ed25519): this party's own scalar
		tk, err := st.GetTKey(ctx, *id, state.Current)
		if err != nil {
			return err
		}
		defer tk.Wipe()
		f, err = backup.ExportT(tk, *id, state.Current, cfg.Role, pub)
		if err != nil {
			return err
		}
	} else {
		ks, err := st.GetKeyset(ctx, *id, state.Current)
		if err != nil {
			return err
		}
		defer ks.Wipe()
		f, err = backup.Export(ks, *id, state.Current, cfg.Role, pub)
		if err != nil {
			return err
		}
	}
	// Verify right away, from the bytes that will be written: a backup that was never verified is not a backup.
	raw := f.Marshal()
	parsed, err := backup.Parse(raw)
	if err != nil {
		return err
	}
	if err := backup.Verify(parsed, pub); err != nil {
		return fmt.Errorf("the backup just written does not verify: %w", err)
	}
	if err := writeNew(*out, raw, 0o600); err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if err := server.RecordBackup(cfg.DataDir, server.BackupState{KeysetID: *id, Generation: state.Current, VerifiedAt: f.CreatedAt, FileSHA256: hex.EncodeToString(sum[:]), RecoveryKeyFpr: fpr}); err != nil {
		return err
	}
	fmt.Printf("backup of keyset %s generation %d (party %s) written to %s and VERIFIED (public data only), under recovery key %s\n", *id, state.Current, cfg.Role, *out, fpr)
	fmt.Println("store it away from the other party's backup; both backups plus the recovery key equal the whole signing key")
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	file := fs.String("file", "", "backup file")
	pubPath := fs.String("recovery-public", "", "recovery public key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" || *pubPath == "" {
		return fmt.Errorf("-file and -recovery-public are required")
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	pub, err := os.ReadFile(*pubPath)
	if err != nil {
		return err
	}
	f, err := backup.Parse(raw)
	if err != nil {
		return err
	}
	if err := backup.Verify(f, pub); err != nil {
		return err
	}
	fmt.Printf("OK: backup of keyset %s generation %d party %s (%s), root public key %s, created %s, recovery key %s\n", f.KeysetID, f.Generation, f.Role, f.Alg, f.RootPublicKey, f.CreatedAt.Format("2006-01-02T15:04:05Z"), f.RecoveryKeyFpr)
	return nil
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "the TARGET party's config (its own token and an EMPTY data directory)")
	privPath := fs.String("recovery-private", "", "recovery PRIVATE key file")
	file := fs.String("file", "", "backup file")
	recPath := fs.String("records", "", "the admin set and recovery-key registry the other parties hold (qv-party-admin records export): written into the restored directory")
	noRecords := fs.Bool("no-records", false, "restore without them: only when the deployment never changed its admin set or its recovery-key registry (the party then starts on the configuration's bootstrap admins and no registry)")
	regPath := fs.String("registry", "", "the recovery-key registry (qv-party-admin recovery-key registry): refuse a backup under a retired or not-current recovery key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *privPath == "" || *file == "" {
		return fmt.Errorf("-config, -recovery-private and -file are required")
	}
	if (*recPath == "") == !*noRecords {
		return fmt.Errorf("give exactly one of -records FILE (from qv-party-admin records export: the restored party gets the admin set and registry the others hold) and -no-records (the deployment never changed them)")
	}
	cfg, st, err := openStore(*cfgPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	f, err := backup.Parse(raw)
	if err != nil {
		return err
	}
	if f.Role != cfg.Role {
		return fmt.Errorf("this backup is for party %s but the config is for party %s: a share restored into the wrong slot is refused", f.Role, cfg.Role)
	}
	if *regPath != "" || *recPath == "" {
		if err := checkRestoreRegistry(*regPath, f); err != nil {
			return err
		}
	}
	if *recPath != "" { // the records first: they are harmless without a share, and a share without them is the state this guards against
		rawRec, err := os.ReadFile(*recPath)
		if err != nil {
			return err
		}
		rec, err := server.ParseRecordsFile(rawRec)
		if err != nil {
			return err
		}
		if *regPath == "" { // the registry inside the records file decides what this backup may be under
			if err := rec.Registry.Allows(f.RecoveryKeyFpr); rec.Registry.Version > 0 && err != nil {
				return fmt.Errorf("refusing to restore: this backup is under recovery key %s: %w", f.RecoveryKeyFpr, err)
			}
		}
		if err := server.WriteRestoredRecords(context.Background(), st, rec); err != nil {
			return err
		}
		fmt.Printf("restored the admin set (version %d) and the recovery-key registry (version %d) from %s\n", rec.AdminSet.Version, rec.Registry.Version, *recPath)
	} else {
		fmt.Fprintln(os.Stderr, "WARNING: -no-records: the party starts on the configuration's bootstrap admins with no recovery-key registry; if either was ever changed it will refuse the current admins and accept a backup under a retired key")
	}
	ctx := context.Background()
	priv, err := os.ReadFile(*privPath)
	if err != nil {
		return err
	}
	if f.IsThreshold() {
		tk, err := backup.RestoreT(f, priv)
		if err != nil {
			return err
		}
		defer tk.Wipe()
		if state, err := st.State(ctx, f.KeysetID); err == nil {
			return fmt.Errorf("the target data directory %s already has keyset %q (generation %d): restore into an empty directory", filepath.Clean(cfg.DataDir), f.KeysetID, state.Current)
		}
		if err := st.PutTCandidate(ctx, f.KeysetID, f.Generation, tk); err != nil {
			return err
		}
		if err := st.Promote(ctx, f.KeysetID, f.Generation); err != nil {
			return err
		}
		fmt.Printf("restored 2-of-3 keyset %s generation %d for party %s into %s, sealed under token %q\n", f.KeysetID, f.Generation, cfg.Role, cfg.DataDir, cfg.Sealer.Token)
		fmt.Println("start the party, then have the operator REFRESH the keyset from party A: the other two parties reconcile with the restored share, and the refresh moves all three to a new generation (existing backups become stale)")
		return nil
	}
	ks, err := backup.Restore(f, priv)
	if err != nil {
		return err
	}
	defer ks.Wipe()
	if state, err := st.State(ctx, f.KeysetID); err == nil {
		return fmt.Errorf("the target data directory %s already has keyset %q (generation %d): restore into an empty directory", filepath.Clean(cfg.DataDir), f.KeysetID, state.Current)
	}
	if err := st.PutCandidate(ctx, f.KeysetID, f.Generation, ks); err != nil {
		return err
	}
	if err := st.Promote(ctx, f.KeysetID, f.Generation); err != nil {
		return err
	}
	fmt.Printf("restored keyset %s generation %d for party %s into %s, sealed under token %q\n", f.KeysetID, f.Generation, cfg.Role, cfg.DataDir, cfg.Sealer.Token)
	fmt.Println("start the party: it reconciles with its peer and proves the keyset with a self-test before serving; a backup older than the peer's generation is refused")
	return nil
}

// checkRestoreRegistry refuses to restore a backup under a recovery key that was retired (or is not the current one). The decision is the registry's,
// which the parties hold and qv-party-admin writes out; the offline machine has no data directory to read it from. Without a registry the tool cannot
// tell, says so, and relies on the party: a backup of a generation the keyset has left is refused when the party reconciles with its peers (it never
// signs with it), and nothing can make a backup of an old generation pair with the refreshed peers again.
func checkRestoreRegistry(path string, f *backup.File) error {
	if path == "" {
		fmt.Fprintf(os.Stderr, "WARNING: no -registry given: this tool cannot tell whether recovery key %s was retired. the party itself refuses a backup of an older generation when it starts (it never signs with it), but that does not protect against anyone who holds the old key and old backups; give -registry to refuse a retired key here\n", fprOrUnrecorded(f.RecoveryKeyFpr))
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var d struct {
		Version uint64   `json:"version"`
		Current string   `json:"current"`
		Retired []string `json:"retired"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return fmt.Errorf("registry %s: %w", path, err)
	}
	reg := server.RecoveryRegistry{Version: d.Version, Current: d.Current, Retired: d.Retired}
	if f.RecoveryKeyFpr == "" && (reg.Current != "" || len(reg.Retired) > 0) {
		return fmt.Errorf("this backup records no recovery key fingerprint and the registry (version %d) names one: it predates the registry; refusing", reg.Version)
	}
	if err := reg.Allows(f.RecoveryKeyFpr); err != nil {
		return fmt.Errorf("refusing to restore: this backup is under recovery key %s: %w", f.RecoveryKeyFpr, err)
	}
	return nil
}

func fprOrUnrecorded(f string) string {
	if f == "" {
		return "(this backup records none)"
	}
	return f
}
