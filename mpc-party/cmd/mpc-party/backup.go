package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/backup"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

const backupUsage = `usage: mpc-party backup <command> [flags]

  gen-recovery-key -private FILE -public FILE
        OFFLINE machine only. Creates the recovery key pair. The private file (mode 0400) belongs to the cold ceremony and
        never goes to a party host; the public file is what 'export' and 'verify' need.
  export  -config CFG -keyset ID -recovery-public FILE -out FILE
        On the party's host: unseals the current generation through the party's HSM, writes the backup file, then verifies it
        automatically and records the verified generation (shown by Health).
  verify  -file FILE -recovery-public FILE
        Public data only. Checks the backup without any secret.
  restore -config CFG -recovery-private FILE -file FILE
        OFFLINE. Decrypts the backup with the recovery private key and writes a keyset sealed for the TARGET party's HSM
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
	cfg, err := server.LoadConfig(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	sealer, err := server.NewSealer(cfg.Sealer)
	if err != nil {
		return nil, nil, err
	}
	st, err := server.NewFileStore(cfg.DataDir, cfg.Role, sealer)
	return cfg, st, err
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
	ks, err := st.GetKeyset(ctx, *id, state.Current)
	if err != nil {
		return err
	}
	defer ks.Wipe()
	pub, err := os.ReadFile(*pubPath)
	if err != nil {
		return err
	}
	f, err := backup.Export(ks, *id, state.Current, cfg.Role, pub)
	if err != nil {
		return err
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
	if err := server.RecordBackup(cfg.DataDir, server.BackupState{KeysetID: *id, Generation: state.Current, VerifiedAt: f.CreatedAt, FileSHA256: hex.EncodeToString(sum[:])}); err != nil {
		return err
	}
	fmt.Printf("backup of keyset %s generation %d (party %s) written to %s and VERIFIED (public data only)\n", *id, state.Current, cfg.Role, *out)
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
	fmt.Printf("OK: backup of keyset %s generation %d party %s (%s), root public key %s, created %s\n", f.KeysetID, f.Generation, f.Role, f.Alg, f.RootPublicKey, f.CreatedAt.Format("2006-01-02T15:04:05Z"))
	return nil
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "the TARGET party's config (its own token and an EMPTY data directory)")
	privPath := fs.String("recovery-private", "", "recovery PRIVATE key file")
	file := fs.String("file", "", "backup file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" || *privPath == "" || *file == "" {
		return fmt.Errorf("-config, -recovery-private and -file are required")
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
	ctx := context.Background()
	if state, err := st.State(ctx, f.KeysetID); err == nil {
		return fmt.Errorf("the target data directory %s already has keyset %q (generation %d): restore into an empty directory", filepath.Clean(cfg.DataDir), f.KeysetID, state.Current)
	}
	priv, err := os.ReadFile(*privPath)
	if err != nil {
		return err
	}
	ks, err := backup.Restore(f, priv)
	if err != nil {
		return err
	}
	defer ks.Wipe()
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
