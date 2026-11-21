package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

const migrateUsage = `usage: mpc-party migrate-seal -from OLD.json -to NEW.json

  OFFLINE and one-way. Moves the data directory of a party from the PKCS#11 sealer to the attested sealer: every share is opened with the old
  sealer (OLD.json: the config the party runs with today) and sealed again under data keys released by the broker (NEW.json: the same party,
  same data_dir, sealer.type "attested"); the local state (generations, freeze, stored signatures, key metadata) is sealed too.
  The new set is built beside the old files and verified before it replaces them; run the command again after a crash. Stop the party first,
  and take a snapshot of the data directory before you start: after the command the PKCS#11 sealer cannot read the directory any more.
`

func migrateMain(args []string) {
	fs := flag.NewFlagSet("migrate-seal", flag.ContinueOnError)
	from := fs.String("from", "", "config the party runs with today (sealer pkcs11)")
	to := fs.String("to", "", "config of the same party with sealer attested")
	if err := fs.Parse(args); err != nil || *from == "" || *to == "" {
		fmt.Fprint(os.Stderr, migrateUsage)
		os.Exit(2)
	}
	fc, err := server.LoadConfig(*from)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	tc, err := server.LoadConfig(*to)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	server.RunningConfigPath = *to // the party will run with the NEW config: that is the image the attester measures
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	rep, err := server.MigrateSeal(ctx, fc, tc, server.MigrateOptions{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if rep.Resumed {
		fmt.Println("finished a migration that had been verified earlier")
		return
	}
	fmt.Printf("migrated: %d keysets, %d generations, %d key records, %d stored signatures, %d freeze records, %d admin records; all verified before they replaced the old files\n",
		rep.Keysets, rep.Generations, rep.Keys, rep.Jobs, rep.Freezes, rep.Records)
}
