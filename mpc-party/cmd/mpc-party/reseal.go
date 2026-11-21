package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
)

const resealUsage = `usage: mpc-party reseal -config CFG -new-label LABEL
       mpc-party reseal -config CFG -destroy-label OLD -confirm-restarted
       mpc-party reseal -config CFG -status

  Replace the wrap key that seals this party's shares, inside the same PKCS#11 token (sealer.type pkcs11, softhsm or cloudhsm profile).

  -new-label LABEL   OFFLINE (stop the party first; it takes the data directory lock). Makes the key LABEL in the token if it is not there, opens every
                     share with the key its envelope names, seals it again under LABEL, checks each one by opening it, and only then replaces the files.
                     Run it again after a crash. No keyset changes, no public key changes. Then set "wrap_key_label": "LABEL" in the sealer section of
                     the configuration and restart the party.
  -destroy-label OLD After the party was restarted with the new wrap_key_label and every keyset is resolved: removes the key OLD from the token. It refuses while
                     the configuration still seals under OLD, while any share is sealed under OLD, and while a reseal is unfinished.
                     -confirm-restarted says you checked that restart.
  -status            Prints which keys the shares are sealed under.
`

func resealMain(args []string) {
	fs := flag.NewFlagSet("reseal", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "the party's configuration (the one it runs with now)")
	newLabel := fs.String("new-label", "", "label of the new wrap key")
	destroy := fs.String("destroy-label", "", "label of the old wrap key to remove")
	confirmed := fs.Bool("confirm-restarted", false, "with -destroy-label: the party was restarted with the new wrap_key_label and every keyset is resolved")
	status := fs.Bool("status", false, "print the keys the shares are sealed under")
	if err := fs.Parse(args); err != nil || *cfgPath == "" || (*newLabel == "") == (*destroy == "") && !*status {
		fmt.Fprint(os.Stderr, resealUsage)
		os.Exit(2)
	}
	cfg, err := server.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	switch {
	case *status:
		l, err := server.ResealStatus(cfg.DataDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		cur := cfg.Sealer.WrapKeyLabel
		if cur == "" {
			cur = "qv-share-wrap (default)"
		}
		fmt.Printf("the configuration seals new shares under: %s\nshares are sealed under:\n", cur)
		for _, s := range l {
			fmt.Println(" ", s)
		}
	case *newLabel != "":
		rep, err := server.ResealWrapKey(ctx, cfg, *newLabel, server.ResealOptions{})
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		if rep.Resumed {
			fmt.Println("finished a reseal that had been verified earlier")
		} else {
			fmt.Printf("resealed: %d generation files in the data directory, %d moved to wrap key %q (before: %v); every one was opened again with the new key before it replaced the old file\n", rep.Generations, rep.Moved, *newLabel, rep.Before)
		}
		fmt.Printf("next: set \"wrap_key_label\": %q in the sealer section of %s, restart the party, wait until every keyset is resolved, then: mpc-party reseal -config %s -destroy-label <old label> -confirm-restarted\n", *newLabel, *cfgPath, *cfgPath)
	default:
		if !*confirmed {
			fmt.Fprintln(os.Stderr, "error: -confirm-restarted is required: the old key is destroyed for good, so confirm the party runs with the new wrap_key_label and every keyset is resolved")
			os.Exit(2)
		}
		if err := server.DestroyWrapKey(ctx, cfg, *destroy); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		fmt.Printf("wrap key %q removed from the token\n", *destroy)
	}
}
