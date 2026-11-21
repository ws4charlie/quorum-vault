package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/kmsrelease"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/nitroprobe"
)

// nitroProbeMain is `mpc-party nitro-probe -config probe.json`: the first-hardware check (internal/nitroprobe). It runs as the entry point of a probe EIF built by
// deploy/images/eif-build.sh --probe, inside an enclave, and sends its report to the parent over vsock. It touches no party state.
func nitroProbeMain(args []string) {
	fs := flag.NewFlagSet("nitro-probe", flag.ExitOnError)
	cfgPath := fs.String("config", "", "probe.json")
	_ = fs.Parse(args)
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "nitro-probe: "+format+"\n", a...)
		os.Exit(1)
	}
	var cfg nitroprobe.Config
	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		fail("%v", err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg.ReportVsockPort <= 2 {
		fail("probe.json: report_vsock_port above 2 is required (%v)", err)
	}
	nsm, err := attest.OpenNSM()
	if err != nil {
		fail("%v", err)
	}
	ver, err := attest.NewProductionNitroVerifier()
	if err != nil {
		fail("%v", err)
	}
	d := nitroprobe.Deps{Attester: nsm, Verifier: ver}
	if k := cfg.KMS; k != nil {
		cl, err := kmsrelease.New(kmsrelease.Config{KeyID: k.KeyID, Region: k.Region,
			Dial:  kmsrelease.VsockDialer(kmsrelease.ParentCID, k.VsockPort),
			Creds: &kmsrelease.IMDSCreds{Dial: kmsrelease.VsockDialer(kmsrelease.ParentCID, k.CredsVsockPort)}})
		if err != nil {
			fail("%v", err)
		}
		d.KMS = cl
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rep := nitroprobe.Run(ctx, cfg, d)
	fmt.Print(rep.Summary())
	conn, err := kmsrelease.VsockDialer(kmsrelease.ParentCID, cfg.ReportVsockPort)(ctx, "", "")
	if err != nil {
		fail("cannot reach the parent on vsock port %d: %v", cfg.ReportVsockPort, err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(rep); err != nil {
		fail("sending the report: %v", err)
	}
}
