// qv-load is the load generator of QuorumVault.
//
//	qv-load run    -scenario FILE -target FILE -out DIR [-run-id ID] [-rate-scale X] [-metrics-listen ADDR] [-meta K=V ...]
//	qv-load report -in DIR [-compare DIR ...]
//
// run drives the API of the target with the scenario, checks the books afterwards, and writes DIR/result.json and DIR/ops.jsonl and the static report
// DIR/report.html. The exit code is 1 if a correctness check failed (a run that is fast and wrong has failed) and 0 otherwise; objectives on time do not
// change it (they are the result, not a gate). report makes the page again from a result file.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ws4charlie/quorum-vault/loadtest/gen"
	"github.com/ws4charlie/quorum-vault/loadtest/report"
)

type kv map[string]string

func (k kv) String() string { return fmt.Sprint(map[string]string(k)) }
func (k kv) Set(s string) error {
	a, b, ok := strings.Cut(s, "=")
	if !ok {
		return fmt.Errorf("want K=V")
	}
	k[a] = b
	return nil
}

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: qv-load run|report ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(run(os.Args[2:]))
	case "report":
		os.Exit(makeReport(os.Args[2:]))
	case "addr": // addr -key-file FILE: the address of a hex secp256k1 key (the kind runner funds it on the local chain)
		os.Exit(addr(os.Args[2:]))
	default:
		fmt.Fprintln(os.Stderr, "usage: qv-load run|report ...")
		os.Exit(2)
	}
}

func run(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	scen := fs.String("scenario", "", "scenario file (JSON)")
	target := fs.String("target", "", "target file (JSON): where the system is and who the generator is")
	out := fs.String("out", "", "directory for the result files")
	runID := fs.String("run-id", "", "run identifier (default: random); customers and idempotency keys carry it")
	scale := fs.Float64("rate-scale", 1, "multiplies every stream's rate")
	seed := fs.Int64("seed", 0, "override the scenario's seed")
	listen := fs.String("metrics-listen", "", "serve the generator's Prometheus metrics here (for the live dashboard)")
	meta := kv{}
	fs.Var(meta, "meta", "K=V recorded in the result (machine, versions, the shape of the stack); repeatable")
	_ = fs.Parse(args)
	if *scen == "" || *target == "" || *out == "" {
		fs.Usage()
		return 2
	}
	if err := gen.ValidateRateScale(*scale); err != nil {
		log.Print(err)
		return 2
	}
	s, err := gen.LoadScenario(*scen)
	if err != nil {
		log.Print(err)
		return 2
	}
	t, err := gen.LoadTarget(*target)
	if err != nil {
		log.Print(err)
		return 2
	}
	if *seed != 0 {
		s.Seed = *seed
	}
	for i := range s.Streams {
		s.Streams[i].Rate *= *scale
	}
	if *runID == "" {
		*runID = "r" + uuid.NewString()[:8]
	}
	meta["rate_scale"] = fmt.Sprint(*scale)
	r, err := gen.NewRunner(s, t, *runID, meta)
	if err != nil {
		log.Print(err)
		return 2
	}
	r.OutDir = *out
	if *listen != "" {
		addr, err := r.Obs.Serve(*listen)
		if err != nil {
			log.Print(err)
			return 2
		}
		log.Printf("metrics on http://%s/metrics", addr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	log.Printf("run %s: scenario %s (%s loop, seed %d), arrivals for %s", *runID, s.Name, s.Mode, s.Seed, s.ArrivalDuration())
	res, err := r.Run(ctx)
	if err != nil {
		log.Print(err)
		return 2
	}
	if err := res.Write(*out); err != nil {
		log.Print(err)
		return 2
	}
	if err := report.Write(res, *out); err != nil {
		log.Print(err)
	}
	for k, o := range res.Total {
		q := o.Latency["total"]
		log.Printf("%-14s offered %d ok %d errors %v  total p50 %.0f ms p95 %.0f ms", k, o.Offered, o.OK, o.Errors, q.P50, q.P95)
	}
	if res.FirstLimit != "" {
		log.Printf("first objective broken: %s", res.FirstLimit)
	}
	log.Printf("result: %s (pass=%v)", filepath.Join(*out, "result.json"), res.Pass)
	if !res.Pass {
		return 1
	}
	return 0
}

func makeReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	in := fs.String("in", "", "run directory (result.json inside)")
	_ = fs.Parse(args)
	if *in == "" {
		fs.Usage()
		return 2
	}
	b, err := os.ReadFile(filepath.Join(*in, "result.json"))
	if err != nil {
		log.Print(err)
		return 2
	}
	var res gen.Result
	if err := json.Unmarshal(b, &res); err != nil {
		log.Print(err)
		return 2
	}
	if err := report.Write(&res, *in); err != nil {
		log.Print(err)
		return 2
	}
	log.Printf("wrote %s", filepath.Join(*in, "report.html"))
	return 0
}

var _ = time.Second

func addr(args []string) int {
	fs := flag.NewFlagSet("addr", flag.ExitOnError)
	kf := fs.String("key-file", "", "file with the hex key")
	_ = fs.Parse(args)
	a, err := gen.AddressOfKeyFile(*kf)
	if err != nil {
		log.Print(err)
		return 2
	}
	fmt.Println(a)
	return 0
}
