// Command mpcbench measures the 2-of-3 GG20 signer: pre-params generation,
// one keygen, and N signings for every 2-party subset and the full set. It
// prints a markdown table for docs/measurements/mpc.md.
//
//	go run ./cmd/mpcbench -n 10 [-fresh-preparams] [-data ./data/mpc-bench]
//
// Needs the party tokens from `make setup`.
package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/mpc"
	"github.com/ws4charlie/quorum-vault/internal/signer"
)

func main() {
	n := flag.Int("n", 10, "signings per party set")
	fresh := flag.Bool("fresh-preparams", false, "regenerate pre-params even if cached")
	dataDir := flag.String("data", filepath.Join("data", "mpc-bench"), "MPC data dir")
	keep := flag.Bool("keep", false, "keep the benchmark key's sealed shares")
	flag.Parse()
	log.SetFlags(0)

	pin := os.Getenv("QV_HSM_PIN")
	if pin == "" {
		pin = "user-dev-1234" // dev-only default, see .env.example
	}
	lib, err := hsm.LoadLib(hsm.DefaultLibPath())
	if err != nil {
		log.Fatal(err)
	}
	defer lib.Close()
	c, err := mpc.NewCluster(mpc.DefaultConfig(*dataDir, pin), lib)
	if err != nil {
		log.Fatalf("%v (run `make setup`?)", err)
	}
	defer c.Close()
	ctx := context.Background()

	log.Printf("pre-params (fresh=%v)...", *fresh)
	ppTook, err := c.PreParams(ctx, *fresh)
	if err != nil {
		log.Fatal(err)
	}

	ref := fmt.Sprintf("bench-%d", time.Now().Unix())
	log.Printf("keygen %s...", ref)
	pub, kst, err := c.Keygen(ctx, ref)
	if err != nil {
		log.Fatal(err)
	}
	if !*keep {
		defer os.RemoveAll(filepath.Join(*dataDir, "keys", ref))
	}

	type row struct {
		name  string
		durs  []time.Duration
		st    mpc.Stats
		count int
	}
	rows := []row{{name: "keygen (3 parties)", durs: []time.Duration{kst.Duration}, st: kst, count: 1}}
	for _, set := range [][]int{{1, 2}, {1, 3}, {2, 3}, {1, 2, 3}} {
		r := row{name: "sign " + partyList(set), count: *n}
		for i := 0; i < *n; i++ {
			d := sha256.Sum256(fmt.Appendf(nil, "mpcbench %s %v %d", ref, set, i))
			sig, st, err := c.Sign(ctx, ref, d, set)
			if err != nil {
				log.Fatalf("sign %v #%d: %v", set, i, err)
			}
			if !signer.Verify(pub, d, sig) {
				log.Fatalf("sign %v #%d: signature does not verify", set, i)
			}
			r.durs = append(r.durs, st.Duration)
			r.st = st
		}
		log.Printf("%s: done", r.name)
		rows = append(rows, r)
	}

	fmt.Printf("- Date: %s\n", time.Now().Format("2006-01-02 15:04 MST"))
	fmt.Printf("- Machine: %s, %d logical CPUs, %s/%s\n", cpuName(), runtime.NumCPU(), runtime.GOOS, runtime.GOARCH)
	fmt.Printf("- Go: %s; tss-lib: %s\n", runtime.Version(), modVersion("github.com/bnb-chain/tss-lib/v4"))
	if ppTook > 0 {
		fmt.Printf("- Pre-params (3 parties in parallel, freshly generated): %s\n", ppTook.Round(time.Millisecond))
	} else {
		fmt.Printf("- Pre-params: cached (run with -fresh-preparams to time them)\n")
	}
	fmt.Println()
	fmt.Println("| Ceremony | N | min ms | median ms | max ms | rounds | messages | bytes |")
	fmt.Println("|---|---:|---:|---:|---:|---:|---:|---:|")
	for _, r := range rows {
		slices.Sort(r.durs)
		fmt.Printf("| %s | %d | %d | %d | %d | %d | %d | %d |\n", r.name, r.count,
			r.durs[0].Milliseconds(), r.durs[len(r.durs)/2].Milliseconds(), r.durs[len(r.durs)-1].Milliseconds(),
			r.st.Rounds, r.st.Messages, r.st.Bytes)
	}
}

func partyList(set []int) string {
	s := make([]string, len(set))
	for i, id := range set {
		s[i] = fmt.Sprint(id)
	}
	return "{" + strings.Join(s, ",") + "}"
}

func cpuName() string {
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "model name") {
				if _, v, ok := strings.Cut(line, ":"); ok {
					return strings.TrimSpace(v)
				}
			}
		}
	}
	return "unknown CPU"
}

func modVersion(path string) string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, m := range bi.Deps {
			if m.Path == path {
				return m.Version
			}
		}
	}
	return "unknown"
}
