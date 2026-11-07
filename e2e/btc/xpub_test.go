package btce2e

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/e2e/mpcstack"
	"github.com/ws4charlie/quorum-vault/internal/chain/btc"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// runXpub runs the built qv-btc-xpub command against the stack, as an operator would: through party A's caller port with the gateway's
// client certificate. It returns standard output, standard error and the error of the process.
func runXpub(t *testing.T, mpc *mpcstack.Stack, extra ...string) (string, string, error) {
	t.Helper()
	crt, key := mpc.CertGW.Write(t, mpc.Dir)
	args := append([]string{"-party", mpc.CallerA, "-cert", crt, "-key", key, "-server-pin", mpc.CertA.Pin, "-keyset", mpc.KeysetID, "-timeout", "20s"}, extra...)
	cmd := exec.Command(filepath.Join(binDir, "qv-btc-xpub"), args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

// The command prints the xpub the system runs with and, with -shards, the hot shard addresses: each is the address of the key party A
// derives at 1/i, which is what the adapter, the gateway and the cosigner pin.
func TestXpubCommandPrintsTheXpubAndTheHotShardAddresses(t *testing.T) {
	requireBTC(t)
	mpc := newMPC(t, t.TempDir())
	for _, network := range []string{"regtest", "mainnet"} {
		out, stderr, err := runXpub(t, mpc, "-network", network, "-shards", "3")
		if err != nil {
			t.Fatalf("%s: %v\n%s", network, err, stderr)
		}
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) != 4 || !strings.HasPrefix(lines[0], "account_xpub=") {
			t.Fatalf("%s: unexpected output %q", network, out)
		}
		xpub := strings.TrimPrefix(lines[0], "account_xpub=")
		if want := accountXpub(t, mpc, network); xpub != want {
			t.Fatalf("%s: the command printed %s, the system runs with %s", network, xpub, want)
		}
		params, _ := btc.Params(network)
		for i := 0; i < 3; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			d, err := mpc.Client.Derive(ctx, &pb.DeriveRequest{KeysetId: mpc.KeysetID, HardenedPath: btc.AccountPath(network), Path: []uint32{btc.BranchHot, uint32(i)}})
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			want, err := btc.P2WPKH(d.PublicKey, params)
			if err != nil {
				t.Fatal(err)
			}
			if got := lines[1+i]; got != fmt.Sprintf("hot_shard.%d=%s", i, want) {
				t.Fatalf("%s: line %d is %q, the key party A derives at 1/%d is %s", network, 1+i, got, i, want)
			}
			// The adapter derives the same address from the xpub alone.
			if a, err := btc.DeriveHotAddress(network, xpub, uint32(i)); err != nil || a != want {
				t.Fatalf("%s: hot shard %d from the xpub is %q (%v), want %s", network, i, a, err, want)
			}
		}
	}
	// Without -shards only the xpub is printed.
	out, _, err := runXpub(t, mpc, "-network", "regtest")
	if err != nil || strings.Count(out, "\n") != 1 || !strings.HasPrefix(out, "account_xpub=") {
		t.Fatalf("without -shards: %q %v", out, err)
	}
}

// A failure is one clear line on standard error, a non-zero exit and nothing on standard output.
func TestXpubCommandFailsCleanly(t *testing.T) {
	requireBTC(t)
	mpc := newMPC(t, t.TempDir())
	check := func(name string, stdout, stderr string, err error, want string) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: exit 0, stdout %q", name, stdout)
		}
		if stdout != "" {
			t.Errorf("%s: standard output %q, want nothing", name, stdout)
		}
		if !strings.Contains(stderr, want) {
			t.Errorf("%s: standard error %q does not say %q", name, stderr, want)
		}
	}
	out, stderr, err := runXpub(t, mpc, "-network", "regtest", "-keyset", "no-such-keyset")
	check("wrong keyset", out, stderr, err, "qv-btc-xpub:")
	out, stderr, err = runXpub(t, mpc, "-network", "dogecoin")
	check("unknown network", out, stderr, err, "unknown network")
	// No party A at the address: nothing listens there.
	crt, key := mpc.CertGW.Write(t, mpc.Dir)
	cmd := exec.Command(filepath.Join(binDir, "qv-btc-xpub"), "-party", mpcstack.FreeAddr(t), "-cert", crt, "-key", key, "-server-pin", mpc.CertA.Pin,
		"-keyset", mpc.KeysetID, "-network", "regtest", "-timeout", "5s")
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	check("no connection", o.String(), e.String(), err, "qv-btc-xpub:")
	// A pin that is not party A's certificate.
	out, stderr, err = runXpub(t, mpc, "-network", "regtest", "-server-pin", strings.Repeat("ab", 32))
	check("wrong pin", out, stderr, err, "qv-btc-xpub:")
}
