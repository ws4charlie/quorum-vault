package custody_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
)

// coldKit is the offline signer's side of a test: the cold key in the qv-cold token, three operators, and the offline config.
// The ceremony runs the real qv-cold binary on files, as it would on the offline machine.
type coldKit struct {
	t       *testing.T
	dir     string
	addr    common.Address
	cfgPath string
	cfg     coldsign.Config
	opKeys  map[string]string // operator -> key file
	ops     map[string]string // operator -> public key
	keyID   []byte
	pub     []byte
}

// newColdKey makes the cold key in the qv-cold token and three operators, in directory name under the system's dir. configure writes
// the offline config once the system's addresses exist.
func newColdKey(t *testing.T, s *system, name string) *coldKit {
	t.Helper()
	k := &coldKit{t: t, dir: filepath.Join(s.dir, name), opKeys: map[string]string{}}
	if err := os.MkdirAll(k.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	tok := hsmtest.Token(t, "qv-cold")
	k.keyID = make([]byte, 16)
	rand.Read(k.keyID)
	pub, err := tok.GenerateECKeyPair(s.ctx, domain.CurveSecp256k1, "qv-cold-test", k.keyID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tok.DestroyPrivateKey(s.ctx, k.keyID) })
	pk, err := crypto.UnmarshalPubkey(pub)
	if err != nil {
		t.Fatal(err)
	}
	k.addr, k.pub = crypto.PubkeyToAddress(*pk), pub
	k.ops = map[string]string{}
	for _, n := range []string{"alice", "bob", "carol"} {
		kp := filepath.Join(k.dir, n+".key")
		out, err := exec.Command(filepath.Join(binDir, "qv-cold"), "operator-key", "-key", kp).Output()
		if err != nil {
			t.Fatalf("operator-key: %v", err)
		}
		k.ops[n] = string(out[:len(out)-1])
		k.opKeys[n] = kp
	}
	return k
}

// configure writes the offline config: refills to the hot shards, and every factory call, with the hot shards as the pinned new
// destinations. Tests add pinned guardians and admins before writing it again with write().
func (k *coldKit) configure(s *system) {
	t := k.t
	var dests []string
	for _, a := range s.shardAddr {
		dests = append(dests, a.Hex())
	}
	k.cfg = coldsign.Config{
		Chain: s.chainName, ChainID: 11155111, Pool: "omnibus", Operators: k.ops, Threshold: 2, Destinations: dests,
		Assets: map[string]coldsign.AssetPolicy{
			"ETH":  {Decimals: 18, MaxAmount: eth(100).String()},
			"USDT": {Token: s.usdt.Hex(), Decimals: 6, MaxAmount: "100000000000"},
		},
		MaxFeeWei: "10000000000000000", PublicKey: hex.EncodeToString(k.pub),
		HSM:       coldsign.HSMConfig{Token: "qv-cold", PinEnv: "QV_HSM_PIN", KeyID: hex.EncodeToString(k.keyID)},
		RecordDir: filepath.Join(k.dir, "record"),
		Actions:   append([]string(nil), coldsign.AdminKinds...), Factory: s.factory.Hex(), NewDestinations: dests,
	}
	k.cfgPath = filepath.Join(k.dir, "qv-cold.json")
	k.write()
	_ = t
}

// write saves the (possibly edited) offline config.
func (k *coldKit) write() { writeJSON(k.t, k.cfgPath, k.cfg) }

func newColdKit(t *testing.T, s *system) *coldKit {
	k := newColdKey(t, s, "cold")
	k.configure(s)
	return k
}

// run executes qv-cold with the repo-local SoftHSM config and the dev PIN.
func (k *coldKit) run(args ...string) (string, error) {
	cmd := exec.Command(filepath.Join(binDir, "qv-cold"), args...)
	cmd.Env = append(os.Environ(), "QV_HSM_PIN="+hsmtest.PIN())
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (k *coldKit) file(name string, v any) string {
	k.t.Helper()
	p := filepath.Join(k.dir, name)
	writeJSON(k.t, p, v)
	return p
}

// ceremony runs inspect, two approvals and the signing for a request file and returns the signed file.
func (k *coldKit) ceremony(name string, rf coldsign.RequestFile, approvers ...string) (coldsign.Signed, string, error) {
	k.t.Helper()
	req := k.file(name+"-request.json", rf)
	if out, err := k.run("inspect", "-config", k.cfgPath, "-request", req); err != nil {
		return coldsign.Signed{}, out, err
	}
	args := []string{"sign", "-config", k.cfgPath, "-request", req, "-out", filepath.Join(k.dir, name+"-signed.json")}
	for _, a := range approvers {
		ap := filepath.Join(k.dir, name+"-approval-"+a+".json")
		if out, err := k.run("approve", "-operator", a, "-key", k.opKeys[a], "-request", req, "-out", ap); err != nil {
			return coldsign.Signed{}, out, err
		}
		args = append(args, "-approval", ap)
	}
	out, err := k.run(args...)
	if err != nil {
		return coldsign.Signed{}, out, err
	}
	b, err := os.ReadFile(filepath.Join(k.dir, name+"-signed.json"))
	if err != nil {
		return coldsign.Signed{}, out, err
	}
	var sg coldsign.Signed
	return sg, out, json.Unmarshal(b, &sg)
}

var _ = ed25519.PublicKeySize
