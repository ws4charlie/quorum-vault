package sole2e

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
)

// solKit is the offline side of a test: the pool's Ed25519 cold key in the qv-cold token, three operators and the offline config. The ceremony runs the
// real qv-cold binary on files.
type solKit struct {
	t       *testing.T
	dir     string
	addr    string
	pub     ed25519.PublicKey
	keyID   []byte
	tok     *hsm.Token
	cfgPath string
	cfg     coldsign.SOLConfig
	opKeys  map[string]string
	ops     map[string]string
}

// newSolKit makes the cold key (before the system starts: its address is pinned in every config).
func newSolKit(t *testing.T) *solKit {
	t.Helper()
	k := &solKit{t: t, dir: t.TempDir(), opKeys: map[string]string{}, ops: map[string]string{}}
	k.tok = hsmtest.Token(t, "qv-cold")
	k.keyID = make([]byte, 16)
	copy(k.keyID, fmt.Sprintf("%016x", time.Now().UnixNano()))
	pub, err := k.tok.GenerateEd25519KeyPair(t.Context(), "qv-cold-sol-test", k.keyID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.tok.DestroyPrivateKey(t.Context(), k.keyID) })
	k.pub, k.addr = pub, base58.Encode(pub)
	for _, n := range []string{"alice", "bob", "carol"} {
		kp := filepath.Join(k.dir, n+".key")
		out, err := exec.Command(filepath.Join(binDir, "qv-cold"), "operator-key", "-key", kp).Output()
		if err != nil {
			t.Fatalf("operator-key: %v", err)
		}
		k.ops[n], k.opKeys[n] = string(out[:len(out)-1]), kp
	}
	return k
}

// configure writes the offline config once the system's addresses exist: the hot shards are the only destinations.
func (k *solKit) configure(s *wdSys) {
	k.cfg = coldsign.SOLConfig{
		Family: "sol", Chain: s.chain, Pool: "omnibus", Operators: k.ops, Threshold: 2, Destinations: s.hotAddrs(),
		Assets: map[string]coldsign.SOLAssetPolicy{
			"SOL": {Decimals: 9, MaxAmount: fmt.Sprint(100 * oneSOL)},
			"TKN": {Mint: s.mint.addr(), Decimals: 6, MaxAmount: fmt.Sprint(100_000 * tknUnit)},
		},
		NoncePool: 3, NonceRent: sol.DefaultNonceRent, MaxComputeUnits: 200_000, MaxMicroLamports: maxMicro, MaxPriorityLamports: 100_000,
		PublicKey: hex.EncodeToString(k.pub), HSM: coldsign.HSMConfig{Token: "qv-cold", PinEnv: "QV_HSM_PIN", KeyID: hex.EncodeToString(k.keyID)},
		RecordDir: filepath.Join(k.dir, "record"),
	}
	k.cfgPath = filepath.Join(k.dir, "qv-cold.json")
	k.write()
}

func (k *solKit) write() { writeJSONFile(k.t, k.cfgPath, k.cfg) }

func (k *solKit) run(args ...string) (string, error) {
	cmd := exec.Command(filepath.Join(binDir, "qv-cold"), args...)
	cmd.Env = append(os.Environ(), "QV_HSM_PIN="+hsmtest.PIN(k.t))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (k *solKit) file(name string, v any) string {
	k.t.Helper()
	p := filepath.Join(k.dir, name)
	writeJSONFile(k.t, p, v)
	return p
}

// approve has an operator approve the request file; it returns the approval file.
func (k *solKit) approve(name, who string, rf coldsign.SOLRequestFile) (string, error) {
	req := k.file(name+"-request.json", rf)
	ap := filepath.Join(k.dir, name+"-approval-"+who+".json")
	out, err := k.run("approve", "-operator", who, "-key", k.opKeys[who], "-request", req, "-out", ap)
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, out)
	}
	return ap, nil
}

// ceremony runs inspect, the approvals and the signing of a request file, as on the offline machine, and returns the signed file.
func (k *solKit) ceremony(name string, rf coldsign.SOLRequestFile, approvers ...string) (coldsign.SOLSigned, string, error) {
	k.t.Helper()
	req := k.file(name+"-request.json", rf)
	if out, err := k.run("inspect", "-config", k.cfgPath, "-request", req); err != nil {
		return coldsign.SOLSigned{}, out, err
	}
	args := []string{"sign", "-config", k.cfgPath, "-request", req, "-out", filepath.Join(k.dir, name+"-signed.json")}
	for _, a := range approvers {
		ap, err := k.approve(name, a, rf)
		if err != nil {
			return coldsign.SOLSigned{}, err.Error(), err
		}
		args = append(args, "-approval", ap)
	}
	out, err := k.run(args...)
	if err != nil {
		return coldsign.SOLSigned{}, out, err
	}
	b, err := os.ReadFile(filepath.Join(k.dir, name+"-signed.json"))
	if err != nil {
		return coldsign.SOLSigned{}, out, err
	}
	var sg coldsign.SOLSigned
	return sg, out, json.Unmarshal(b, &sg)
}

// ---- the online side of the ceremony, over the core's API ----

func (s *wdSys) via(from, to any) {
	b, _ := json.Marshal(from)
	if err := json.Unmarshal(b, to); err != nil {
		s.t.Fatal(err)
	}
}

type refillRow struct{ ID, Asset, Status, Reason, Tx string }

func (s *wdSys) refills() []refillRow {
	s.t.Helper()
	rows, err := s.pool.Query(s.ctx, `SELECT id, asset, status, COALESCE(failure_reason,''), COALESCE(tx_hash,'') FROM refills WHERE chain=$1 AND kind='refill' ORDER BY created_at`, s.chain)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	var out []refillRow
	for rows.Next() {
		var r refillRow
		if err := rows.Scan(&r.ID, &r.Asset, &r.Status, &r.Reason, &r.Tx); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// waitRefill waits for a refill of asset in status.
func (s *wdSys) waitRefill(asset, status string, timeout time.Duration) refillRow {
	s.t.Helper()
	var got refillRow
	s.waitFor(timeout, "a "+asset+" refill to be "+status, func() bool {
		for _, r := range s.refills() {
			if r.Asset == asset && r.Status == status {
				got = r
				return true
			}
		}
		return false
	})
	return got
}

func (s *wdSys) exportRefill(id string) coldsign.SOLRequestFile {
	s.t.Helper()
	code, out := s.call("POST", "/v2/refills/"+id+"/export", nil)
	if code != 200 {
		s.t.Fatalf("export %s: %d %v", id, code, out)
	}
	var rf coldsign.SOLRequestFile
	s.via(out, &rf)
	return rf
}

func (s *wdSys) importRefill(id string, sg coldsign.SOLSigned) (int, map[string]any) {
	return s.call("POST", "/v2/refills/"+id+"/import", sg)
}

// refillCeremony exports, signs with two approvals, and imports.
func (s *wdSys) refillCeremony(k *solKit, id string) coldsign.SOLRequestFile {
	s.t.Helper()
	rf := s.exportRefill(id)
	sg, out, err := k.ceremony("rf-"+id, rf, "alice", "bob")
	if err != nil {
		s.t.Fatalf("ceremony %s: %v\n%s", id, err, out)
	}
	if code, res := s.importRefill(id, sg); code != 200 {
		s.t.Fatalf("import %s: %d %v", id, code, res)
	}
	return rf
}

// coldSetup runs the one-time setup ceremony of the pool's cold address: its nonce accounts and the token account.
func (s *wdSys) coldSetup(k *solKit) {
	s.t.Helper()
	code, out := s.call("POST", "/v2/cold-setup/export", map[string]string{"pool": "omnibus"})
	if code != 200 || out["nothing_to_do"] == true {
		s.t.Fatalf("setup export: %d %v", code, out)
	}
	var rf coldsign.SOLRequestFile
	s.via(out, &rf)
	sg, o, err := k.ceremony("setup", rf, "alice", "carol")
	if err != nil {
		s.t.Fatalf("setup ceremony: %v\n%s", err, o)
	}
	code, out = s.call("POST", "/v2/cold-setup/submit", map[string]any{"request": rf.Request, "signed": sg})
	if code != 200 {
		s.t.Fatalf("setup submit: %d %v", code, out)
	}
	if code, out := s.call("POST", "/v2/cold-setup/export", map[string]string{"pool": "omnibus"}); code != 200 || out["nothing_to_do"] != true {
		s.t.Fatalf("after the setup there is still something to do: %d %v", code, out)
	}
}

// fundCold puts SOL and tokens on the cold address (the operator's deposit from outside) and tells the books.
func (s *wdSys) fundCold(sols, tokens uint64) {
	s.t.Helper()
	if sols > 0 {
		s.c.airdrop(s.coldAdr, sols)
		if err := s.svc.FundCold(s.ctx, fmt.Sprintf("fund-sol-%d", sols), 0, "SOL", bigU(sols)); err != nil {
			s.t.Fatal(err)
		}
	}
	if tokens > 0 {
		cold := addrBytes(s.t, s.coldAdr)
		ata := s.c.ata(cold, s.mint.pub)
		s.c.waitStatus(s.c.run(s.funder, nil, s.c.mintTo(s.mint.pub, ata, s.funder.pub, tokens)), "finalized", false)
		if err := s.svc.FundCold(s.ctx, fmt.Sprintf("fund-tkn-%d", tokens), 0, "TKN", bigU(tokens)); err != nil {
			s.t.Fatal(err)
		}
	}
}

// refuseImport imports a signed file and requires a 400.
func (s *wdSys) refuseImport(what, id string, sg coldsign.SOLSigned) {
	s.t.Helper()
	if code, out := s.importRefill(id, sg); code != 400 {
		s.t.Fatalf("%s: import answered %d %v, want 400", what, code, out)
	}
}

var _ = fmt.Sprint

func mustRaw(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
