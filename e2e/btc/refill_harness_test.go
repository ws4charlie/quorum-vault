package btce2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/coldsign"
	"github.com/ws4charlie/quorum-vault/internal/custody"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
)

// coldKit is the offline side of the ceremony: a cold key in the qv-cold SoftHSM token, three operators and the offline config. qv-cold runs as a separate
// process and only files cross.
type coldKit struct {
	dir     string
	cfgPath string
	addr    string
}

// newColdKit makes the cold key (qv-cold keygen -network regtest), the operators and the offline config pinning the system's hot shard, and returns the
// cold address, which becomes the pool's cold address in both the business config and the gateway's.
func (s *system) newColdKit(o opts) string {
	t := s.t
	hsmtest.Token(t, "qv-cold") // skips, or fails under QV_REQUIRE_HSM, when the token is missing
	k := &coldKit{dir: filepath.Join(s.dir, "cold")}
	if err := os.MkdirAll(k.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyJSON := filepath.Join(k.dir, "key.json")
	s.runCold("keygen", "-lib", hsm.DefaultLibPath(), "-pin-env", "QV_HSM_PIN", "-network", "regtest", "-out", keyJSON)
	var key map[string]string
	b, _ := os.ReadFile(keyJSON)
	json.Unmarshal(b, &key)
	k.addr = key["btc_address"]
	ops := map[string]string{}
	for _, n := range []string{"alice", "bob", "carol"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		if err := os.WriteFile(filepath.Join(k.dir, n+".key"), []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
			t.Fatal(err)
		}
		ops[n] = hex.EncodeToString(pub)
	}
	cfg := coldsign.BTCConfig{Family: "btc", Network: "regtest", Chain: s.chain, Pool: "omnibus", Operators: ops, Threshold: 2, HotShards: []string{s.hotAddr},
		MaxAmount: 1_000_000_000, MaxFeeSats: 100_000, MaxFeeRate: 200, MaxInputs: 20, PublicKey: key["btc_public_key"],
		HSM: coldsign.HSMConfig{Token: "qv-cold", PinEnv: "QV_HSM_PIN", KeyID: key["key_id"]}, RecordDir: filepath.Join(k.dir, "record")}
	k.cfgPath = filepath.Join(k.dir, "cfg.json")
	writeJSONFile(t, k.cfgPath, cfg)
	s.kit = k
	ttl, poll := o.refillTTL, o.refillPoll
	if ttl == "" {
		ttl = "24h"
	}
	if poll == "" {
		poll = "1s"
	}
	stuck := o.refillStuck
	if stuck == "" {
		stuck = "10m"
	}
	s.cf.Cold.Refill = custody.RefillFile{Poll: poll, RequestTTL: ttl, StuckAfter: stuck}
	return k.addr
}

// runCold runs qv-cold and returns its output; it fails the test if the tool refuses.
func (s *system) runCold(args ...string) string {
	s.t.Helper()
	out, err := s.runColdErr(args...)
	if err != nil {
		s.t.Fatalf("qv-cold %v: %v\n%s", args, err, out)
	}
	return out
}

func (s *system) runColdErr(args ...string) (string, error) {
	cmd := exec.Command(filepath.Join(binDir, "qv-cold"), args...)
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+hsm.RepoSoftHSMConf(), "QV_HSM_PIN="+hsmtest.PIN())
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

// rawCall is an API call that returns the status and the body as sent (the files of the ceremony are exchanged as they are).
func (s *system) rawCall(method, path string, body []byte) (int, []byte) {
	s.t.Helper()
	req, err := http.NewRequest(method, s.apiURL+path, bytes.NewReader(body))
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("X-Actor", "ops")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

type rfRow struct {
	ID, Status, Reason, Tx string
	Amount, Fee            int64
	Revision               int
}

func (s *system) refillRows() []rfRow {
	s.t.Helper()
	rows, err := s.pool.Query(s.ctx, `SELECT id, status, COALESCE(failure_reason,''), COALESCE(tx_hash,''), amount::bigint, COALESCE(fee,0)::bigint, revision FROM refills WHERE chain=$1 AND kind='refill' ORDER BY created_at, id`, s.chain)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	var out []rfRow
	for rows.Next() {
		var r rfRow
		if err := rows.Scan(&r.ID, &r.Status, &r.Reason, &r.Tx, &r.Amount, &r.Fee, &r.Revision); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// refillIn waits for a refill in the status and returns the newest such.
func (s *system) refillIn(status string, timeout time.Duration) rfRow {
	s.t.Helper()
	var got rfRow
	s.waitFor(timeout, "a refill "+status, func() bool {
		for _, r := range s.refillRows() {
			if r.Status == status {
				got = r
			}
		}
		return got.ID != "" && got.Status == status
	})
	return got
}

func (s *system) refillsOpen() int {
	n := 0
	for _, r := range s.refillRows() {
		if r.Status != "confirmed" && r.Status != "failed" {
			n++
		}
	}
	return n
}

// exportRefill asks the core for the request file and writes it where the offline machine can take it.
func (s *system) exportRefill(id, name string) string {
	s.t.Helper()
	code, b := s.rawCall("POST", "/v2/refills/"+id+"/export", nil)
	if code != 200 {
		s.t.Fatalf("export: %d %s", code, b)
	}
	p := filepath.Join(s.kit.dir, name+".request.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		s.t.Fatal(err)
	}
	return p
}

// signRefill is the offline ceremony: two operators approve the request file, qv-cold signs it; the signed file is returned.
func (s *system) signRefill(reqPath string, operators ...string) (string, string, error) {
	s.t.Helper()
	if len(operators) == 0 {
		operators = []string{"alice", "bob"}
	}
	args := []string{"sign", "-config", s.kit.cfgPath, "-request", reqPath}
	for _, op := range operators {
		ap := strings.TrimSuffix(reqPath, ".request.json") + "." + op + ".approval.json"
		if out, err := s.runColdErr("approve", "-operator", op, "-key", filepath.Join(s.kit.dir, op+".key"), "-request", reqPath, "-out", ap); err != nil {
			return "", out, err
		}
		args = append(args, "-approval", ap)
	}
	signed := strings.TrimSuffix(reqPath, ".request.json") + ".signed.json"
	args = append(args, "-out", signed)
	out, err := s.runColdErr(args...)
	return signed, out, err
}

func (s *system) importRefill(id, signedPath string) (int, string) {
	s.t.Helper()
	b, err := os.ReadFile(signedPath)
	if err != nil {
		s.t.Fatal(err)
	}
	code, resp := s.rawCall("POST", "/v2/refills/"+id+"/import", b)
	return code, string(resp)
}

// ceremony runs the whole thing for one refill: export, approvals, signing, import.
func (s *system) ceremony(id, name string) {
	s.t.Helper()
	req := s.exportRefill(id, name)
	signed, out, err := s.signRefill(req)
	if err != nil {
		s.t.Fatalf("the ceremony refused: %v\n%s", err, out)
	}
	if code, body := s.importRefill(id, signed); code != 200 {
		s.t.Fatalf("import: %d %s", code, body)
	}
}

// coldRows counts cold outputs in the table by status.
func (s *system) coldRows(status string) int {
	return s.count(`SELECT count(*) FROM btc_utxos WHERE chain=$1 AND cold AND status=$2`, s.chain, status)
}

func (s *system) coldValue(status string) int64 {
	var v int64
	if err := s.pool.QueryRow(s.ctx, `SELECT COALESCE(SUM(value),0) FROM btc_utxos WHERE chain=$1 AND cold AND status=$2`, s.chain, status).Scan(&v); err != nil {
		s.t.Fatal(err)
	}
	return v
}

var _ = testing.Short
