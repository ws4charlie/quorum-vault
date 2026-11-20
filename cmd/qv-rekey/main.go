// Command qv-rekey walks the replacement of the key of one EVM hot shard, one step at a time, and can be stopped and run again at any step
// (docs/runbooks/key-replacement.md).
//
//	qv-rekey open       -shard S -mode mpc|hsm -reason TEXT   check the shard and write the plan
//	qv-rekey dkg        [-admin-auth F]                      make the new key: mpc: a DKG on the parties (an operator's `qv-keysets party-auth` file); hsm: a key in the token
//	qv-rekey candidate  [-change F]                          register the new generation in the zone (signed record) and the core
//	qv-rekey drain-start -cap ASSET=N ... [-compromised] [-change F]   the old generation drains into the new one (-compromised: marked compromised instead)
//	qv-rekey activate   [-change F]                          the new generation is active; prints the cold ceremony to do
//	qv-rekey caps       -cap ASSET=N ... [-change F]          raise (or reset) the drain caps of the old generation in the zone
//	qv-rekey status                                           where every part stands, and the next step
//	qv-rekey retire     [-change F]                          the drained old generation is retired
//	qv-rekey emergency  -cap ASSET=N ... -changes F ... [-shard S -mode M -reason T]   the emergency order in one resumable run (emergency.go)
//
// Common flags: -dir WORK_DIR (the plan lives there), -config ZONE_CONFIG, -guard-dsn name=DSN (repeat: the gateway's and every cosigner's guard database),
// -core URL, -core-ca CA.pem, -token-file FILE (an admin's bearer token, read at every call), -core-header K=V (development only).
//
// The tool signs nothing. A step that needs the operators' signature prints the `qv-keysets sign` command to run (with the sequence number to use) and
// stops; run it again with -change FILE (the signed, joined change) and it applies the file to every zone database and then asks the core's admin route to
// mirror the step. The zone is always first; it refuses to go on when the zone and the core disagree, and says which is behind.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ws4charlie/quorum-vault/internal/auth"
	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsmsigner"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "qv-rekey:", err)
		os.Exit(1)
	}
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: qv-rekey open|dkg|candidate|drain-start|activate|caps|status|retire|emergency (see docs/runbooks/key-replacement.md)")
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	dir := fs.String("dir", "", "work directory (holds plan.json)")
	cfgPath := fs.String("config", "", "signing-zone config file")
	var guards, caps, headers listFlag
	fs.Var(&guards, "guard-dsn", "a zone guard database as name=DSN (repeat: the gateway and every cosigner)")
	fs.Var(&caps, "cap", "ASSET=BASE_UNITS (drain-start, caps)")
	fs.Var(&headers, "core-header", "K=V header on every core call (development only; X-Actor=name in the test environment)")
	coreURL := fs.String("core", "", "the core's base URL, e.g. https://qv-core:8443")
	coreCA := fs.String("core-ca", "", "PEM file of the CA that signed the core's certificate")
	tokenFile := fs.String("token-file", "", "file with an admin's bearer token (a fresh login: the routes need step-up)")
	compromised := fs.Bool("compromised", false, "drain-start: the emergency order, the old key is marked compromised (it signs only its drain, and is never retired)")
	change := fs.String("change", "", "the signed, joined change file for this step")
	var changes listFlag
	fs.Var(&changes, "changes", "emergency: a signed, joined change file (repeat: the candidate, mark-compromised and activate records, signed ahead of time)")
	poll := fs.Duration("poll", 10*time.Second, "emergency: how often the drain is looked at")
	stallAfter := fs.Duration("stall-after", 10*time.Minute, "emergency: the drain is called stalled when it shows no progress for this long (the command ends; run it again)")
	shard := fs.String("shard", "", "open: the shard ID, entity/chain/pool/number")
	mode := fs.String("mode", "", "open: mpc (2-of-3 keyset on the parties) or hsm (a key in the token)")
	reason := fs.String("reason", "", "open: why the key is replaced")
	adminAuth := fs.String("admin-auth", "", "dkg (mpc): the operator's `qv-keysets party-auth -op dkg -keyset ID` file")
	rpc := fs.String("rpc", "", "status, activate: the chain's RPC URL, to read the factory's destination")
	window := fs.Int64("window", 0, "drain-start of a deposit tree: seconds its old deposit addresses stay swept before the old generation may retire (the signed record carries it)")
	factory := fs.String("factory", "", "status, activate: the forwarder factory's address")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dir == "" || *cfgPath == "" {
		return errors.New("-dir and -config are required")
	}
	cfg, err := gateway.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Operators == nil {
		return errors.New("the config has no operators section: signed keyset changes are off")
	}
	zone, closeZone, err := openZone(ctx, cfg, guards)
	if err != nil {
		return err
	}
	defer closeZone()
	env := &Env{Dir: *dir, Zone: zone, Out: out, Now: time.Now, ChangeFile: *change, Caps: caps, Compromised: *compromised, Window: *window}
	var hdr []string
	hdr = append(hdr, headers...)
	env.Core = &httpCore{base: strings.TrimRight(*coreURL, "/"), tokenFile: *tokenFile, headers: hdr, caCert: *coreCA}
	if *rpc != "" && *factory != "" {
		env.FactoryDestination = func(ctx context.Context) (string, error) {
			return factoryDestination(ctx, *rpc, common.HexToAddress(*factory))
		}
	}
	switch cmd {
	case "open":
		return env.Open(ctx, *shard, *mode, *reason)
	case "dkg", "status":
		p, err := loadPlan(*dir)
		if err != nil {
			return err
		}
		if cmd == "dkg" {
			keys, closeKeys, err := keysFor(cfg, zone, p, *adminAuth)
			if err != nil {
				return err
			}
			defer closeKeys()
			env.Keys = keys
			return env.DKG(ctx)
		}
		return env.Status(ctx)
	case "emergency":
		return runEmergency(ctx, env, func(p *Plan) (Keys, func(), error) { return keysFor(cfg, zone, p, *adminAuth) }, emergencyFlags{shard: *shard, mode: *mode, reason: *reason, adminAuth: *adminAuth, changes: changes, poll: *poll, stallAfter: *stallAfter})
	case "candidate":
		return env.Candidate(ctx)
	case "drain-start":
		return env.DrainStart(ctx)
	case "activate":
		return env.Activate(ctx)
	case "caps":
		return env.SetCaps(ctx)
	case "retire":
		return env.Retire(ctx)
	}
	return fmt.Errorf("unknown command %q", cmd)
}

// ---- the zone ----

type guardStore struct {
	name  string
	guard *gateway.Guard
}

type zoneDBs struct {
	cfg    *gateway.Config
	stores []guardStore
}

func openZone(ctx context.Context, cfg *gateway.Config, guards []string) (*zoneDBs, func(), error) {
	if len(guards) == 0 {
		return nil, nil, errors.New("at least one -guard-dsn is required")
	}
	z := &zoneDBs{cfg: cfg}
	var closers []func()
	closeAll := func() {
		for _, c := range closers {
			c()
		}
	}
	for _, g := range guards {
		name, dsn, ok := strings.Cut(g, "=")
		if !ok || name == "" || dsn == "" {
			closeAll()
			return nil, nil, fmt.Errorf("-guard-dsn %q: want name=DSN", g)
		}
		pool, err := db.NewPool(ctx, dsn, nil, nil)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		closers = append(closers, pool.Close)
		guard, err := gateway.OpenGuard(ctx, pool)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		z.stores = append(z.stores, guardStore{name, guard})
	}
	return z, closeAll, nil
}

func (z *zoneDBs) MinOperators() int { return z.cfg.Operators.Min }

func (z *zoneDBs) Views(ctx context.Context, shard string) (map[string]ZoneView, error) {
	out := map[string]ZoneView{}
	for _, s := range z.stores {
		v, err := s.guard.EffectiveKeysets(ctx, z.cfg)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
		zv := ZoneView{Seq: v.Seq, Gens: map[int]ZoneGen{}}
		for _, e := range v.Generations(partition.ShardID(shard)) {
			addr := e.Address
			if addr == "" {
				addr = e.PublicKey // a deposit tree has no address: its identity stands for it (the core records the same string)
			}
			zv.Gens[e.Generation] = ZoneGen{State: e.State, Address: addr, KeyRef: e.KeyRef, Successor: e.Successor}
		}
		if len(zv.Gens) == 0 {
			return nil, fmt.Errorf("%s: the zone does not know shard %s", s.name, shard)
		}
		out[s.name] = zv
	}
	return out, nil
}

func (z *zoneDBs) Apply(ctx context.Context, c gateway.KeysetChange) error {
	var failed []string
	for _, s := range z.stores {
		if err := s.guard.ApplyKeysetChange(ctx, z.cfg, c, time.Now(), s.name); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", s.name, err))
		}
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return nil
}

func (z *zoneDBs) Partition(shard string) (string, error) {
	if isTreePlan(shard) {
		return z.treePartition(shard)
	}
	var parts []string
	for _, cc := range z.cfg.Chains {
		for p := range cc.EVM.HotAddresses {
			if k, err := partition.Parse(p); err == nil && k.Tier == partition.TierHot && string(k.ShardID()) == shard {
				parts = append(parts, p)
			}
		}
	}
	for _, cc := range z.cfg.Chains {
		for p := range cc.SOL.HotShards {
			if k, err := partition.Parse(p); err == nil && k.Tier == partition.TierHot && string(k.ShardID()) == shard {
				parts = append(parts, p)
			}
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("shard %s is not a hot shard of an EVM or Solana chain in this zone's config", shard)
	}
	sort.Strings(parts)
	return parts[0], nil
}

// ---- the core ----

type httpCore struct {
	base      string
	tokenFile string
	headers   []string
	caCert    string
}

func (c *httpCore) client() (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS13}
	if c.caCert != "" {
		pem, err := os.ReadFile(c.caCert)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("-core-ca holds no certificate")
		}
		tc.RootCAs = pool
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}, nil
}

func (c *httpCore) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	if c.base == "" {
		return 0, nil, errors.New("-core is required")
	}
	cl, err := c.client()
	if err != nil {
		return 0, nil, err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.tokenFile != "" {
		raw, err := os.ReadFile(c.tokenFile)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(raw)), "Bearer ")))
	}
	for _, h := range c.headers {
		k, v, _ := strings.Cut(h, "=")
		req.Header.Set(k, v)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, nil
}

func (c *httpCore) Keysets(ctx context.Context, shard string) (map[int]CoreGen, error) {
	code, raw, err := c.do(ctx, http.MethodGet, "/v2/keysets", nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("GET /v2/keysets: %d %s", code, strings.TrimSpace(string(raw)))
	}
	var body struct {
		Keysets []CoreGen `json:"keysets"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	out := map[int]CoreGen{}
	for _, k := range body.Keysets {
		if k.ShardID == shard {
			out[k.Generation] = k
		}
	}
	return out, nil
}

func (c *httpCore) Post(ctx context.Context, route string, body map[string]any) error {
	code, raw, err := c.do(ctx, http.MethodPost, "/v2/keysets/"+route, body)
	if err != nil {
		return err
	}
	if code != 200 && code != 201 {
		return fmt.Errorf("POST /v2/keysets/%s: %d %s", route, code, strings.TrimSpace(string(raw)))
	}
	return nil
}

// ---- the new key ----

func addressOf(pubHex string) (string, error) {
	raw, err := hex.DecodeString(pubHex)
	if err != nil {
		return "", err
	}
	if len(raw) == 32 { // an Ed25519 key (a Solana hot shard): its address is the key in base58
		return sol.Address([32]byte(raw)), nil
	}
	pub, err := crypto.UnmarshalPubkey(raw)
	if err != nil {
		return "", err
	}
	return crypto.PubkeyToAddress(*pub).Hex(), nil
}

// mpcKeys makes a 2-of-3 keyset on the parties through party A (the coordinators of the shard's signer entry).
type mpcKeys struct {
	cfg       *gateway.Config
	partition string
	adminAuth string
}

func (k *mpcKeys) dial(c gateway.MPCSignerFile) (pb.MpcPartyClient, func(), error) {
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("client certificate: %w", err)
	}
	pin, err := wire.ParsePin(c.ServerPin)
	if err != nil {
		return nil, nil, err
	}
	creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true, //nolint:gosec // pinned
		VerifyPeerCertificate: wire.VerifyPinned(map[wire.Pin]bool{pin: true}, time.Now)})
	conn, err := grpc.NewClient(c.Address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, err
	}
	return pb.NewMpcPartyClient(conn), func() { conn.Close() }, nil
}

func (k *mpcKeys) coordinators() ([]gateway.MPCSignerFile, error) {
	sf, ok := k.cfg.Signers[k.partition]
	if !ok || (sf.Scheme != "ecdsa-2of3" && sf.Scheme != "ed25519-2of3") || len(sf.Coordinators) < 2 {
		return nil, fmt.Errorf("partition %q has no ecdsa-2of3 or ed25519-2of3 signer with coordinators A and B in the zone config", k.partition)
	}
	return sf.Coordinators, nil
}

// ed says whether the shard's key is an Ed25519 one (a Solana hot shard): its public key is the 32 bytes, in hex, and the address is their base58.
func (k *mpcKeys) ed() bool { return k.cfg.Signers[k.partition].Scheme == "ed25519-2of3" }

// pubHex is the hex form the plan and the zone record keep of a keyset's public key.
func (k *mpcKeys) pubHex(c []byte) (string, error) {
	if k.ed() {
		if len(c) != 32 {
			return "", fmt.Errorf("an Ed25519 public key is 32 bytes, the party gave %d", len(c))
		}
		return hex.EncodeToString(c), nil
	}
	return uncompressed(c)
}

// keyset finds the keyset on a party and returns its public key (uncompressed hex), or "" when it has none.
func keyset(ctx context.Context, cl pb.MpcPartyClient, id string) (*pb.KeysetStatus, error) {
	h, err := cl.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return nil, err
	}
	for _, s := range h.Keysets {
		if s.KeysetId == id {
			return s, nil
		}
	}
	return nil, nil
}

func uncompressed(c []byte) (string, error) {
	pk, err := crypto.DecompressPubkey(c)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.FromECDSAPub(pk)), nil
}

func (k *mpcKeys) New(ctx context.Context, p *Plan) (string, string, error) {
	coords, err := k.coordinators()
	if err != nil {
		return "", "", err
	}
	a, closeA, err := k.dial(coords[0])
	if err != nil {
		return "", "", err
	}
	defer closeA()
	id := p.KeysetID()
	// A keyset made by an earlier run whose result was not saved is found again, not made twice.
	if st, err := keyset(ctx, a, id); err != nil {
		return "", "", fmt.Errorf("party A: %w", err)
	} else if st != nil {
		pub, err := k.pubHex(st.PublicKey)
		return id, pub, err
	}
	if k.adminAuth == "" {
		return "", "", fmt.Errorf("-admin-auth is required: an operator's file from `qv-keysets party-auth -op dkg -keyset %s` (valid for a few minutes, make it right before)", id)
	}
	raw, err := os.ReadFile(k.adminAuth)
	if err != nil {
		return "", "", err
	}
	var f struct {
		Op        string `json:"op"`
		Keyset    string `json:"keyset"`
		Unix      int64  `json:"unix_seconds"`
		PublicKey string `json:"public_key"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return "", "", err
	}
	if f.Op != "dkg" || f.Keyset != id {
		return "", "", fmt.Errorf("%s is for %s of keyset %q, this step needs dkg of %q", k.adminAuth, f.Op, f.Keyset, id)
	}
	pub, err1 := hex.DecodeString(f.PublicKey)
	sig, err2 := hex.DecodeString(f.Signature)
	if err1 != nil || err2 != nil {
		return "", "", errors.New("the admin-auth file is not hex")
	}
	x, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	scheme := pb.Scheme_SCHEME_ECDSA_2OF3
	if k.ed() {
		scheme = pb.Scheme_SCHEME_ED25519_2OF3
	}
	r, err := a.DKG(x, &pb.DKGRequest{KeysetId: id, Scheme: scheme, Admin: &pb.AdminAuth{UnixSeconds: f.Unix, PublicKey: pub, Signature: sig}})
	if err != nil {
		// The DKG may have finished on the parties although the answer was lost: look again before reporting.
		if st, e2 := keyset(ctx, a, id); e2 == nil && st != nil {
			u, e3 := k.pubHex(st.PublicKey)
			return id, u, e3
		}
		return "", "", fmt.Errorf("DKG %s: %w", id, err)
	}
	u, err := k.pubHex(r.RootPublicKey)
	return id, u, err
}

func (k *mpcKeys) Check(ctx context.Context, p *Plan) error {
	coords, err := k.coordinators()
	if err != nil {
		return err
	}
	var gen uint64
	for i, c := range coords[:2] {
		cl, closeC, err := k.dial(c)
		if err != nil {
			return err
		}
		st, err := keyset(ctx, cl, p.KeyRef)
		closeC()
		if err != nil {
			return fmt.Errorf("party %s: %w", c.Name, err)
		}
		if st == nil {
			return fmt.Errorf("party %s does not have keyset %s", c.Name, p.KeyRef)
		}
		if st.Frozen || !st.Resolved {
			return fmt.Errorf("party %s: keyset %s is frozen=%v resolved=%v", c.Name, p.KeyRef, st.Frozen, st.Resolved)
		}
		u, err := k.pubHex(st.PublicKey)
		if err != nil || u != p.PublicKey {
			return fmt.Errorf("party %s holds another public key for keyset %s", c.Name, p.KeyRef)
		}
		if i == 0 {
			gen = st.Generation
		} else if st.Generation != gen {
			return fmt.Errorf("party %s is at generation %d of the keyset, party %s at %d", c.Name, st.Generation, coords[0].Name, gen)
		}
	}
	return nil
}

// hsmKeys makes a second key in the shard's token.
type hsmKeys struct {
	tok *hsm.Token
}

func newHSMKeys(cfg *gateway.Config, part string) (*hsmKeys, func(), error) {
	sf, ok := cfg.Signers[part]
	if !ok || sf.Backend == "mpc" || sf.Token == "" {
		return nil, nil, fmt.Errorf("partition %q has no HSM signer in the zone config", part)
	}
	pin, err := hsm.ServicePIN() // the file named by QV_HSM_PIN_FILE; the environment form only when QV_ENV is dev or test
	if err != nil {
		return nil, nil, err
	}
	lib, err := hsm.LoadLib(hsm.DefaultLibPath())
	if err != nil {
		return nil, nil, fmt.Errorf("load pkcs11: %w", err)
	}
	if err := hsm.RefuseSoftHSM(lib, auth.EnvironmentFromEnv() == auth.Production); err != nil {
		lib.Close()
		return nil, nil, err
	}
	tok, err := lib.OpenToken(sf.Token, pin)
	if err != nil {
		lib.Close()
		return nil, nil, err
	}
	return &hsmKeys{tok: tok}, func() { tok.Close(); lib.Close() }, nil
}

func (k *hsmKeys) New(ctx context.Context, p *Plan) (string, string, error) {
	key, err := hsmsigner.NewGenerator(k.tok).Generate(ctx, "rekey-"+p.KeysetID(), 1)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(key.HSMKeyID), hex.EncodeToString(key.PublicKey), nil
}

// Check signs a random digest with the new key and verifies the signature: the key is in the token and works.
func (k *hsmKeys) Check(ctx context.Context, p *Plan) error {
	id, err := hex.DecodeString(p.KeyRef)
	if err != nil {
		return err
	}
	pub, err := hex.DecodeString(p.PublicKey)
	if err != nil {
		return err
	}
	s, err := hsmsigner.New(k.tok, domainKey(id, pub))
	if err != nil {
		return err
	}
	var d [32]byte
	rand.Read(d[:])
	res, err := s.SignDigest(ctx, d, signer.SignOptions{})
	if err != nil {
		return fmt.Errorf("test signature: %w", err)
	}
	if !signer.Verify(s.PublicKey(), d, res.Sig) {
		return errors.New("the test signature does not verify")
	}
	return nil
}

// factoryDestination reads destination() of the forwarder factory.
func factoryDestination(ctx context.Context, rpc string, factory common.Address) (string, error) {
	ec, err := ethclient.DialContext(ctx, rpc)
	if err != nil {
		return "", err
	}
	defer ec.Close()
	out, err := ec.CallContract(ctx, ethereum.CallMsg{To: &factory, Data: crypto.Keccak256([]byte("destination()"))[:4]}, nil)
	if err != nil {
		return "", err
	}
	return common.BytesToAddress(out).Hex(), nil
}

func domainKey(id, pub []byte) domain.Key {
	return domain.Key{ID: "rekey", Backend: domain.BackendHSM, Curve: domain.CurveSecp256k1, HSMKeyID: id, PublicKey: pub}
}

// keysFor makes the Keys of the plan's mode: the parties for mpc, the token for hsm. The caller closes it.
func keysFor(cfg *gateway.Config, zone *zoneDBs, p *Plan, adminAuth string) (Keys, func(), error) {
	part, err := zone.Partition(p.Shard)
	if err != nil {
		return nil, nil, err
	}
	switch p.Mode {
	case "mpc":
		if isTreePlan(p.Shard) {
			return &treeKeys{cfg: cfg, partition: part, adminAuth: adminAuth}, func() {}, nil
		}
		return &mpcKeys{cfg: cfg, partition: part, adminAuth: adminAuth}, func() {}, nil
	case "hsm":
		k, closeKeys, err := newHSMKeys(cfg, part)
		if err != nil {
			return nil, nil, err
		}
		return k, closeKeys, nil
	}
	return nil, nil, fmt.Errorf("the plan has no mode %q", p.Mode)
}
