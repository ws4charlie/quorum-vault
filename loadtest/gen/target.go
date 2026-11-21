package gen

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Target says where the system is and who the generator is. Written by the setup of a run (the local stack's test, the kind lane, later the cloud's
// pipeline); the generator holds no default.
type Target struct {
	API    []string `json:"api"`     // base URLs of the core API; requests go round robin (several copies of the core)
	CAFile string   `json:"ca_file"` // trust root of the API's certificate, if https
	// ServerName is the name the API's certificate carries, when the URL is an address (a port-forward to a cluster: https://127.0.0.1:PORT, name qv-core.qv.svc)
	ServerName string   `json:"tls_server_name,omitempty"`
	Token      TokenCfg `json:"token"`
	Actors     struct {
		Initiator string   `json:"initiator"` // requests withdrawals
		Ops       string   `json:"ops"`       // creates customers, reads, reconciles
		Approvers []string `json:"approvers"` // sign approvals (tier "two": the first two that are not the initiator)
	} `json:"actors"`
	ApproverKeyFiles map[string]string `json:"approver_key_files"` // name -> file with the hex Ed25519 seed
	EVM              *EVMTarget        `json:"evm,omitempty"`
	// PrometheusURL: if set, the run's check asks it which alerts are firing (the "no alert that should not have fired" check).
	PrometheusURL string `json:"prometheus_url,omitempty"`
}

// EVMTarget is the chain the deposits are paid on.
type EVMTarget struct {
	Chain         string `json:"chain"`           // the custody config's chain name
	RPC           string `json:"rpc"`             // JSON-RPC of the node
	FunderKeyFile string `json:"funder_key_file"` // hex secp256k1 key that pays the deposits (a test chain's faucet)
	ChainID       int64  `json:"chain_id"`
}

// TokenCfg is how bearer tokens are obtained.
type TokenCfg struct {
	// Kind "endpoint": GET URL?actor=NAME returns the token as the body (the local stack's test issuer, behind a loopback address).
	// Kind "keycloak": the realm's login page, user name and password (SecretsDir/kc-<user>), client qv-e2e: the dev realm of the kind lane (as e2e/idp).
	Kind       string `json:"kind"`
	URL        string `json:"url"`
	CAFile     string `json:"ca_file,omitempty"`
	ServerName string `json:"tls_server_name,omitempty"`
	SecretsDir string `json:"secrets_dir,omitempty"`
	Realm      string `json:"realm,omitempty"`
}

// LoadTarget reads a target file.
func LoadTarget(path string) (*Target, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Target
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(t.API) == 0 {
		return nil, fmt.Errorf("%s: no api", path)
	}
	if t.Actors.Initiator == "" || t.Actors.Ops == "" {
		return nil, fmt.Errorf("%s: actors need an initiator and an ops", path)
	}
	return &t, nil
}

// Approvers reads the approvers' signing keys.
func (t *Target) Approvers() (map[string]ed25519.PrivateKey, error) {
	out := map[string]ed25519.PrivateKey{}
	for name, p := range t.ApproverKeyFiles {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s: not a hex Ed25519 seed", p)
		}
		out[name] = ed25519.NewKeyFromSeed(seed)
	}
	return out, nil
}

func tlsConfig(caFile, serverName string) (*tls.Config, error) {
	if caFile == "" {
		return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName}, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no certificate", caFile)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: serverName}, nil
}

// tokens hands out bearer tokens, a fresh one for an actor at least every 45 seconds (an approval needs a recent login: the core's window is five minutes).
type tokens struct {
	cfg TokenCfg
	hc  *http.Client
	mu  sync.Mutex
	c   map[string]cached
}

type cached struct {
	tok string
	at  time.Time
}

func newTokens(cfg TokenCfg) (*tokens, error) {
	tc, err := tlsConfig(cfg.CAFile, cfg.ServerName)
	if err != nil {
		return nil, err
	}
	return &tokens{cfg: cfg, c: map[string]cached{}, hc: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, MaxIdleConnsPerHost: 8}}}, nil
}

func (t *tokens) bearer(actor string) (string, error) {
	t.mu.Lock()
	if c, ok := t.c[actor]; ok && time.Since(c.at) < 45*time.Second {
		t.mu.Unlock()
		return c.tok, nil
	}
	t.mu.Unlock()
	var tok string
	var err error
	switch t.cfg.Kind {
	case "endpoint":
		tok, err = t.fromEndpoint(actor)
	case "keycloak":
		tok, err = t.fromKeycloak(actor)
	default:
		err = fmt.Errorf("token kind %q", t.cfg.Kind)
	}
	if err != nil {
		return "", err
	}
	t.mu.Lock()
	t.c[actor] = cached{tok, time.Now()}
	t.mu.Unlock()
	return tok, nil
}

func (t *tokens) fromEndpoint(actor string) (string, error) {
	resp, err := t.hc.Get(t.cfg.URL + "?actor=" + url.QueryEscape(actor))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token endpoint: HTTP %d", resp.StatusCode)
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "Bearer ")), nil
}

// fromKeycloak logs the user in through the realm's login page, username and password only, with the client qv-e2e of the dev realm (the same flow as
// e2e/idp and ci/kind/tools/kindwd). The password is read from SecretsDir/kc-<user>.
func (t *tokens) fromKeycloak(user string) (string, error) {
	pw, err := os.ReadFile(filepath.Join(t.cfg.SecretsDir, "kc-"+user))
	if err != nil {
		return "", err
	}
	realm := t.cfg.Realm
	if realm == "" {
		realm = "quorumvault"
	}
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Timeout: 30 * time.Second, Jar: jar, Transport: t.hc.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := strings.TrimRight(t.cfg.URL, "/") + "/realms/" + realm + "/protocol/openid-connect/"
	redirect := "http://127.0.0.1/cb"
	resp, err := hc.Get(base + "auth?" + url.Values{"client_id": {"qv-e2e"}, "response_type": {"code"}, "scope": {"openid"}, "redirect_uri": {redirect}, "state": {"s"}}.Encode())
	if err != nil {
		return "", err
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page)
	if m == nil {
		return "", fmt.Errorf("keycloak: no login form (HTTP %d)", resp.StatusCode)
	}
	resp, err = hc.PostForm(strings.ReplaceAll(string(m[1]), "&amp;", "&"), url.Values{"username": {user}, "password": {strings.TrimSpace(string(pw))}, "credentialId": {""}})
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	loc, err := resp.Location()
	if err != nil || loc.Query().Get("code") == "" {
		return "", fmt.Errorf("keycloak: login did not redirect with a code (HTTP %d)", resp.StatusCode)
	}
	resp, err = hc.PostForm(base+"token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"qv-e2e"}, "code": {loc.Query().Get("code")}, "redirect_uri": {redirect}})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(b, &out) != nil || out.AccessToken == "" {
		return "", fmt.Errorf("keycloak: token: HTTP %d", resp.StatusCode)
	}
	return out.AccessToken, nil
}
