//go:build teesim

package server_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

// The admin set and the recovery-key registry of a party are plain files under the PKCS#11 sealer and sealed ones under the attested sealer. The migration
// seals them: a party that was moved over keeps the set it had, instead of finding a file it cannot read (which refuses every admin call) or, worse,
// starting on its configuration's list.
func TestMigrationSealsTheAdminRecords(t *testing.T) {
	env := testenv.NewEnv(t)
	r := newAttRigOn(t, env)
	p := startPair(t, pairOpts{env: env, sealerA: pkcs11Sealer(t, "qv-party-1"), sealerB: pkcs11Sealer(t, "qv-party-2")})
	p.dkg(t, "ks", pb.Curve_CURVE_SECP256K1)
	ctx, cancel := context.WithTimeout(context.Background(), 10_000_000_000)
	defer cancel()
	p.A.Shutdown(ctx)
	p.B.Shutdown(ctx)
	c := newAttClusterOn(t, r)

	var keys []string
	for _, k := range env.AdminKeys {
		keys = append(keys, hex.EncodeToString(k.Public().(ed25519.PublicKey)))
	}
	fpr := strings.Repeat("ab", 32)
	old := strings.Repeat("cd", 32)
	zero := strings.Repeat("00", 32)
	set, _ := json.Marshal(map[string]any{"v": 1, "version": 3, "keys": keys, "threshold": 2, "prev_hash": zero, "applied_unix": 1, "signed_by": []string{}})
	reg, _ := json.Marshal(map[string]any{"v": 1, "version": 2, "current": fpr, "retired": []string{old}, "prev_hash": zero, "applied_unix": 1, "signed_by": []string{}})
	for _, cfg := range []*server.Config{c.cfgA, c.cfgB} {
		for name, body := range map[string][]byte{"admin-set.json": set, "recovery-key.json": reg} {
			if err := os.WriteFile(filepath.Join(cfg.DataDir, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for role, tok := range map[string]string{"A": "qv-party-1", "B": "qv-party-2"} {
		cfg := map[string]*server.Config{"A": c.cfgA, "B": c.cfgB}[role]
		from, to := *cfg, *cfg
		from.Sealer = server.SealerConfig{Type: "pkcs11", Token: tok, PinEnv: "QV_TEST_PIN"}
		to.Sealer = r.sealerConfig(role, "")
		rep, err := server.MigrateSeal(context.Background(), &from, &to, server.MigrateOptions{})
		if err != nil || rep.Records != 2 {
			t.Fatalf("migrate %s: %+v %v", role, rep, err)
		}
		for _, name := range []string{"admin-set.json", "recovery-key.json"} {
			raw, _ := os.ReadFile(filepath.Join(cfg.DataDir, name))
			var probe struct{ KID string }
			if json.Unmarshal(raw, &probe) != nil || probe.KID == "" {
				t.Fatalf("%s %s is not sealed after the migration: %s", role, name, raw)
			}
		}
	}
	c.up()
	defer c.down()
	c.waitReady(30_000_000_000)
	h, err := c.p.Client.Health(ctx30(t), &pb.HealthRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if h.AdminSet == nil || h.AdminSet.Version != 3 || !h.AdminSet.FromState {
		t.Fatalf("the admin set after the migration: %v", h.AdminSet)
	}
	if h.RecoveryKey == nil || h.RecoveryKey.Version != 2 || h.RecoveryKey.Current != fpr || len(h.RecoveryKey.Retired) != 1 {
		t.Fatalf("the registry after the migration: %v", h.RecoveryKey)
	}
}
