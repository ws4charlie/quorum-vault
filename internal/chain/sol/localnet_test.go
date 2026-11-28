package sol

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"filippo.io/edwards25519"
)

// A local validator's genesis hash is not pinned, so New refuses network "localnet" in production (QV_ENV unset or anything but dev or
// test) before it touches the node or the database; dev and test go on (here to the nil-pool error, the next check).
func TestNewRefusesLocalnetInProduction(t *testing.T) {
	cfg := Config{Chain: "sol", Network: "localnet", RPCURL: "http://127.0.0.1:1",
		AccountPublicKey: hex.EncodeToString(edwards25519.NewGeneratorPoint().Bytes()), AccountChainCode: hex.EncodeToString(make([]byte, 32))}
	for env, refused := range map[string]bool{"": true, "prod": true, "staging": true, "dev": false, "test": false, " TEST ": false} {
		t.Run("QV_ENV="+env, func(t *testing.T) {
			t.Setenv("QV_ENV", env)
			_, err := New(context.Background(), cfg, nil)
			if err == nil {
				t.Fatal("New succeeded with a nil pool")
			}
			if got := strings.Contains(err.Error(), "localnet is refused in production"); got != refused {
				t.Fatalf("refused=%v, want %v: %v", got, refused, err)
			}
		})
	}
	t.Run("devnet in production is not refused by this rule", func(t *testing.T) {
		t.Setenv("QV_ENV", "")
		c := cfg
		c.Network = "devnet"
		if _, err := New(context.Background(), c, nil); err == nil || strings.Contains(err.Error(), "localnet") {
			t.Fatalf("devnet: %v", err)
		}
	})
}
