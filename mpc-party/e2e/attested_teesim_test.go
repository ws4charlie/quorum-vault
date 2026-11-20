//go:build teesim

package e2e

import (
	"testing"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest/teetest"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/server"
	"github.com/ws4charlie/quorum-vault/mpc-party/internal/testenv"
)

// The crash matrix of the two-phase commit (a party killed at every failpoint of DKG and Refresh, restarted, converges on one generation that
// signs) with real party processes that run the ATTESTED sealer: each (re)start proves itself to a real broker (SoftHSM, signed allowlist, audit
// log) and gets its data keys back; the broker lives in the test process, the evidence root is the test CA. Run with -tags teesim.

func attestedCluster(t *testing.T) *cluster {
	t.Helper()
	env := testenv.NewEnv(t)
	ca := env.Config(t, "A", "127.0.0.1:1", "127.0.0.1:0", "")
	cb := env.Config(t, "B", "", "127.0.0.1:0", "127.0.0.1:0")
	rig := teetest.New(t, []teetest.PartyCert{
		{Role: "A", CertFile: ca.CertFile, KeyFile: ca.KeyFile, Pin: env.CertA.Pin},
		{Role: "B", CertFile: cb.CertFile, KeyFile: cb.KeyFile, Pin: env.CertB.Pin},
	})
	return newClusterOn(t, env, func(role string, c *server.Config) {
		c.Sealer = server.SealerConfig{Type: server.AttestedSealerType, BrokerURL: rig.URL, BrokerPins: []string{rig.Pin},
			BrokerCertFile: c.CertFile, BrokerKeyFile: c.KeyFile,
			Attester: server.AttesterConfig{Type: "mock", CADir: rig.CADir, PCR0: rig.Parties[role].PCR0Hex()}}
	}, false)
}

func TestAttestedCrashMatrixRefresh(t *testing.T) { crashMatrixRefresh(t, attestedCluster) }

func TestAttestedCrashMatrixDKG(t *testing.T) { crashMatrixDKG(t, attestedCluster) }
