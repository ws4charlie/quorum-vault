package signing

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/mpc"
)

// MPCGenerator is the MPC KeyGenerator used by the service. It does what
// mpc.NewGenerator does (same "<walletID>-v<version>" key ref, so
// mpc.NewSigner finds the shares) and also records the DKG ceremony as an
// mpc.keygen audit event with its stats, which domain.KeyGenerator cannot
// return.
type MPCGenerator struct {
	c   *mpc.Cluster
	aud domain.Auditor
	log *slog.Logger
}

func NewMPCGenerator(c *mpc.Cluster, aud domain.Auditor, log *slog.Logger) *MPCGenerator {
	if log == nil {
		log = slog.Default()
	}
	return &MPCGenerator{c: c, aud: aud, log: log}
}

func (g *MPCGenerator) Backend() domain.Backend { return domain.BackendMPC }

func (g *MPCGenerator) Generate(ctx context.Context, walletID string, version int) (domain.Key, error) {
	ref := fmt.Sprintf("%s-v%d", walletID, version)
	pub, st, err := g.c.Keygen(ctx, ref)
	if err != nil {
		return domain.Key{}, err
	}
	k := domain.Key{
		ID:        uuid.NewString(),
		WalletID:  walletID,
		Version:   version,
		Curve:     domain.CurveSecp256k1,
		Backend:   domain.BackendMPC,
		MPCKeyRef: ref,
		PublicKey: crypto.FromECDSAPub(pub),
		Address:   crypto.PubkeyToAddress(*pub).Hex(),
	}
	parties := []string{}
	for _, id := range g.c.PartyIDs() {
		parties = append(parties, fmt.Sprintf("party-%d", id))
	}
	b, _ := json.Marshal(map[string]any{
		"key_ref": ref, "version": version, "address": k.Address, "participants": parties,
		"threshold": fmt.Sprintf("%d-of-%d", g.c.Threshold()+1, len(parties)),
		"rounds":    st.Rounds, "messages": st.Messages, "bytes": st.Bytes, "duration_ms": st.Duration.Milliseconds(),
	})
	if _, err := g.aud.Append(context.WithoutCancel(ctx), domain.AuditEvent{Actor: "system", Type: domain.EventMPCKeygen,
		WalletID: walletID, KeyID: k.ID, Payload: b}); err != nil {
		g.log.Error("AUDIT APPEND FAILED after MPC keygen", "key_ref", ref, "err", err)
	}
	return k, nil
}
