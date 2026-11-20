package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/chain/sol"
	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/mpcsigner"
	"github.com/ws4charlie/quorum-vault/internal/partition"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// The replacement of the deposit key tree of a Bitcoin or Solana chain (K6): the same steps as a hot shard's (open, dkg, candidate, drain-start, activate,
// retire, status), on the shard entity/chain/deposit-tree/0. The new key is a second 2-party HD keyset on parties A and B (Curve secp256k1 for Bitcoin,
// ed25519 for Solana); what the zone and the core record is its public identity (the account xpub, or "<node key hex>:<chain code hex>") and the keyset ID.
// On Bitcoin the hot shards derive from the same account, so drain-start also drains them (-cap BTC=SATS bounds it in the zone) and activate moves new
// work to the new key's hot shards; on Solana only the deposit node changes here (the hot shard is another task). retire takes -window from drain-start.

func isTreePlan(shard string) bool { return partition.ShardID(shard).IsDepositTree() }

// treeKeys makes the second HD keyset of the tree.
type treeKeys struct {
	cfg       *gateway.Config
	partition string
	adminAuth string
}

// party returns the connection settings of party A for the tree's signer: Bitcoin's signer entry, or Solana's deposit section.
func (k *treeKeys) party() (gateway.MPCSignerFile, string, error) {
	sf, ok := k.cfg.Signers[k.partition]
	if !ok {
		return gateway.MPCSignerFile{}, "", fmt.Errorf("partition %q has no signer entry in the zone config", k.partition)
	}
	if sf.Deposit != nil { // Solana
		return *sf.Deposit.MPC, "ed25519", nil
	}
	if sf.KeysetID != "" && len(sf.HardenedPath) > 0 { // Bitcoin: a key-tree signer
		return *sf.MPC, "secp256k1", nil
	}
	return gateway.MPCSignerFile{}, "", fmt.Errorf("partition %q has no deposit key tree signer (a Bitcoin key-tree signer, or a Solana deposit section)", k.partition)
}

func (k *treeKeys) client() (pb.MpcPartyClient, func(), string, error) {
	c, curve, err := k.party()
	if err != nil {
		return nil, nil, "", err
	}
	m := &mpcKeys{cfg: k.cfg, partition: k.partition}
	cl, closeC, err := m.dial(c)
	return cl, closeC, curve, err
}

// identity reads the account node of the keyset from party A and puts it in the form the zone and the core record.
func (k *treeKeys) identity(ctx context.Context, cl pb.MpcPartyClient, id, curve string) (string, error) {
	if curve == "ed25519" {
		n, err := sol.AccountNode(ctx, cl, id)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(n.PublicKey[:]) + ":" + hex.EncodeToString(n.ChainCode[:]), nil
	}
	network, err := k.network()
	if err != nil {
		return "", err
	}
	return mpcsigner.AccountXpub(ctx, cl, id, network)
}

func (k *treeKeys) network() (string, error) {
	for _, cc := range k.cfg.Chains {
		for p := range cc.BTC.HotShards {
			if p == k.partition {
				return cc.BTC.Network, nil
			}
		}
	}
	return "", errors.New("the partition is on no Bitcoin chain of the zone config")
}

func (k *treeKeys) New(ctx context.Context, p *Plan) (string, string, error) {
	cl, closeC, curve, err := k.client()
	if err != nil {
		return "", "", err
	}
	defer closeC()
	id := p.KeysetID()
	if st, err := keyset(ctx, cl, id); err != nil {
		return "", "", fmt.Errorf("party A: %w", err)
	} else if st != nil { // made by an earlier run whose result was not saved
		ident, err := k.identity(ctx, cl, id, curve)
		return id, ident, err
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
	c := pb.Curve_CURVE_SECP256K1
	if curve == "ed25519" {
		c = pb.Curve_CURVE_ED25519
	}
	x, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	if _, err := cl.DKG(x, &pb.DKGRequest{KeysetId: id, Curve: c, Admin: &pb.AdminAuth{UnixSeconds: f.Unix, PublicKey: pub, Signature: sig}}); err != nil {
		if st, e2 := keyset(ctx, cl, id); e2 != nil || st == nil { // the DKG may have finished although the answer was lost
			return "", "", fmt.Errorf("DKG %s: %w", id, err)
		}
	}
	ident, err := k.identity(ctx, cl, id, curve)
	return id, ident, err
}

func (k *treeKeys) Check(ctx context.Context, p *Plan) error {
	cl, closeC, curve, err := k.client()
	if err != nil {
		return err
	}
	defer closeC()
	st, err := keyset(ctx, cl, p.KeyRef)
	if err != nil {
		return fmt.Errorf("party A: %w", err)
	}
	if st == nil {
		return fmt.Errorf("party A does not have keyset %s", p.KeyRef)
	}
	if st.Frozen || !st.Resolved {
		return fmt.Errorf("party A: keyset %s is frozen=%v resolved=%v", p.KeyRef, st.Frozen, st.Resolved)
	}
	ident, err := k.identity(ctx, cl, p.KeyRef, curve)
	if err != nil {
		return err
	}
	if ident != p.PublicKey {
		return fmt.Errorf("party A derives another account key for keyset %s than the plan holds", p.KeyRef)
	}
	return nil
}

var _ = tls.VersionTLS13

// treePartition is a hot partition of the chain whose deposit tree the shard names: its signer entry says where party A is.
func (z *zoneDBs) treePartition(shard string) (string, error) {
	var parts []string
	for name, cc := range z.cfg.Chains {
		var ps []string
		switch cc.Family {
		case gateway.FamilyBTC:
			for p := range cc.BTC.HotShards {
				ps = append(ps, p)
			}
		case gateway.FamilySOL:
			for p := range cc.SOL.HotShards {
				ps = append(ps, p)
			}
		}
		for _, p := range ps {
			if k, err := partition.Parse(p); err == nil {
				if id, err := partition.DepositTreeID(k.Entity, name); err == nil && string(id) == shard {
					parts = append(parts, p)
				}
			}
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("%s is not the deposit tree of a Bitcoin or Solana chain in this zone's config", shard)
	}
	sort.Strings(parts)
	return parts[0], nil
}
