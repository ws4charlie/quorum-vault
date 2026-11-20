package gateway

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsmsigner"
	"github.com/ws4charlie/quorum-vault/internal/mpcsigner"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// Signing from a generation of a hot shard other than the first.
//
// Generation 1 of a shard is what the signers section of the config pins: one signer per partition, its key checked against the pinned hot address at
// start. A later generation has its own key, and the zone learns how to reach it from the operator-signed record that registered the candidate (its
// key reference and public key, keysets.go), never from the business side. The signers of the config say HOW to reach the key (the token, or the parties
// and their certificates); the record says WHICH key. A GenerationSigner builds the signer from both, and the gateway picks it by the SENDER of the job's
// transaction: the generation whose address is the sender. Picking authorises nothing: the Decider still refuses a sender that is not a generation of
// the shard, a state that does not allow the job, and a signer whose key is not the sender's address, so a wrong pick is a refusal or a failed job, never
// a signature from a key the state rules do not allow.

// GenerationSigner builds the signer of generation e of the shard of partition, given the partition's configured (generation 1) signer. It returns
// (nil, nil) when it does not handle that kind of signer, so several can be tried in turn (ComposeGenerationSigners).
type GenerationSigner func(partition string, base signer.Signer, e *KeysetEntry) (signer.Signer, error)

// ComposeGenerationSigners tries each function in turn and returns the first signer one of them builds.
func ComposeGenerationSigners(fns ...GenerationSigner) GenerationSigner {
	return func(p string, base signer.Signer, e *KeysetEntry) (signer.Signer, error) {
		for _, f := range fns {
			if f == nil {
				continue
			}
			if s, err := f(p, base, e); s != nil || err != nil {
				return s, err
			}
		}
		return nil, nil
	}
}

// entryKey parses the public key a record carries and checks it hashes to the generation's address.
func entryKey(e *KeysetEntry) (*ecdsa.PublicKey, []byte, error) {
	if e.KeyRef == "" || e.PublicKey == "" {
		return nil, nil, fmt.Errorf("generation %d of %s has no key reference in its signed record: register the candidate with one", e.Generation, e.Shard)
	}
	raw, err := hex.DecodeString(e.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pub, err := crypto.UnmarshalPubkey(raw)
	if err != nil {
		return nil, nil, err
	}
	if crypto.PubkeyToAddress(*pub).Hex() != e.Address {
		return nil, nil, fmt.Errorf("the public key of generation %d of %s is not the key of %s", e.Generation, e.Shard, e.Address)
	}
	return pub, raw, nil
}

// MPCGenerationSigner builds the signer of a later generation of a 2-of-3 shard: the same parties and certificates as the partition's configured
// signer, the keyset named by the record's key reference.
func MPCGenerationSigner() GenerationSigner {
	return func(p string, base signer.Signer, e *KeysetEntry) (signer.Signer, error) {
		ts, ok := base.(*mpcsigner.ThresholdSigner)
		if !ok {
			return nil, nil
		}
		_, raw, err := entryKey(e)
		if err != nil {
			return nil, err
		}
		return ts.WithKey(e.KeyRef, raw)
	}
}

// HSMGenerationSigner builds the signer of a later generation of an HSM shard: the same token as the partition's configured signer, the key whose
// CKA_ID (hex) is the record's key reference.
func HSMGenerationSigner(cfg *Config, tokens map[string]*hsm.Token) GenerationSigner {
	return func(p string, base signer.Signer, e *KeysetEntry) (signer.Signer, error) {
		sf, ok := cfg.Signers[p]
		if !ok || sf.Backend == "mpc" {
			return nil, nil
		}
		tok := tokens[sf.Token]
		if tok == nil {
			return nil, fmt.Errorf("token %q is not open", sf.Token)
		}
		_, raw, err := entryKey(e)
		if err != nil {
			return nil, err
		}
		id, err := hex.DecodeString(e.KeyRef)
		if err != nil || len(id) == 0 {
			return nil, fmt.Errorf("the key reference of generation %d of %s must be the key's CKA_ID in hex", e.Generation, e.Shard)
		}
		return hsmsigner.New(tok, domain.Key{ID: p, Backend: domain.BackendHSM, Curve: domain.CurveSecp256k1, HSMKeyID: id, PublicKey: raw})
	}
}

// genSigners caches the signers built for later generations.
type genSigners struct {
	build GenerationSigner
	mu    sync.Mutex
	made  map[string]signer.Signer
}

func (g *genSigners) get(p string, base signer.Signer, e *KeysetEntry) (signer.Signer, error) {
	k := p + "|" + e.KeyRef + "|" + e.PublicKey
	g.mu.Lock()
	defer g.mu.Unlock()
	if s := g.made[k]; s != nil {
		return s, nil
	}
	s, err := g.build(p, base, e)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("no way to reach the key of generation %d of %s from this partition's signer", e.Generation, e.Shard)
	}
	if g.made == nil {
		g.made = map[string]signer.Signer{}
	}
	g.made[k] = s
	return s, nil
}

// signerFor picks the signer of an EVM job: the partition's configured signer, or the one of the later generation whose address is the sender of the
// job's transaction. An error is an operational failure of this zone (the record names no usable key), not a refusal.
func (g *Gateway) signerFor(ctx context.Context, job signjob.Job, base signer.Signer) (signer.Signer, error) {
	if g.gens == nil {
		return base, nil
	}
	codec := g.codecs[job.Chain]
	if codec == nil || g.cfg.Chains[job.Chain] == nil || g.cfg.Chains[job.Chain].Family != FamilyEVM {
		return base, nil
	}
	info, err := codec.Decode(chain.UnsignedTx{Chain: job.Chain, Digest: job.Digest, Payload: job.Payload, KeyRef: chain.KeyRef{PartitionID: job.PartitionID, Path: job.KeyRef}})
	if err != nil {
		return base, nil // the decision refuses a transaction that does not decode
	}
	kv, err := g.guard.EffectiveKeysets(ctx, g.cfg)
	if err != nil {
		return nil, err
	}
	shard, ok := kv.shardOf(job.PartitionID)
	if !ok {
		return base, nil
	}
	e := kv.byAddress(shard, info.Sender)
	if e == nil || e.Generation == 1 {
		return base, nil
	}
	s, err := g.gens.get(job.PartitionID, base, e)
	if err != nil {
		// Not an outcome of its own: with the configured signer the decision refuses what the state rules do not allow (that comes first), and a job they
		// do allow then fails on "the signer's key is not the sender's", with this ALERT saying why.
		slog.Error("ALERT keyset registry: the zone cannot sign from a generation of a shard: its signed record names no usable key", "job", job.ID, "partition", job.PartitionID, "sender", info.Sender, "error", err.Error())
		return base, nil
	}
	return s, nil
}
