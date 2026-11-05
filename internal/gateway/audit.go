package gateway

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// The zone's audit trail. Every decision the gateway and the cosigner make is appended to the hash chain in their own guard
// database: the permission to sign ("sign.allowed") in the same transaction that reserves the digest, so there is no signature
// without a record; the release of a signature ("sign.completed"), in the transaction that stores it; and every refusal
// ("sign.refused") with its reason, in a transaction of its own, before the refusal is reported. A write that fails is an
// error, never a quiet skip: the gateway then retries the job instead of answering without a record.
//
// Payloads hold ids, amounts, addresses, hashes and the names of the approvers. Never keys or signatures.
const (
	EventSignAllowed   = "sign.allowed"   // steps 1 to 5 passed, the digest is reserved; the signer may run
	EventSignReplayed  = "sign.replayed"  // a stored signature was returned, nothing signed again
	EventSignCompleted = "sign.completed" // gateway only: the signature was stored and is released
	EventSignRefused   = "sign.refused"   // a policy refusal, with its code and detail
)

// Pool-level access for the anchors and the verify command.
func (g *Guard) Querier() audit.Querier { return g.pool }

// auditRecord is what a decision says about the job.
type auditRecord struct {
	mode      Mode
	job       signjob.Job
	intent    *intentFacts
	approvers []string
	reason    string
}

type intentFacts struct {
	ID, Kind, Asset, Amount, Sender string
	Nonce                           uint64
	IntentHash                      []byte
}

func (m Mode) actor() string {
	if m == ModeCosigner {
		return "qv-cosigner"
	}
	return "qv-gateway"
}

func (r auditRecord) event(typ string) (domain.AuditEvent, error) {
	p := map[string]any{"job": r.job.ID, "chain": r.job.Chain, "partition": r.job.PartitionID, "digest": hex.EncodeToString(r.job.Digest)}
	if f := r.intent; f != nil {
		p["intent"], p["kind"], p["asset"], p["amount"], p["sender"], p["nonce"] = f.ID, f.Kind, f.Asset, f.Amount, f.Sender, f.Nonce
		p["intent_hash"] = hex.EncodeToString(f.IntentHash)
	}
	if r.approvers != nil {
		p["approvers"] = r.approvers
	}
	if r.reason != "" {
		p["reason"] = r.reason
	}
	b, err := json.Marshal(p)
	if err != nil {
		return domain.AuditEvent{}, err
	}
	return domain.AuditEvent{Actor: r.mode.actor(), Type: typ, Payload: b}, nil
}

// Audit appends a decision inside the guard transaction.
func (t *GuardTx) audit(ctx context.Context, rec auditRecord, typ string) error {
	ev, err := rec.event(typ)
	if err != nil {
		return err
	}
	if _, err := audit.AppendTx(ctx, t.tx, ev, ""); err != nil {
		return fmt.Errorf("gateway: audit %s: %w", typ, err)
	}
	return nil
}

// auditAlone appends a decision in a transaction of its own (a refusal rolls the guard transaction back, so it cannot ride in it).
func (g *Guard) auditAlone(ctx context.Context, rec auditRecord, typ string) error {
	ev, err := rec.event(typ)
	if err != nil {
		return err
	}
	tx, err := g.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("gateway: audit %s: %w", typ, err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err := audit.AppendTx(ctx, tx, ev, ""); err != nil {
		return fmt.Errorf("gateway: audit %s: %w", typ, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("gateway: audit %s: %w", typ, err)
	}
	return nil
}

// completedEvent is the record of a stored signature: which intent and digest, never the signature itself.
func (r auditRecord) completedEvent(intent string) (domain.AuditEvent, error) {
	b, err := json.Marshal(map[string]any{"intent": intent, "digest": hex.EncodeToString(r.job.Digest)})
	if err != nil {
		return domain.AuditEvent{}, err
	}
	return domain.AuditEvent{Actor: r.mode.actor(), Type: EventSignCompleted, Payload: b}, nil
}

// RecordRefusal records a refusal made before the Decider ran (the cosigner's checks of its own request). If the record cannot
// be written the error says so, and the caller must not answer as if it had refused.
func (d *Decider) RecordRefusal(ctx context.Context, jobID, chain string, digest []byte, reason string) error {
	return d.guard.auditAlone(ctx, auditRecord{mode: d.mode, job: signjob.Job{ID: jobID, Chain: chain, Digest: digest}, reason: reason}, EventSignRefused)
}
