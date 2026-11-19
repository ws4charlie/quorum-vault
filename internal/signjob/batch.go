package signjob

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// KindBatch is the job kind of one transaction that pays several withdrawals at once (Bitcoin).
const KindBatch = "batch"

// KindDrain is the job kind that moves everything an old hot shard key holds to its successor key (EVM first). Intent.PartitionID names the shard,
// Asset the asset, From the source address (which names the generation) and To the successor's address. The intent format and its version are
// unchanged: only the kind is new.
const KindDrain = "drain"

// BatchMember is one withdrawal of a batch exactly as a single withdrawal job carries it: its own intent and the approvals over that intent's hash.
// Approval stays per withdrawal; nothing is approved at the level of the batch.
type BatchMember struct {
	Intent    Intent
	Approvals []Approval
}

// Batch is the intent of a batch job (Job.Intent is its JSON). The batch has its own ID, the replay guard's key for the one transaction, and the
// members in payment order: the transaction's first outputs are exactly the members, in this order. Every member is a "withdrawal" intent of the
// batch's own chain, partition and asset. A batch job carries no approvals of its own (Job.Approvals must be empty).
type Batch struct {
	Kind        string // KindBatch
	ID          string
	PartitionID string
	Chain       string
	Asset       string
	Members     []BatchMember
}

const batchDomain = "qv-batch-v1\n"

// Hash identifies the batch: its fields and the hash of every member intent, in order. The replay guard records it under the batch's ID, so the
// same ID with other members or another order is a different batch. Approvals are not part of it (they are signatures over the member hashes).
func (b Batch) Hash() [32]byte {
	buf := []byte(batchDomain)
	for _, f := range []string{b.Kind, b.ID, b.PartitionID, b.Chain, b.Asset} {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(f)))
		buf = append(buf, f...)
	}
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(b.Members)))
	for _, m := range b.Members {
		h := m.Intent.Hash()
		buf = append(buf, h[:]...)
	}
	return sha256.Sum256(buf)
}

// Intents lists the member intents in order.
func (b Batch) Intents() []Intent {
	out := make([]Intent, len(b.Members))
	for i, m := range b.Members {
		out[i] = m.Intent
	}
	return out
}

// DecodeBatch reads the JSON of a batch intent strictly: unknown fields and trailing data are errors.
func DecodeBatch(raw []byte) (Batch, error) {
	var b Batch
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return b, fmt.Errorf("parse batch: %w", err)
	}
	if dec.More() {
		return b, errors.New("trailing data after batch")
	}
	return b, nil
}

// IsBatch reports whether the JSON of a job's intent is a batch (its "Kind" field is KindBatch), without judging the rest.
func IsBatch(raw []byte) bool {
	var k struct{ Kind string }
	return json.Unmarshal(raw, &k) == nil && k.Kind == KindBatch
}
