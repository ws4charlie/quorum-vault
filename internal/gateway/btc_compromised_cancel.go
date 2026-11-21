package gateway

import (
	"context"
	"strconv"
	"time"

	"github.com/ws4charlie/quorum-vault/internal/partition"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// btcCompromisedCancel is the one thing besides its sweeps and its drain that a compromised generation of the Bitcoin account key may sign: the strict cancel
// of a payment of its own that the zone refused after the mark. The case: the gateway admitted a payment (its replay guard claimed every input it spends),
// then a cosigner that already had the mark refused it. No signature exists, the claims stay, and a drain that spends a claimed coin is refused
// (replay_nonce_taken) for ever. A cancel takes the claims over, so the guard refuses every other intent on those coins, and it spends exactly them.
//
// Value never leaves the old key by this rule: the verifier already requires a cancel to have one output, paid to the partition's hot shard under the SAME
// generation as its inputs, within the fee cap, and the rule repeats it (DestGen == Gen) from the decoded transaction. The drain then moves the output of the
// cancel, with every drain check. What this adds to a thief's reach is a bounded number of self-payments that burn fee (max_cancels_per_source per generation).
//
//   - the drain's own precondition: a successor is named and active here, else a wait until the intent's not_after (24 h, the core renews it)
//   - the gateway: strictCancel (decider.go): every input is claimed, by one intent, of this partition, and the claims are all that intent's
//   - a cosigner holding none of the claims (it refused the payment before it reserved anything) admits the cancel by shape and takes them (decider.go: replay);
//     a mixed state is refused by strictCancel
//   - in both: a claim held by a drain is never taken over, so a compromised gateway cannot knock out the drain's own moves
func (d *Decider) btcCompromisedCancel(ctx context.Context, gt *GuardTx, tree map[int]*KeysetEntry, cc *ChainConfig, e *KeysetEntry, label string, i signjob.Intent, info TxInfo, known bool, now time.Time) error {
	if info.DestGen != info.Gen {
		return reject(ReasonKeyset, "%s is compromised: it may cancel its own payment only, back to its own hot shard (the output is generation %d's)", label, info.DestGen)
	}
	if e.Successor == 0 {
		return reject(ReasonKeyset, "%s is compromised with no successor named: it signs nothing, not even a cancel", label)
	}
	s := tree[e.Successor]
	if s == nil || s.State != partition.StateActive {
		return d.keysetLag(i, now, "the successor of %s is not active here: a compromised key signs its cancel only once its drain may start", label)
	}
	if len(info.Claims) == 0 {
		return reject(ReasonKeyset, "a cancel names the coins it frees")
	}
	for _, c := range info.Claims {
		cl, err := gt.Claim(ctx, c)
		if err != nil {
			return err
		}
		if cl != nil && cl.Kind == signjob.KindDrain {
			return reject(ReasonKeyset, "%s is claimed by a drain: a compromised key's cancel does not take over a drain", c)
		}
	}
	if known {
		return nil // another attempt of a cancel already admitted: counted then
	}
	gen := strconv.Itoa(int(info.Gen))
	made, err := gt.SignedCancelCountFromGen(ctx, gen)
	if err != nil {
		return err
	}
	if made >= cc.maxCancelsPerSource() {
		return reject(ReasonCancelGas, "%d cancels already signed under %s, the most the zone allows a compromised generation (max_cancels_per_source %d)", made, label, cc.maxCancelsPerSource())
	}
	return nil
}
