package custody

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"

	"github.com/ws4charlie/quorum-vault/internal/chain"
	"github.com/ws4charlie/quorum-vault/internal/chain/evm"
	"github.com/ws4charlie/quorum-vault/internal/ledger"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
)

// x402 payment authorizations. A hot wallet pays an x402 service by signing an EIP-3009 transferWithAuthorization that a facilitator submits on chain.
// Nothing leaves the wallet when it signs, and nothing may be forgotten: until the facilitator uses the authorization or it can no longer be used, it is
// a liability of the hot wallet. The books carry it as a hold on the ledger account x402:<chain>:<asset> (the hold's counter account is the hot account),
// and the table x402_authorizations says which holds are open and why. It ends in one of two ways, each seen on the chain and each booked once:
//
//   - used: the token emitted AuthorizationUsed(payer, nonce). The hold is posted: x402 -> hot, the amount that left the wallet. Reconcile explains the
//     window between the chain and this booking from the same events (reconcile_evm.go), so the hot wallet check stays exact at every step.
//   - expired: the final head's block time is at or past validBefore and no AuthorizationUsed was seen up to that head, so no block can ever include it.
//     The hold is voided and nothing else is booked: the money never moved.
//
// The signing zone is the authority on what may be signed (internal/chain/evm/eip3009.go, internal/gateway); this file builds the request the zone
// judges, books the liability, and settles it.

// x402Acct is the expense account of x402 payments of a token: the ledger's side of what the hot wallet paid to facilitators (negative: posted holds), and
// the holds on it are the authorizations still open.
func x402Acct(chain, asset string) string { return "x402:" + chain + ":" + asset }

// X402Account exposes the account to tests and tools.
func X402Account(chain, asset string) string { return x402Acct(chain, asset) }

// Statuses of an x402 authorization.
const (
	X402Requested = "requested" // the sign job is queued; the hold is booked
	X402Signed    = "signed"    // the zone signed it; the facilitator may use it
	X402Used      = "used"      // AuthorizationUsed seen: paid
	X402Expired   = "expired"   // past validBefore on a final block, never used: released
	X402Refused   = "refused"   // the zone refused or the job failed: released
)

// Errors of the x402 requests.
var (
	ErrX402NotConfigured = errors.New("custody: x402 is not configured for this asset")
	ErrX402Conflict      = errors.New("custody: x402 request id reused with a different request")
	// ErrX402InsufficientFunds: the paying shard's free balance (what freeHot says, open authorizations included) is below the amount.
	ErrX402InsufficientFunds = errors.New("custody: x402: insufficient free funds on the paying shard")
	// ErrX402Amount: the amount is not in (0, the token's per-payment limit].
	ErrX402Amount = errors.New("custody: x402: amount out of bounds")
	// ErrX402Window: the window is empty, too long, already over, or ends too far ahead of now.
	ErrX402Window = errors.New("custody: x402: window out of bounds")
	// ErrX402Payee: the payee is not an address.
	ErrX402Payee = errors.New("custody: x402: bad payee")
)

// X402Authorization is a row of x402_authorizations.
type X402Authorization struct {
	ID          string
	Chain       string
	Asset       string
	PartitionID string
	Payer       string
	Payee       string
	Amount      *big.Int
	ValidAfter  uint64
	ValidBefore uint64
	Nonce       string // 0x and 64 hex digits
	JobID       string
	SinceBlock  uint64
	Status      string
	UsedTx      string
	UsedBlock   uint64
	Reason      string
}

func (a X402Authorization) open() bool { return a.Status == X402Requested || a.Status == X402Signed }

const x402Cols = `id, chain, asset, partition_id, payer, payee, amount::text, valid_after, valid_before, nonce, job_id, since_block, status, COALESCE(used_tx,''), COALESCE(used_block,0), reason`

func scanX402(row pgx.Row) (X402Authorization, error) {
	var a X402Authorization
	var amt string
	var va, vb, sb, ub int64
	if err := row.Scan(&a.ID, &a.Chain, &a.Asset, &a.PartitionID, &a.Payer, &a.Payee, &amt, &va, &vb, &a.Nonce, &a.JobID, &sb, &a.Status, &a.UsedTx, &ub, &a.Reason); err != nil {
		return a, err
	}
	a.Amount, a.ValidAfter, a.ValidBefore, a.SinceBlock, a.UsedBlock = parseBig(amt), uint64(va), uint64(vb), uint64(sb), uint64(ub)
	return a, nil
}

// X402Request asks for one authorization. ID is the caller's idempotency key. Nonce may be left zero: the core then draws 32 random bytes (an x402
// client chooses its own; a caller that does passes it and gets the same request back on a retry).
type X402Request struct {
	ID          string
	Asset       string
	// Partition is the hot shard that pays (a hot partition of Asset on this chain). Empty: the token's configured x402 shard.
	Partition string
	// Credential is the Gate credential's text exactly as Gate sent it (docs/gate-credential.md). It travels to the zone in the job's intent and is
	// not part of what approvers sign. Empty for a caller that has none: a zone that needs one refuses.
	Credential []byte
	Payee       string
	Amount      *big.Int
	ValidAfter  uint64
	ValidBefore uint64
	Nonce       [32]byte
	// KeepNonce signs Nonce as given, all-zero included (the signing API: the nonce is the caller's). Without it a zero Nonce is drawn at random.
	KeepNonce bool
}

func (r X402Request) bodyHash(payee string) []byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("x402-v1|%s|%s|%s|%d|%d|%x", r.Asset, payee, r.Amount, r.ValidAfter, r.ValidBefore, r.Nonce)))
	return h[:]
}

// X402Intent is the intent of an authorization, the statement the zone judges the payload against. The intent id is the request id, so a retry is the
// same intent; the zone's replay guard holds the token nonce.
func (s *Service) x402Intent(a X402Authorization) signjob.Intent {
	return signjob.Intent{Kind: evm.KindEIP3009, ID: "x402:" + a.ID, PartitionID: a.PartitionID, Chain: a.Chain, Asset: a.Asset, To: a.Payee, Amount: a.Amount.String()}
}

// RequestX402 books the liability and queues the sign job of one authorization, in one transaction. It repeats harmlessly: the same id and request returns
// the existing row (created false); the same id with another request is ErrX402Conflict. The signing zone decides whether it is signed (X402Result).
func (s *Service) RequestX402(ctx context.Context, r X402Request) (a X402Authorization, created bool, err error) {
	c := s.Cfg
	x, ok := c.EVM.X402[r.Asset]
	if !ok || c.Family == FamilyBTC || c.Family == FamilySOL {
		return a, false, fmt.Errorf("%w: %q", ErrX402NotConfigured, r.Asset)
	}
	if r.ID == "" || strings.ContainsAny(r.ID, " \t\n") {
		return a, false, errors.New("custody: x402 request needs an id")
	}
	payee, err := NormalizeAddress(r.Payee)
	if err != nil {
		return a, false, fmt.Errorf("%w: %v", ErrX402Payee, err)
	}
	if r.Amount == nil || r.Amount.Sign() <= 0 || r.Amount.Cmp(x.PerPaymentLimit) > 0 {
		return a, false, fmt.Errorf("%w: %v must be in (0, %s]", ErrX402Amount, r.Amount, x.PerPaymentLimit)
	}
	body := r.bodyHash(payee)
	// An id that exists is answered first, whatever the clock says now: a retry after validBefore gets the stored row, another request under the id is a
	// conflict. The window is judged only for a new row.
	if ex, found, err := s.x402Existing(ctx, s.Pool, r.ID, body); err != nil || found {
		return ex, false, err
	}
	now := uint64(s.Now().Unix())
	if r.ValidBefore <= now || r.ValidBefore <= r.ValidAfter || r.ValidBefore-r.ValidAfter > x.MaxWindowSeconds || r.ValidBefore > now+x.MaxWindowSeconds {
		return a, false, fmt.Errorf("%w: (%d, %d) is not within %d s of now %d", ErrX402Window, r.ValidAfter, r.ValidBefore, x.MaxWindowSeconds, now)
	}
	nonce := r.Nonce
	if nonce == ([32]byte{}) && !r.KeepNonce {
		if _, err := rand.Read(nonce[:]); err != nil {
			return a, false, err
		}
	}
	part := c.PartitionKey(r.Asset, c.X402Shard[r.Asset]).String()
	if r.Partition != "" {
		if !c.isHotPartitionOf(r.Partition, r.Asset) {
			return a, false, fmt.Errorf("custody: x402: %q is not a hot shard of %s on this chain", r.Partition, r.Asset)
		}
		part = r.Partition
	}
	// The payer is the address of the shard's active key generation, as for every other payment, never the configured address.
	payerAddr, _, err := s.ShardAddressOf(part)
	if err != nil {
		return a, false, fmt.Errorf("custody: x402 payer: %w", err)
	}
	payer := common.HexToAddress(payerAddr)
	// Where the event search starts. Without it nothing is recorded: a stored 0 would read the chain from its first block.
	if s.Reader == nil {
		return a, false, errors.New("custody: x402: no chain reader to place the request")
	}
	since, err := s.Reader.SafeHead(ctx)
	if err != nil {
		return a, false, fmt.Errorf("custody: x402: read the final head (nothing recorded, retry): %w", err)
	}
	payload, digest, err := c.EVM.NewPayload3009(r.Asset, payer, common.HexToAddress(payee), r.Amount, r.ValidAfter, r.ValidBefore, nonce)
	if err != nil {
		return a, false, err
	}
	jobID := "x402:" + r.ID
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		created = false
		// The same lock the withdrawal path takes: reservations of one shard are serialized.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM partitions WHERE id=$1 FOR UPDATE`, part); err != nil {
			return err
		}
		if ex, found, err := s.x402Existing(ctx, tx, r.ID, body); err != nil || found {
			a = ex
			return err
		}
		free, err := s.freeHot(ctx, tx, part)
		if err != nil {
			return err
		}
		if free.Cmp(r.Amount) < 0 {
			return fmt.Errorf("%w: %s has %s free, the authorization needs %s", ErrX402InsufficientFunds, part, free, r.Amount)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO x402_authorizations (id, chain, asset, partition_id, payer, payee, amount, valid_after, valid_before, nonce, body_hash, job_id, since_block, status)
			VALUES ($1,$2,$3,$4,$5,$6,$7::numeric,$8,$9,$10,$11,$12,$13,'requested')`,
			r.ID, c.Chain, r.Asset, part, payer.Hex(), payee, r.Amount.String(), int64(r.ValidAfter), int64(r.ValidBefore), fmt.Sprintf("0x%x", nonce), body, jobID, int64(since)); err != nil {
			return err // another id with the same token nonce: the unique key says no
		}
		created = true
		if a, err = scanX402(tx.QueryRow(ctx, `SELECT `+x402Cols+` FROM x402_authorizations WHERE id=$1`, r.ID)); err != nil {
			return err
		}
		exp := time.Unix(int64(r.ValidBefore), 0).UTC()
		if err := s.Led.Hold(ctx, tx, ledger.HoldReq{ID: "x402-hold:" + r.ID, Account: x402Acct(c.Chain, r.Asset), CounterAccount: hotAcct(part),
			Amount: r.Amount, ExpiresAt: &exp, Metadata: map[string]any{"x402": r.ID, "payee": payee, "nonce": a.Nonce}}); err != nil {
			return err
		}
		ib, err := json.Marshal(intentWithCredential{Intent: s.x402Intent(a), Credential: string(r.Credential)})
		if err != nil {
			return err
		}
		u := chain.UnsignedTx{Chain: c.Chain, Digest: digest[:], Payload: payload, KeyRef: chain.KeyRef{PartitionID: part}}
		return EnqueueUnsigned(ctx, tx, jobID, part, u, ib, nil)
	})
	return a, created, err
}

// intentWithCredential is the intent of a job that carries a Gate credential: the credential's text beside the intent's fields, under the key the
// zone reads (signjob.Intent.Credential, added by the zone-enforcement task). It is not part of Intent.Canonical: no approver signs it. Omitted when
// empty, so a job without a credential has the bytes it always had.
type intentWithCredential struct {
	signjob.Intent
	Credential string `json:"Credential,omitempty"`
}

// isHotPartitionOf reports whether id is one of this chain's hot shards of asset.
func (c *Config) isHotPartitionOf(id, asset string) bool {
	for i := range c.HotShards {
		if c.PartitionKey(asset, i).String() == id {
			return true
		}
	}
	return false
}

// x402Existing returns the row of id when there is one: the same request gives the row, another request under the id is ErrX402Conflict.
func (s *Service) x402Existing(ctx context.Context, q booksQ, id string, body []byte) (X402Authorization, bool, error) {
	var same bool
	err := q.QueryRow(ctx, `SELECT body_hash=$2 FROM x402_authorizations WHERE id=$1`, id, body).Scan(&same)
	if errors.Is(err, pgx.ErrNoRows) {
		return X402Authorization{}, false, nil
	}
	if err != nil {
		return X402Authorization{}, false, err
	}
	if !same {
		return X402Authorization{}, false, fmt.Errorf("%w: %s", ErrX402Conflict, id)
	}
	a, err := scanX402(q.QueryRow(ctx, `SELECT `+x402Cols+` FROM x402_authorizations WHERE id=$1`, id))
	return a, true, err
}

// X402Result is what the zone made of an authorization. When Status is X402Signed, R, S and V are the signature in the form EIP-3009 and x402 expect
// (r and s big-endian 32 bytes, s low, v 27 or 28), and the authorization is the typed data of Authorization.
type X402Result struct {
	X402Authorization
	R, S [32]byte
	V    byte
}

// X402 returns an authorization and, if its job is done, the signature; it first moves the row along: a job the zone refused releases the hold (refused),
// a job that is done makes the row signed. It repeats harmlessly.
func (s *Service) X402(ctx context.Context, id string) (X402Result, error) {
	var out X402Result
	a, err := scanX402(s.Pool.QueryRow(ctx, `SELECT `+x402Cols+` FROM x402_authorizations WHERE id=$1`, id))
	if err != nil {
		return out, err
	}
	out.X402Authorization = a
	if a.Status != X402Requested && a.Status != X402Signed && a.Status != X402Used {
		return out, nil
	}
	job, err := signjob.Get(ctx, s.Pool, a.JobID)
	if err != nil {
		return out, err
	}
	switch job.Status {
	case signjob.StatusRejected, signjob.StatusFailed:
		if a.Status == X402Requested {
			if err := s.x402Release(ctx, id, X402Refused, "the signing zone refused it: "+job.RejectReason); err != nil {
				return out, err
			}
			out.Status, out.Reason = X402Refused, "the signing zone refused it: "+job.RejectReason
		}
	case signjob.StatusDone:
		var digest [32]byte
		copy(digest[:], job.Digest)
		sig := signer.Signature{R: new(big.Int).SetBytes(job.Signature[:32]), S: new(big.Int).SetBytes(job.Signature[32:])}
		if out.R, out.S, out.V, err = evm.SignatureRSVFor(digest, sig, common.HexToAddress(a.Payer)); err != nil {
			return out, err
		}
		if a.Status == X402Requested {
			if _, err := s.Pool.Exec(ctx, `UPDATE x402_authorizations SET status='signed', updated_at=now() WHERE id=$1 AND status='requested'`, id); err != nil {
				return out, err
			}
			out.Status = X402Signed
		}
	}
	return out, nil
}

// x402Release ends an open authorization without a payment: its hold is voided and the row takes status (expired or refused). It does nothing if the row
// is no longer open (a repeat, or a payment that was seen first).
func (s *Service) x402Release(ctx context.Context, id, status, reason string) error {
	return InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		a, err := scanX402(tx.QueryRow(ctx, `SELECT `+x402Cols+` FROM x402_authorizations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if !a.open() {
			return nil
		}
		if err := s.Led.Void(ctx, tx, "x402-hold:"+id, "x402-void:"+id); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE x402_authorizations SET status=$2, reason=$3, updated_at=now() WHERE id=$1`, id, status, reason)
		return err
	})
}

// x402Pay books a payment the chain showed: the open authorization's hold is posted (x402 -> hot). A row that is not open is left alone, so the same
// event seen twice books once. (An authorization released as expired that is then used would be a real difference between the books and the chain, and
// Reconcile reports it: the expiry rule makes it impossible, and the books are not bent to hide it.)
func (s *Service) x402Pay(ctx context.Context, id string, ev UsedAuthorization) (booked bool, err error) {
	err = InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		booked = false
		a, err := scanX402(tx.QueryRow(ctx, `SELECT `+x402Cols+` FROM x402_authorizations WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if !a.open() {
			return nil
		}
		if err := s.Led.Post(ctx, tx, "x402-hold:"+id, "x402-post:"+id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE x402_authorizations SET status='used', used_tx=$2, used_block=$3, updated_at=now() WHERE id=$1`, id, ev.TxHash, int64(ev.Block)); err != nil {
			return err
		}
		booked = true
		return nil
	})
	return booked, err
}

// UsedAuthorization is one AuthorizationUsed event of a token for a payer.
type UsedAuthorization struct {
	Nonce  string // 0x and 64 hex digits
	Block  uint64
	TxHash string
}

// AuthorizationReader is implemented by a Reader that can read the AuthorizationUsed events of a token and the time of a block. EVMReader has it.
type AuthorizationReader interface {
	// AuthorizationsUsed returns the AuthorizationUsed events of the configured token asset for payer in blocks [from, to].
	AuthorizationsUsed(ctx context.Context, asset, payer string, from, to uint64) ([]UsedAuthorization, error)
	// BlockTime is the timestamp (seconds) of the block at height.
	BlockTime(ctx context.Context, height uint64) (uint64, error)
}

// x402Open reads the open authorizations of the chain, oldest first.
func (s *Service) x402Open(ctx context.Context, q booksQ) ([]X402Authorization, error) {
	rows, err := q.Query(ctx, `SELECT `+x402Cols+` FROM x402_authorizations WHERE chain=$1 AND status IN ('requested','signed') ORDER BY created_at, id`, s.Cfg.Chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []X402Authorization
	for rows.Next() {
		a, err := scanX402(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// x402Events reads, for each payer and token of the given authorizations, the
// AuthorizationUsed events in [the oldest since_block, upTo], and returns the ones that name the nonce of a row, by row id.
func (s *Service) x402Events(ctx context.Context, ar AuthorizationReader, rows []X402Authorization, upTo uint64) (map[string]UsedAuthorization, error) {
	type key struct{ asset, payer string }
	from := map[key]uint64{}
	for _, a := range rows {
		k := key{a.Asset, a.Payer}
		if f, ok := from[k]; !ok || a.SinceBlock < f {
			from[k] = a.SinceBlock
		}
	}
	keys := make([]key, 0, len(from))
	for k := range from {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].asset+keys[i].payer < keys[j].asset+keys[j].payer })
	byNonce := map[string]UsedAuthorization{}
	for _, k := range keys {
		if from[k] > upTo {
			continue
		}
		evs, err := ar.AuthorizationsUsed(ctx, k.asset, k.payer, from[k], upTo)
		if err != nil {
			return nil, err
		}
		for _, e := range evs {
			byNonce[k.asset+"|"+strings.ToLower(k.payer)+"|"+e.Nonce] = e
		}
	}
	out := map[string]UsedAuthorization{}
	for _, a := range rows {
		if e, ok := byNonce[a.Asset+"|"+strings.ToLower(a.Payer)+"|"+a.Nonce]; ok && e.Block >= a.SinceBlock {
			out[a.ID] = e
		}
	}
	return out, nil
}

// X402Settled is what one pass of SettleX402 did.
type X402Settled struct {
	Used, Expired, Refused int
}

// SettleX402 is the worker's pass over the open authorizations, up to the final head. For each: a job the zone refused is released; a payment the token
// recorded (AuthorizationUsed with its nonce) is booked; one that was not paid and whose validBefore the final head's block time has reached is released,
// because no later block can include it. It repeats harmlessly, and it books the same event once however often it sees it.
func (s *Service) SettleX402(ctx context.Context) (X402Settled, error) {
	var res X402Settled
	if len(s.Cfg.EVM.X402) == 0 {
		return res, nil
	}
	ar, ok := s.Reader.(AuthorizationReader)
	if !ok {
		return res, errors.New("custody: x402: this chain reader cannot read AuthorizationUsed events")
	}
	open, err := s.x402Open(ctx, s.Pool)
	if err != nil {
		return res, err
	}
	if len(open) == 0 {
		return res, nil
	}
	for _, a := range open { // a refusal is known from the job, whatever the chain says
		if a.Status == X402Requested {
			r, err := s.X402(ctx, a.ID)
			if err != nil {
				return res, err
			}
			if r.Status == X402Refused {
				res.Refused++
			}
		}
	}
	if open, err = s.x402Open(ctx, s.Pool); err != nil {
		return res, err
	}
	head, err := s.Reader.SafeHead(ctx)
	if err != nil {
		return res, err
	}
	used, err := s.x402Events(ctx, ar, open, head)
	if err != nil {
		return res, err
	}
	headTime, haveTime := uint64(0), false
	for _, a := range open {
		if ev, ok := used[a.ID]; ok {
			booked, err := s.x402Pay(ctx, a.ID, ev)
			if err != nil {
				return res, err
			}
			if booked {
				res.Used++
			}
			continue
		}
		if !haveTime {
			if headTime, err = ar.BlockTime(ctx, head); err != nil {
				return res, err
			}
			haveTime = true
		}
		if headTime >= a.ValidBefore {
			if err := s.x402Release(ctx, a.ID, X402Expired, fmt.Sprintf("validBefore %d reached by the final block %d (time %d) without a payment", a.ValidBefore, head, headTime)); err != nil {
				return res, err
			}
			res.Expired++
		}
	}
	return res, nil
}

// x402Pending is Reconcile's part: what the books lack for the authorizations the chain has shown paid at or below h and the books have not booked
// yet, put on the books' side exactly as x402Pay would book it (x402 -> hot).
func (s *Service) x402Pending(ctx context.Context, q booksQ, rr any, h uint64, a *evmAdj) (reason string, err error) {
	open, err := s.x402Open(ctx, q)
	if err != nil || len(open) == 0 {
		return "", err
	}
	ar, ok := rr.(AuthorizationReader)
	if !ok {
		return "the chain reader cannot read AuthorizationUsed events, so the open x402 authorizations cannot be explained", nil
	}
	used, err := s.x402Events(ctx, ar, open, h)
	if err != nil {
		return "", err
	}
	for _, x := range open {
		if _, ok := used[x.ID]; ok {
			a.mined++
			a.move(x402Acct(x.Chain, x.Asset), hotAcct(x.PartitionID), x.Amount)
		}
	}
	return "", nil
}

// RunX402 is the worker's loop: SettleX402 (and PruneGateRequests) every interval until ctx ends. A failed pass is logged and tried again; the pass repeats harmlessly.
func (s *Service) RunX402(ctx context.Context, interval time.Duration, log *slog.Logger) {
	if len(s.Cfg.EVM.X402) == 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if res, err := s.SettleX402(ctx); err != nil {
			log.Error("x402 settle pass failed", "error", err.Error())
		} else if res != (X402Settled{}) {
			log.Info("x402 authorizations settled", "used", res.Used, "expired", res.Expired, "refused", res.Refused)
		}
		// The signing API's request rows (gate.go) are pruned in the same pass: the API serves only x402 authorizations.
		if n, err := s.PruneGateRequests(ctx); err != nil {
			log.Error("gate request pruning failed", "error", err.Error())
		} else if n > 0 {
			log.Info("gate requests pruned", "rows", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
