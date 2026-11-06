package btc

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// MaxMove is the most a hot-to-cold move from the partition can carry now: the oldest available hot outputs, at most max_inputs of them, minus the
// fee of a transaction with that many inputs and two outputs (the payment and the change). An output reserved by a withdrawal is not available, so a
// move never takes one. Zero (or less than dust) means nothing can be moved yet.
func (a *Adapter) MaxMove(ctx context.Context, partitionID string) (*big.Int, error) {
	sh, err := a.shardOf(partitionID)
	if err != nil {
		return nil, err
	}
	rows, err := a.pool.Query(ctx, `SELECT value FROM btc_utxos WHERE chain=$1 AND partition_id=$2 AND status='available' AND NOT deposit
		ORDER BY created_at, txid, vout LIMIT $3`, a.cfg.Chain, partitionID, a.cfg.MaxInputs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	n, sum := 0, uint64(0)
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		n++
		sum += uint64(v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if n == 0 {
		return new(big.Int), nil
	}
	// The cold address may be a script as large as P2WSH (34 bytes): size the payment output for it.
	fee := vsize(n, sh.script, make([]byte, 34)) * a.feeRate(ctx)
	if sum <= fee {
		return new(big.Int), nil
	}
	return new(big.Int).SetUint64(sum - fee), nil
}

// unspent is one output of the node's UTXO set.
type unspent struct {
	Txid   string      `json:"txid"`
	Vout   uint32      `json:"vout"`
	Desc   string      `json:"desc"`
	Amount json.Number `json:"amount"`
	Height int64       `json:"height"`
}

func (u unspent) address() string {
	d := strings.TrimPrefix(u.Desc, "addr(")
	if i := strings.Index(d, ")"); i >= 0 {
		return d[:i]
	}
	return ""
}

// scanBatch is how many addresses one scantxoutset call reads: the node is busy for the whole call, so the work is cut into bounded pieces.
const scanBatch = 100

// scan reads the node's UTXO set for the addresses (scantxoutset, at the node's tip, not from our tables) and returns the unspent outputs and the
// height it read.
func (a *Adapter) scan(ctx context.Context, addrs []string) ([]unspent, int64, error) {
	var out []unspent
	var height int64
	for i := 0; i < len(addrs); i += scanBatch {
		j := min(i+scanBatch, len(addrs))
		objs := make([]string, 0, j-i)
		for _, ad := range addrs[i:j] {
			objs = append(objs, "addr("+ad+")")
		}
		var res struct {
			Success  bool      `json:"success"`
			Height   int64     `json:"height"`
			Unspents []unspent `json:"unspents"`
		}
		if err := a.rpc.Call(ctx, &res, "scantxoutset", "start", objs); err != nil {
			return nil, 0, err
		}
		if !res.Success {
			return nil, 0, fmt.Errorf("btc: scantxoutset did not finish")
		}
		height = res.Height
		out = append(out, res.Unspents...)
	}
	return out, height, nil
}

// settledDepth is how deep an output must be before the books count it, by how the books learn of it: change and sweep outputs of our own
// transactions at the spend depth, anything else (deposits, operator funding) at the deposit depth.
func (a *Adapter) settledDepths(ctx context.Context, us []unspent) (map[string]bool, error) {
	ids := map[string]bool{}
	for _, u := range us {
		ids[u.Txid] = true
	}
	own := map[string]bool{}
	if len(ids) == 0 {
		return own, nil
	}
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	rows, err := a.pool.Query(ctx, `SELECT txid FROM btc_attempts WHERE chain=$1 AND txid = ANY($2)`, a.cfg.Chain, list)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		own[id] = true
	}
	return own, rows.Err()
}

// settled reports whether the books should already count u at tip.
func (a *Adapter) settled(u unspent, tip int64, own map[string]bool) bool {
	need := int64(a.cfg.Confirmations)
	if own[u.Txid] {
		need = int64(a.cfg.SpendConfirmations)
	}
	return u.Height > 0 && tip-u.Height+1 >= need
}

// BalanceBatch is the chain's balance, in satoshis, of each address: the sum of its unspent outputs that the books should count by now (see
// settled), read with scantxoutset at the node's tip. It returns the tip height it read. It does not use our output table, so a difference between the
// two is visible. The node is busy during a read: callers batch addresses and run this on their own cadence, never on a request path.
func (a *Adapter) BalanceBatch(ctx context.Context, addrs []string) (map[string]*big.Int, uint64, error) {
	canon := make([]string, 0, len(addrs))
	for _, ad := range addrs {
		c, err := a.NormalizeAddress(ad)
		if err != nil {
			return nil, 0, err
		}
		canon = append(canon, c)
	}
	us, tip, err := a.scan(ctx, canon)
	if err != nil {
		return nil, 0, err
	}
	own, err := a.settledDepths(ctx, us)
	if err != nil {
		return nil, 0, err
	}
	out := map[string]*big.Int{}
	for _, c := range canon {
		out[c] = new(big.Int)
	}
	for _, u := range us {
		if !a.settled(u, tip, own) {
			continue
		}
		amt, err := Sats(u.Amount.String())
		if err != nil {
			return nil, 0, err
		}
		if b, ok := out[u.address()]; ok {
			b.Add(b, amt)
		}
	}
	return out, uint64(tip), nil
}

// Balance of one address (see BalanceBatch); the height argument is not used: the read is at the node's tip.
func (a *Adapter) Balance(ctx context.Context, address, asset string, _ uint64) (*big.Int, error) {
	if asset != Native {
		return nil, fmt.Errorf("btc: unknown asset %q", asset)
	}
	m, _, err := a.BalanceBatch(ctx, []string{address})
	if err != nil {
		return nil, err
	}
	c, _ := a.NormalizeAddress(address)
	return m[c], nil
}

// ChainView reads the node's UTXO set for the addresses and puts it in the terms of the books (see chain.ChainView). A table row whose output is gone
// from the chain is explained when a confirmed transaction of ours spends it (btc_attempts holds every transaction we sent, with its inputs); an
// unspent output that is not in the table is explained when it is an output of a transaction of ours (not settled yet) or younger than the credit
// depth. A deposit output of a customer that nothing explains, a hot output that is not in the table, a differing value or a missing row nothing
// explains are returned as differences. It changes nothing.
func (a *Adapter) ChainView(ctx context.Context, addrs []string) (chain.ChainView, error) {
	set := map[string]bool{}
	canon := make([]string, 0, len(addrs))
	add := func(ad string) {
		if ad != "" && !set[ad] {
			set[ad] = true
			canon = append(canon, ad)
		}
	}
	for _, ad := range addrs {
		c, err := a.NormalizeAddress(ad)
		if err != nil {
			return chain.ChainView{}, err
		}
		add(c)
	}
	for _, sh := range a.shards {
		add(sh.address)
	}
	type row struct {
		txid    string
		vout    uint32
		value   int64
		status  string
		deposit bool
		address string
	}
	rows, err := a.pool.Query(ctx, `SELECT txid, vout, value, status, deposit, COALESCE(address,''), partition_id FROM btc_utxos WHERE chain=$1 AND status IN ('available','reserved')`, a.cfg.Chain)
	if err != nil {
		return chain.ChainView{}, err
	}
	var table []row
	for rows.Next() {
		var r row
		var part string
		if err := rows.Scan(&r.txid, &r.vout, &r.value, &r.status, &r.deposit, &r.address, &part); err != nil {
			rows.Close()
			return chain.ChainView{}, err
		}
		if !r.deposit {
			sh, err := a.shardOf(part)
			if err != nil {
				rows.Close()
				return chain.ChainView{}, err
			}
			r.address = sh.address
		}
		add(r.address)
		table = append(table, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return chain.ChainView{}, err
	}
	sort.Strings(canon)
	us, tip, err := a.scan(ctx, canon)
	if err != nil {
		return chain.ChainView{}, err
	}
	own, err := a.ownTxids(ctx, us)
	if err != nil {
		return chain.ChainView{}, err
	}
	ours, err := a.settledDepths(ctx, us) // every transaction of ours, settled or not
	if err != nil {
		return chain.ChainView{}, err
	}
	onChain := map[string]unspent{}
	for _, u := range us {
		onChain[fmt.Sprintf("%s:%d", u.Txid, u.Vout)] = u
	}
	v := chain.ChainView{Height: uint64(tip), Balance: map[string]*big.Int{}, SpentInFlight: map[string]*big.Int{}}
	for _, ad := range canon {
		v.Balance[ad] = new(big.Int)
		v.SpentInFlight[ad] = new(big.Int)
	}
	inTable := map[string]bool{}
	for _, r := range table {
		k := fmt.Sprintf("%s:%d", r.txid, r.vout)
		inTable[k] = true
		u, ok := onChain[k]
		if !ok {
			spent, err := a.spentByConfirmedAttempt(ctx, r.txid, r.vout)
			if err != nil {
				return chain.ChainView{}, err
			}
			if spent {
				v.SpentInFlight[r.address].Add(v.SpentInFlight[r.address], big.NewInt(r.value))
				continue
			}
			v.Diffs = append(v.Diffs, chain.OutputDiff{Address: r.address, Output: k,
				Detail: fmt.Sprintf("the table holds %d sats (%s) but the output is not unspent on chain and no confirmed transaction of ours spent it", r.value, r.status)})
			continue
		}
		amt, err := Sats(u.Amount.String())
		if err != nil {
			return chain.ChainView{}, err
		}
		if amt.Int64() != r.value {
			v.Diffs = append(v.Diffs, chain.OutputDiff{Address: r.address, Output: k, Detail: fmt.Sprintf("the table holds %d sats, the chain %s", r.value, amt)})
		}
		v.Balance[r.address].Add(v.Balance[r.address], amt)
	}
	for _, u := range us {
		k := fmt.Sprintf("%s:%d", u.Txid, u.Vout)
		if inTable[k] {
			continue
		}
		ad := u.address()
		if own[u.Txid] || (!ours[u.Txid] && tip-u.Height+1 < int64(a.cfg.Confirmations)) {
			v.Unsettled++ // an output of ours the books record at settlement, or a payment not yet deep enough to credit
			continue
		}
		amt, err := Sats(u.Amount.String())
		if err != nil {
			return chain.ChainView{}, err
		}
		if b, ok := v.Balance[ad]; ok {
			b.Add(b, amt)
		}
		if _, hot := a.byAddr[ad]; hot {
			v.Diffs = append(v.Diffs, chain.OutputDiff{Address: ad, Output: k, Detail: "an unspent output on a hot address that the table does not hold"})
			continue
		}
		var known bool
		if err := a.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM deposits WHERE chain=$1 AND dedup_key=$2) OR NOT EXISTS (SELECT 1 FROM deposit_addresses WHERE chain=$1 AND address=$3)`,
			a.cfg.Chain, a.cfg.Chain+":"+k, ad).Scan(&known); err != nil {
			return chain.ChainView{}, err
		}
		if !known { // on a customer's deposit address, old enough, and no deposit of ours explains it (a suspense deposit does): the scan has not seen it
			v.Diffs = append(v.Diffs, chain.OutputDiff{Address: ad, Output: k, Detail: "an unspent output on a deposit address that no deposit of ours explains"})
		}
	}
	sort.Slice(v.Diffs, func(i, j int) bool { return v.Diffs[i].Output < v.Diffs[j].Output })
	return v, nil
}

// ownTxids returns which of the unspent outputs' transactions are transactions of ours that the books have not settled yet.
func (a *Adapter) ownTxids(ctx context.Context, us []unspent) (map[string]bool, error) {
	ids := map[string]bool{}
	for _, u := range us {
		ids[u.Txid] = true
	}
	own := map[string]bool{}
	if len(ids) == 0 {
		return own, nil
	}
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	rows, err := a.pool.Query(ctx, `SELECT txid FROM btc_attempts WHERE chain=$1 AND txid = ANY($2) AND settled_at IS NULL`, a.cfg.Chain, list)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		own[id] = true
	}
	return own, rows.Err()
}

// spentByConfirmedAttempt reports whether a transaction of ours that is in a block spends the output.
func (a *Adapter) spentByConfirmedAttempt(ctx context.Context, txid string, vout uint32) (bool, error) {
	probe, _ := json.Marshal([]map[string]any{{"txid": txid, "vout": vout}})
	rows, err := a.pool.Query(ctx, `SELECT txid FROM btc_attempts WHERE chain=$1 AND broadcast_at IS NOT NULL AND payload->'inputs' @> $2::jsonb`, a.cfg.Chain, string(probe))
	if err != nil {
		return false, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return false, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, id := range ids {
		n, err := a.confirmations(ctx, id)
		if err != nil {
			return false, err
		}
		if n >= 1 {
			return true, nil
		}
	}
	return false, nil
}

var (
	_ chain.MoveCapacity = (*Adapter)(nil)
	_ chain.ChainViewer  = (*Adapter)(nil)
)
