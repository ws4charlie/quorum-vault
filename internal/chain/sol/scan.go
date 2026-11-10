package sol

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// What counts as a deposit. A deposit is a transfer instruction (top level or inner, so a payment made through another program counts) in
// a transaction that succeeded and is finalized:
//   - SOL: a System Program transfer (or transferWithSeed) whose destination is a deposit address.
//   - SPL: a classic Token program transfer or transferChecked whose destination is the ATA of a deposit address for a configured mint.
//     Tokens sent to any other token account owned by the address are NOT credited (that account is not the one customers are told to
//     use, and the scanner does not follow accounts it was not told about): Balance notices them and raises an ALERT, an operator decides.
//     Tokens of another mint, and Token-2022 tokens, are never credited.
// A failed transaction changes no balance and is skipped (a SOL transfer below the rent-exempt minimum to an address that does not exist
// yet fails on chain, so it is never seen as a deposit). The dedup key is chain:signature:instruction:inner-instruction ("-" at the top level).

// ataInfo says which owner and asset a watched token account belongs to.
type ataInfo struct {
	owner, symbol string
}

// Scan reads the deposits that finalized in slots [fromHeight, finalized head], for every deposit address and its ATAs. Heights are slots.
func (a *Adapter) Scan(ctx context.Context, fromHeight uint64) (chain.ScanResult, error) {
	safe, err := a.rpc.Slot(ctx, Finalized) // before the watch list is read: an address created after this cannot have been paid in a slot at or below it
	if err != nil {
		return chain.ScanResult{}, err
	}
	if safe < fromHeight {
		if fromHeight == 0 {
			return chain.ScanResult{}, nil
		}
		return chain.ScanResult{SafeHeadHeight: fromHeight - 1}, nil
	}
	owners, err := a.watched(ctx)
	if err != nil {
		return chain.ScanResult{}, err
	}
	w, err := a.watchSet(owners)
	if err != nil {
		return chain.ScanResult{}, err
	}
	sigs := map[string]uint64{}
	for addr := range w.accounts {
		infos, err := a.signaturesSince(ctx, addr, fromHeight, safe)
		if err != nil {
			return chain.ScanResult{}, err
		}
		for _, s := range infos {
			sigs[s.Signature] = s.Slot
		}
	}
	order := make([]string, 0, len(sigs))
	for s := range sigs {
		order = append(order, s)
	}
	sort.Slice(order, func(i, j int) bool {
		if sigs[order[i]] != sigs[order[j]] {
			return sigs[order[i]] < sigs[order[j]]
		}
		return order[i] < order[j]
	})
	var res chain.ScanResult
	for _, sig := range order {
		tx, err := a.rpc.GetTransaction(ctx, sig)
		if err != nil {
			return chain.ScanResult{}, err
		}
		if tx == nil {
			return chain.ScanResult{}, fmt.Errorf("sol: finalized transaction %s is not available from the node yet", sig)
		}
		ds, err := ParseDeposits(a.cfg.Chain, sig, tx, w.owners, w.atas)
		if err != nil {
			return chain.ScanResult{}, err
		}
		res.Deposits = append(res.Deposits, ds...)
	}
	res.SafeHeadHeight = safe
	return res, nil
}

// signaturesSince lists the successful signatures of address with slots in [from, to], paging backwards.
func (a *Adapter) signaturesSince(ctx context.Context, address string, from, to uint64) ([]SigInfo, error) {
	var out []SigInfo
	before := ""
	for {
		page, err := a.rpc.Signatures(ctx, address, Finalized, before, 1000)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return out, nil
		}
		for _, s := range page {
			if s.Slot < from {
				return out, nil
			}
			if s.Slot > to || (len(s.Err) > 0 && string(s.Err) != "null") {
				continue
			}
			out = append(out, s)
		}
		if len(page) < 1000 {
			return out, nil
		}
		before = page[len(page)-1].Signature
	}
}

type watchSet struct {
	owners   map[string]bool
	atas     map[string]ataInfo
	accounts map[string]bool // owners and ATAs: the addresses whose signatures are listed
}

func (a *Adapter) watchSet(owners []string) (watchSet, error) {
	w := watchSet{owners: map[string]bool{}, atas: map[string]ataInfo{}, accounts: map[string]bool{}}
	for _, o := range owners {
		raw, err := ParseAddress(o)
		if err != nil {
			return w, err
		}
		w.owners[o] = true
		w.accounts[o] = true
		for _, m := range a.cfg.mints {
			ata, err := ATA(raw, m.raw)
			if err != nil {
				return w, err
			}
			s := Address(ata)
			w.atas[s] = ataInfo{owner: o, symbol: m.symbol}
			w.accounts[s] = true
		}
	}
	return w, nil
}

func decodeParsed(raw json.RawMessage) (Parsed, bool) {
	var p Parsed
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &p) != nil {
		return p, false
	}
	return p, true
}

// ParseDeposits extracts the deposits one finalized transaction makes to the watched owners and token accounts. A failed transaction yields none.
func ParseDeposits(chainName, sig string, tx *Transaction, owners map[string]bool, atas map[string]ataInfo) ([]chain.ObservedDeposit, error) {
	if tx.Meta == nil {
		return nil, fmt.Errorf("sol: transaction %s has no meta", sig)
	}
	if len(tx.Meta.Err) > 0 && string(tx.Meta.Err) != "null" {
		return nil, nil
	}
	var out []chain.ObservedDeposit
	visit := func(ix int, inner string, in Instruction) error {
		p, ok := decodeParsed(in.Parsed)
		if !ok {
			return nil
		}
		key := fmt.Sprintf("%s:%s:%d:%s", chainName, sig, ix, inner)
		var info struct {
			Source      string          `json:"source"`
			Destination string          `json:"destination"`
			Lamports    json.Number     `json:"lamports"`
			Amount      string          `json:"amount"`
			Mint        string          `json:"mint"`
			TokenAmount json.RawMessage `json:"tokenAmount"`
		}
		if err := json.Unmarshal(p.Info, &info); err != nil {
			return nil
		}
		switch {
		case in.ProgramID == SystemProgram && (p.Type == "transfer" || p.Type == "transferWithSeed"):
			if !owners[info.Destination] || info.Source == info.Destination {
				return nil
			}
			n, ok := new(big.Int).SetString(info.Lamports.String(), 10)
			if !ok || n.Sign() <= 0 {
				return nil
			}
			out = append(out, chain.ObservedDeposit{Chain: chainName, Asset: Native, Address: info.Destination, Amount: n, BlockHeight: tx.Slot, TxHash: sig, DedupKey: key})
		case in.ProgramID == TokenProgram && (p.Type == "transfer" || p.Type == "transferChecked"):
			t, ok := atas[info.Destination]
			if !ok || info.Source == info.Destination {
				return nil
			}
			amt := info.Amount
			if p.Type == "transferChecked" {
				var ta struct {
					Amount string `json:"amount"`
				}
				if json.Unmarshal(info.TokenAmount, &ta) != nil {
					return nil
				}
				amt = ta.Amount
			}
			n, ok := new(big.Int).SetString(amt, 10)
			if !ok || n.Sign() <= 0 {
				return nil
			}
			out = append(out, chain.ObservedDeposit{Chain: chainName, Asset: t.symbol, Address: t.owner, Amount: n, BlockHeight: tx.Slot, TxHash: sig, DedupKey: key})
		}
		return nil
	}
	for i, in := range tx.Transaction.Message.Instructions {
		if err := visit(i, "-", in); err != nil {
			return nil, err
		}
	}
	for _, g := range tx.Meta.InnerInstructions {
		for j, in := range g.Instructions {
			if err := visit(g.Index, strconv.Itoa(j), in); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}
