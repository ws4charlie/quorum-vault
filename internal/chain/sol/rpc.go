package sol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// RPC is a plain JSON-RPC 2.0 client for a Solana node. Every read that decides money names its commitment.
type RPC struct {
	url string
	hc  *http.Client
	id  atomic.Int64
}

// NewRPC returns a client for url.
func NewRPC(url string) *RPC { return &RPC{url: url, hc: &http.Client{Timeout: 60 * time.Second}} }

// RPCError is an error answer of the node.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Method  string `json:"-"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("sol rpc %s: %s (%d)", e.Method, e.Message, e.Code)
}

// Call runs method and decodes its result into out (nil: ignore).
func (r *RPC) Call(ctx context.Context, out any, method string, params ...any) error {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": r.id.Add(1), "method": method, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.hc.Do(req)
	if err != nil {
		return fmt.Errorf("sol rpc %s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("sol rpc %s: %w", method, err)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *RPCError       `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("sol rpc %s: HTTP %d: %.200s", method, resp.StatusCode, raw)
	}
	if env.Error != nil {
		env.Error.Method = method
		return env.Error
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

// Finalized and Confirmed are the two commitments the cell uses: finalized (rooted) for crediting and balances, confirmed for "seen".
const (
	Finalized = "finalized"
	Confirmed = "confirmed"
)

type commitment struct {
	Commitment string `json:"commitment"`
}

// Slot is the highest slot at a commitment.
func (r *RPC) Slot(ctx context.Context, c string) (uint64, error) {
	var n uint64
	return n, r.Call(ctx, &n, "getSlot", commitment{c})
}

// SigInfo is one entry of getSignaturesForAddress.
type SigInfo struct {
	Signature string          `json:"signature"`
	Slot      uint64          `json:"slot"`
	Err       json.RawMessage `json:"err"`
}

// Signatures lists signatures that involve address at a commitment, newest first, before `before` (empty: from the tip).
func (r *RPC) Signatures(ctx context.Context, address, c, before string, limit int) ([]SigInfo, error) {
	opt := map[string]any{"commitment": c, "limit": limit}
	if before != "" {
		opt["before"] = before
	}
	var out []SigInfo
	return out, r.Call(ctx, &out, "getSignaturesForAddress", address, opt)
}

// Instruction is one instruction of a transaction in the node's jsonParsed form. Parsed is set for programs the node knows
// (system, spl-token).
type Instruction struct {
	Program   string          `json:"program"`
	ProgramID string          `json:"programId"`
	Parsed    json.RawMessage `json:"parsed"`
}

// Parsed is the parsed body of an instruction.
type Parsed struct {
	Type string          `json:"type"`
	Info json.RawMessage `json:"info"`
}

// Transaction is the part of getTransaction (jsonParsed) the scanner reads.
type Transaction struct {
	Slot uint64 `json:"slot"`
	Meta *struct {
		Err               json.RawMessage `json:"err"`
		Fee               uint64          `json:"fee"`
		PreBalances       []uint64        `json:"preBalances"`
		PostBalances      []uint64        `json:"postBalances"`
		InnerInstructions []struct {
			Index        int           `json:"index"`
			Instructions []Instruction `json:"instructions"`
		} `json:"innerInstructions"`
		PostTokenBalances []TokenBalance `json:"postTokenBalances"`
		PreTokenBalances  []TokenBalance `json:"preTokenBalances"`
	} `json:"meta"`
	Transaction struct {
		Message struct {
			Instructions []Instruction `json:"instructions"`
			AccountKeys  []struct {
				Pubkey string `json:"pubkey"`
			} `json:"accountKeys"`
		} `json:"message"`
		Signatures []string `json:"signatures"`
	} `json:"transaction"`
}

// TokenBalance is an entry of pre/postTokenBalances.
type TokenBalance struct {
	AccountIndex int    `json:"accountIndex"`
	Mint         string `json:"mint"`
	Owner        string `json:"owner"`
}

// GetTransaction reads one finalized transaction, parsed. A nil result means the node does not have it (yet).
func (r *RPC) GetTransaction(ctx context.Context, sig string) (*Transaction, error) {
	var tx *Transaction
	err := r.Call(ctx, &tx, "getTransaction", sig, map[string]any{"encoding": "jsonParsed", "commitment": Finalized, "maxSupportedTransactionVersion": 0})
	return tx, err
}

// Lamports is the balance of an account at a commitment and the slot it was read at.
func (r *RPC) Lamports(ctx context.Context, address, c string) (uint64, uint64, error) {
	var out struct {
		Context struct {
			Slot uint64 `json:"slot"`
		} `json:"context"`
		Value uint64 `json:"value"`
	}
	err := r.Call(ctx, &out, "getBalance", address, commitment{c})
	return out.Value, out.Context.Slot, err
}

// TokenAccount is a token account of an owner.
type TokenAccount struct {
	Pubkey  string
	Mint    string
	Amount  uint64
	Decimal int
}

// TokenAccountsByOwner lists the owner's token accounts of the classic Token program at a commitment, optionally of one mint.
func (r *RPC) TokenAccountsByOwner(ctx context.Context, owner, mint, c string) ([]TokenAccount, error) {
	filter := map[string]any{"programId": TokenProgram}
	if mint != "" {
		filter = map[string]any{"mint": mint}
	}
	var out struct {
		Value []struct {
			Pubkey  string `json:"pubkey"`
			Account struct {
				Data struct {
					Parsed struct {
						Info struct {
							Mint        string `json:"mint"`
							TokenAmount struct {
								Amount   string `json:"amount"`
								Decimals int    `json:"decimals"`
							} `json:"tokenAmount"`
						} `json:"info"`
					} `json:"parsed"`
				} `json:"data"`
			} `json:"account"`
		} `json:"value"`
	}
	if err := r.Call(ctx, &out, "getTokenAccountsByOwner", owner, filter, map[string]any{"encoding": "jsonParsed", "commitment": c}); err != nil {
		return nil, err
	}
	var accts []TokenAccount
	for _, v := range out.Value {
		var amt uint64
		if _, err := fmt.Sscanf(v.Account.Data.Parsed.Info.TokenAmount.Amount, "%d", &amt); err != nil {
			return nil, fmt.Errorf("sol: token account %s: amount %q", v.Pubkey, v.Account.Data.Parsed.Info.TokenAmount.Amount)
		}
		accts = append(accts, TokenAccount{Pubkey: v.Pubkey, Mint: v.Account.Data.Parsed.Info.Mint, Amount: amt, Decimal: v.Account.Data.Parsed.Info.TokenAmount.Decimals})
	}
	return accts, nil
}

// MintDecimals is the decimals of a mint of the classic Token program, read from the chain; an account that is not such a mint is an error.
func (r *RPC) MintDecimals(ctx context.Context, mint string) (int, error) {
	var out struct {
		Value *struct {
			Owner string `json:"owner"`
			Data  struct {
				Parsed struct {
					Type string `json:"type"`
					Info struct {
						Decimals int `json:"decimals"`
					} `json:"info"`
				} `json:"parsed"`
			} `json:"data"`
		} `json:"value"`
	}
	if err := r.Call(ctx, &out, "getAccountInfo", mint, map[string]any{"encoding": "jsonParsed", "commitment": Finalized}); err != nil {
		return 0, err
	}
	if out.Value == nil {
		return 0, fmt.Errorf("sol: mint %s does not exist", mint)
	}
	if out.Value.Owner != TokenProgram || out.Value.Data.Parsed.Type != "mint" {
		return 0, fmt.Errorf("sol: %s is not a mint of the classic Token program", mint)
	}
	return out.Value.Data.Parsed.Info.Decimals, nil
}
