package btc

import (
	"fmt"
	"math/big"
	"strings"
)

// Sats converts the decimal BTC amount bitcoind prints ("0.00012345", maybe "1e-05" never: the node prints fixed point) to
// satoshis exactly, with no floating point.
func Sats(v string) (*big.Int, error) {
	s := strings.TrimSpace(v)
	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" || strings.ContainsAny(s, "eE-+") {
		return nil, fmt.Errorf("btc: bad amount %q", v)
	}
	if len(frac) > Decimals {
		if strings.Trim(frac[Decimals:], "0") != "" {
			return nil, fmt.Errorf("btc: amount %q has more than %d decimals", v, Decimals)
		}
		frac = frac[:Decimals]
	}
	frac += strings.Repeat("0", Decimals-len(frac))
	n, ok := new(big.Int).SetString(whole+frac, 10)
	if !ok {
		return nil, fmt.Errorf("btc: bad amount %q", v)
	}
	return n, nil
}
