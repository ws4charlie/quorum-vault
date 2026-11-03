package mpc

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/bnb-chain/tss-lib/v4/tss"
)

// outBuffer bounds the messages a ceremony may emit without the router
// reading them. It is far above what 3 parties emit (keygen 12, signing
// ~30), so a party goroutine never blocks on a router that already returned.
const outBuffer = 1024

var roundRE = regexp.MustCompile(`Round(\d+)`)

// route is the in-memory transport. It starts every party, then moves each
// outgoing message to its recipients (all other parties for a broadcast,
// msg.GetTo() for point-to-point) as wire bytes via UpdateFromBytes, exactly
// as a network transport would. It returns the parties' outputs once every
// party has finished, or the first error, or ctx.Err().
//
// parties[i] must have PartyID().Index == i (the order of the
// tss.SortedPartyIDs the parties were built from).
func route[T any](ctx context.Context, parties []tss.Party, outCh chan tss.Message, endCh chan T) ([]T, Stats, error) {
	start := time.Now()
	var st Stats
	errCh := make(chan error, 1)
	fail := func(err error) {
		select {
		case errCh <- err:
		default: // first error wins
		}
	}
	safe := func(fn func()) {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					fail(fmt.Errorf("mpc: tss-lib panic: %v", r))
				}
			}()
			fn()
		}()
	}

	for _, p := range parties {
		safe(func() {
			if err := p.Start(); err != nil {
				fail(err)
			}
		})
	}

	outs := make([]T, 0, len(parties))
	for len(outs) < len(parties) {
		select {
		case <-ctx.Done():
			return nil, st, ctx.Err()
		case err := <-errCh:
			return nil, st, err
		case out := <-endCh:
			outs = append(outs, out)
		case msg := <-outCh:
			bz, _, err := msg.WireBytes()
			if err != nil {
				return nil, st, fmt.Errorf("mpc: wire bytes: %w", err)
			}
			if m := roundRE.FindStringSubmatch(msg.Type()); m != nil {
				if r, _ := strconv.Atoi(m[1]); r > st.Rounds {
					st.Rounds = r
				}
			}
			from := msg.GetFrom()
			var dests []tss.Party
			if to := msg.GetTo(); to == nil {
				for _, p := range parties {
					if p.PartyID().Index != from.Index {
						dests = append(dests, p)
					}
				}
			} else {
				for _, id := range to {
					if id.Index < 0 || id.Index >= len(parties) || id.Index == from.Index {
						return nil, st, fmt.Errorf("mpc: bad destination %v for message from %v", id, from)
					}
					dests = append(dests, parties[id.Index])
				}
			}
			for _, p := range dests {
				st.Messages++
				st.Bytes += len(bz)
				safe(func() {
					if _, err := p.UpdateFromBytes(bz, from, msg.IsBroadcast()); err != nil {
						fail(err)
					}
				})
			}
		}
	}
	st.Duration = time.Since(start)
	return outs, st, nil
}
