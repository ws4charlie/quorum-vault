// Package gen is the load generator of QuorumVault: it drives the public API the way a client does (bearer tokens, signed approvals, deposits paid on
// the chain), at arrival rates that do not wait for the system (open loop) or with a fixed number of users (closed loop), and writes one result file per run.
//
// It imports nothing from the services (no internal packages): the same binary runs against a laptop stack and against a cluster, with targets and
// identities from files and flags. Nothing secret is in the repository: keys and tokens come from files the setup of a run writes.
package gen

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"time"
)

// Scenario is one named workload. Rates are per second at scale 1; Steps multiply them.
type Scenario struct {
	Name string `json:"name"`
	Note string `json:"note,omitempty"`
	Seed int64  `json:"seed"`
	// Mode is "open" (arrivals at a given rate whatever the system does; a slow system shows as growing latency) or "closed" (Concurrency users, each
	// starts its next operation when the last one finished; a slow system shows as a lower rate).
	Mode        string `json:"mode"`
	Concurrency int    `json:"concurrency,omitempty"` // closed loop: users; the mix of operations follows the streams' rates
	Setup       Setup  `json:"setup"`
	// Phases: the rate rises linearly from 0 over RampS, holds for HoldS, then arrivals stop and the run waits up to DrainS for the open operations.
	// With Steps, the hold phase is replaced by one hold of StepS seconds per step, at the rates times the step's scale.
	RampS   float64   `json:"ramp_s"`
	HoldS   float64   `json:"hold_s"`
	DrainS  float64   `json:"drain_s"`
	StepS   float64   `json:"step_s,omitempty"`
	Steps   []float64 `json:"steps,omitempty"`
	Streams []Stream  `json:"streams"`
	// Objectives are what the run is judged by; a step or a run that breaks one is where the system's first limit is.
	Objectives Objectives `json:"objectives"`
	// MaxInflight: when more operations than this are open, no new ones arrive (the system is far past its limit; more load only buries it and makes the
	// settle take long). The run records where it stopped. 0 = never stop.
	MaxInflight int `json:"max_inflight,omitempty"`
	// SettleS: how long after the drain the generator waits for operations it gave up on to end, before it judges the books (default 300).
	SettleS float64 `json:"settle_s,omitempty"`
	// BackgroundReconcileS: a Reconcile call every so many seconds during the run (the operator's job); 0 = none.
	BackgroundReconcileS float64 `json:"background_reconcile_s,omitempty"`
}

// Setup prepares the books before the load: customers with funds to withdraw, and customers whose addresses receive the deposits of the run.
type Setup struct {
	WithdrawCustomers int     `json:"withdraw_customers"` // each is funded by a deposit and waits to be credited
	FundEachETH       float64 `json:"fund_each_eth"`
	DepositCustomers  int     `json:"deposit_customers"` // addresses that receive the deposits of the run (one open deposit per customer at a time)
	FundParallel      int     `json:"fund_parallel,omitempty"`
}

// Stream is one kind of operation with its own arrival rate.
type Stream struct {
	Op    string  `json:"op"`             // "deposit" or "withdraw"
	Tier  string  `json:"tier,omitempty"` // withdraw: "auto" (the worker's key approves) or "two" (two named approvers sign)
	Asset string  `json:"asset,omitempty"`
	Rate  float64 `json:"rate"`
	// AmountETH is [min, max], uniform. For a deposit: ETH sent. For a withdrawal: ETH asked (tier "two" must be at or over the chain's second tier).
	AmountETH [2]float64 `json:"amount_eth"`
	// Until: a deposit ends when it is "swept" (default) or earlier, when it is "credited" (the customer's view; a closed-loop user does not wait for the sweep)
	Until string `json:"until,omitempty"`
}

// Objectives are the pass lines of a step. Zero = not checked.
type Objectives struct {
	WithdrawP95MS            float64 `json:"withdraw_p95_ms,omitempty"`              // request -> confirmed, 95th percentile
	ApprovedToBroadcastP95MS float64 `json:"approved_to_broadcast_p95_ms,omitempty"` // approved -> broadcast
	DepositCreditP95MS       float64 `json:"deposit_credit_p95_ms,omitempty"`        // sent -> credited
	SweepP95MS               float64 `json:"sweep_p95_ms,omitempty"`                 // sent -> swept
	ErrorRate                float64 `json:"error_rate,omitempty"`                   // errors / operations
	AchievedOfOffered        float64 `json:"achieved_of_offered,omitempty"`          // completed per second / offered per second, at least
}

// LoadScenario reads and checks a scenario file.
func LoadScenario(path string) (*Scenario, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Scenario
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, s.Check()
}

// Check refuses a scenario that cannot run.
// NeedsApprovers reports whether a stream asks for approvals by people (tier "two").
func (s *Scenario) NeedsApprovers() bool {
	for _, st := range s.Streams {
		if st.Op == "withdraw" && st.Tier == "two" {
			return true
		}
	}
	return false
}

func (s *Scenario) Check() error {
	if s.Name == "" {
		return fmt.Errorf("scenario: no name")
	}
	if s.Mode == "" {
		s.Mode = "open"
	}
	if s.SettleS == 0 {
		s.SettleS = 300
	}
	if s.Mode != "open" && s.Mode != "closed" {
		return fmt.Errorf("scenario %s: mode %q", s.Name, s.Mode)
	}
	if s.Mode == "closed" && s.Concurrency <= 0 {
		return fmt.Errorf("scenario %s: closed loop needs concurrency", s.Name)
	}
	if len(s.Streams) == 0 {
		return fmt.Errorf("scenario %s: no streams", s.Name)
	}
	needsFunds := false
	for i, st := range s.Streams {
		switch st.Op {
		case "deposit":
		case "withdraw":
			needsFunds = true
			if st.Tier != "auto" && st.Tier != "two" {
				return fmt.Errorf("scenario %s: stream %d: tier %q", s.Name, i, st.Tier)
			}
		default:
			return fmt.Errorf("scenario %s: stream %d: op %q", s.Name, i, st.Op)
		}
		if st.Rate <= 0 || st.AmountETH[0] <= 0 || st.AmountETH[1] < st.AmountETH[0] {
			return fmt.Errorf("scenario %s: stream %d: rate and amounts must be positive", s.Name, i)
		}
	}
	if needsFunds && (s.Setup.WithdrawCustomers <= 0 || s.Setup.FundEachETH <= 0) {
		return fmt.Errorf("scenario %s: withdrawals need setup.withdraw_customers and fund_each_eth", s.Name)
	}
	if s.RampS < 0 || s.HoldS < 0 || s.DrainS <= 0 {
		return fmt.Errorf("scenario %s: phases", s.Name)
	}
	if len(s.Steps) > 0 && s.StepS <= 0 {
		return fmt.Errorf("scenario %s: steps need step_s", s.Name)
	}
	if len(s.Steps) == 0 && s.HoldS <= 0 {
		return fmt.Errorf("scenario %s: hold_s", s.Name)
	}
	return nil
}

// Duration of the arrival phases (ramp, then hold or steps).
func (s *Scenario) ArrivalDuration() time.Duration {
	h := s.HoldS
	if len(s.Steps) > 0 {
		h = s.StepS * float64(len(s.Steps))
	}
	return time.Duration((s.RampS + h) * float64(time.Second))
}

// scaleAt is the rate multiplier t seconds into the arrival phases, and the step it belongs to (-1 in the ramp, or the hold without steps: 0).
func (s *Scenario) scaleAt(t float64) (scale float64, step int) {
	if t < s.RampS {
		first := 1.0
		if len(s.Steps) > 0 {
			first = s.Steps[0]
		}
		return first * t / s.RampS, -1
	}
	if len(s.Steps) == 0 {
		return 1, 0
	}
	i := int((t - s.RampS) / s.StepS)
	if i >= len(s.Steps) {
		i = len(s.Steps) - 1
	}
	return s.Steps[i], i
}

// ValidateRateScale refuses a rate scale that would make the arrival loop wait for ever or never end: zero, negative, infinite or not a number.
func ValidateRateScale(x float64) error {
	if math.IsNaN(x) || math.IsInf(x, 0) || x <= 0 {
		return fmt.Errorf("-rate-scale must be a positive number, got %v", x)
	}
	return nil
}
