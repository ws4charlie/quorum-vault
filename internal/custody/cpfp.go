package custody

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/ws4charlie/quorum-vault/internal/chain"
)

// ErrCPFPRefused is the answer when a CPFP child cannot be started now (409): the send is not broadcast, is confirmed, or no child can raise its rate.
var ErrCPFPRefused = errors.New("custody: no CPFP child can be started")

// CPFPChild is what an operator's call gets back: the owner whose send is pulled in (the withdrawal itself, or the batch it is in) and the child's first job.
type CPFPChild struct {
	OwnerKind string `json:"owner_kind"`
	OwnerID   string `json:"owner_id"`
	Job       string `json:"child_job"`
	Existing  bool   `json:"existing"` // the child was there before this call (a repeat): nothing new was built
}

// StartCPFP builds the CPFP child of a withdrawal's send now, instead of after cpfp_after. A withdrawal in a batch is pulled in with its batch.
// It is allowed only while the send is broadcast and not decided, and only if the chain's own check says a child raises the package rate; the
// signing zone's rules are unchanged. A repeat returns the child that exists. The caller then wakes the workflow that drives the send.
func (s *Service) StartCPFP(ctx context.Context, withdrawalID string) (CPFPChild, error) {
	wd, err := s.GetWithdrawal(ctx, withdrawalID)
	if err != nil {
		return CPFPChild{}, err
	}
	o := wd.Owner()
	if wd.BatchID != "" {
		b, err := s.GetBatch(ctx, wd.BatchID)
		if err != nil {
			return CPFPChild{}, err
		}
		if b.Status != BatchBroadcast {
			return CPFPChild{}, fmt.Errorf("%w: the batch %s is %s, not broadcast", ErrCPFPRefused, b.ID, b.Status)
		}
		o = b.Owner()
	}
	if _, ok := s.Chain.(chain.CPFPBuilder); !ok {
		return CPFPChild{}, fmt.Errorf("%w: this chain has no CPFP", ErrCPFPRefused)
	}
	oc, err := s.Chain.Outcome(ctx, o.Kind, o.ID)
	if err != nil {
		return CPFPChild{}, err
	}
	switch {
	case oc.State != chain.OutcomeOpen:
		return CPFPChild{}, fmt.Errorf("%w: the send is already decided (%s)", ErrCPFPRefused, oc.State)
	case oc.Attempts == 0:
		return CPFPChild{}, fmt.Errorf("%w: the send is not broadcast", ErrCPFPRefused)
	}
	first := CPFPTrack(o).Replacement(1)
	var have bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sign_jobs WHERE id=$1)`, first).Scan(&have); err != nil {
		return CPFPChild{}, err
	}
	if have {
		return CPFPChild{OwnerKind: o.Kind, OwnerID: o.ID, Job: first, Existing: true}, nil
	}
	id, err := s.EnqueueCPFP(ctx, o, 1)
	switch {
	case errors.Is(err, chain.ErrCannotBump):
		return CPFPChild{}, fmt.Errorf("%w: %v", ErrCPFPRefused, err)
	case err != nil:
		return CPFPChild{}, err
	case id == "":
		return CPFPChild{}, fmt.Errorf("%w: this chain has no CPFP", ErrCPFPRefused)
	}
	return CPFPChild{OwnerKind: o.Kind, OwnerID: o.ID, Job: id}, nil
}

// cpfper is implemented by orchestrators that can wake the workflow that drives a send to start its CPFP child.
type cpfper interface {
	CPFPNow(ctx context.Context, ownerID string) error
}

// startCPFP is POST /v2/withdrawals/{id}/cpfp: an operator, freshly logged in, asks for the CPFP child of a stuck send now. 202 with the child, or 409 with
// the reason. The call is in the audit trail (handle writes it before this runs) and in the log.
func (a *API) startCPFP(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.actor(w, r)
	if !ok {
		return
	}
	cp, ok := a.orch.(cpfper)
	if !ok {
		a.fail(w, fmt.Errorf("%w: CPFP is not available", ErrInvalid))
		return
	}
	id := r.PathValue("id")
	child, err := a.svc.StartCPFP(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrCPFPRefused) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		a.fail(w, err)
		return
	}
	// A child whose job exists may not be signed yet (an earlier call's wake-up was lost): wake the workflow again. The workflow ignores it when it is
	// already signing or has broadcast the child.
	if err := cp.CPFPNow(r.Context(), child.OwnerID); err != nil {
		a.log.Error("could not wake the workflow to start the CPFP child", "owner", child.OwnerKind+" "+child.OwnerID, "error", err.Error())
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "the send's workflow could not be reached; call again"})
		return
	}
	a.log.Info("CPFP child requested", "withdrawal", id, "owner", child.OwnerKind+" "+child.OwnerID, "job", child.Job, "existing", child.Existing, "actor", actor)
	writeJSON(w, http.StatusAccepted, map[string]any{"withdrawal": id, "requested_by": actor, "child": child})
}
