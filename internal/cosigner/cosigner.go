// Package cosigner is the independent check next to party B. It repeats the gateway's decision (intent, transaction
// verification, approvals, policy, replay guard) from its OWN signing-zone config and its OWN replay-guard database, and
// answers party B's mpc-party over a unix socket. Compromising the business database, the gateway and party A together
// must not yield a signature for an unapproved transaction: this process is why.
package cosigner

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// Cosigner decides for party B.
type Cosigner struct {
	dec *gateway.Decider
	log *slog.Logger
}

// New builds a Cosigner from its own config and guard.
func New(cfg *gateway.Config, guard *gateway.Guard, log *slog.Logger, now func() time.Time) (*Cosigner, error) {
	codecs, err := gateway.NewCodecs(cfg)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return &Cosigner{dec: gateway.NewDecider(cfg, codecs, guard, gateway.ModeCosigner, now), log: log}, nil
}

// Decide answers one request. Every doubt is a refusal.
func (c *Cosigner) Decide(ctx context.Context, r wire.Request) wire.Response {
	resp := c.decide(ctx, r)
	attrs := []any{"job_id", r.JobID, "key_id", r.KeyID, "allow", resp.Allow, "unavailable", resp.Unavailable}
	if !resp.Allow {
		attrs = append(attrs, "reason", resp.Reason)
	}
	c.log.Info("cosigner decision", attrs...)
	return resp
}

func (c *Cosigner) decide(ctx context.Context, r wire.Request) wire.Response {
	no := func(format string, a ...any) wire.Response { return wire.Response{Reason: fmt.Sprintf(format, a...)} }
	if pb.Algorithm(r.Algorithm) != pb.Algorithm_ALGORITHM_ECDSA_SECP256K1 {
		return no("cosigner: only secp256k1 ECDSA signing is supported")
	}
	if len(r.Digest) != 32 {
		return no("cosigner: digest must be 32 bytes")
	}
	if r.JobID == "" {
		return no("cosigner: no job id")
	}
	pub, err := crypto.DecompressPubkey(r.PublicKey)
	if err != nil || len(r.PublicKey) != 33 {
		return no("cosigner: the key to sign with is missing or not a secp256k1 point")
	}
	job, err := gateway.DecodePackage(r.IntentPackage)
	if err != nil {
		return no("%s: %v", gateway.ReasonIntent, err)
	}
	// The package must be about exactly what party A asked B to sign.
	if job.ID != r.JobID {
		return no("%s: intent package is for job %q, not %q", gateway.ReasonIntent, job.ID, r.JobID)
	}
	if !bytes.Equal(job.Digest, r.Digest) {
		return no("%s: intent package digest differs from the digest to sign", gateway.ReasonTx)
	}
	return c.verdict(ctx, job, pub)
}

func (c *Cosigner) verdict(ctx context.Context, job signjob.Job, pub *ecdsa.PublicKey) wire.Response {
	v, err := c.dec.Decide(ctx, job, pub)
	if err != nil {
		if why, ok := gateway.IsRejection(err); ok {
			return wire.Response{Reason: why}
		}
		if errors.Is(err, gateway.ErrSigner) {
			return wire.Response{Reason: "signer_key_mismatch: " + err.Error()}
		}
		// Not a decision: the guard database failed, a deadline passed. Nothing is allowed, but this is an outage and the
		// caller must retry later, not treat it as a refusal.
		c.log.Error("cosigner could not decide (unavailable)", "job_id", job.ID, "error", err.Error())
		return wire.Response{Unavailable: true, Reason: "cosigner_error: " + err.Error()}
	}
	if !v.NeedSign {
		// Gateway mode only: a signature already stored. The cosigner never stores one.
		return wire.Response{Unavailable: true, Reason: "cosigner_error: unexpected stored signature"}
	}
	return wire.Response{Allow: true}
}

// Handler serves POST wire.Path.
func (c *Cosigner) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+wire.Path, func(w http.ResponseWriter, req *http.Request) {
		var r wire.Request
		dec := json.NewDecoder(http.MaxBytesReader(w, req.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		out := c.Decide(req.Context(), r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})
	return mux
}

// ListenUnix opens a unix socket that only the owner can use (mode 0600), replacing a stale socket file.
func ListenUnix(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		os.Remove(path)
	}
	// umask first so the socket never exists with wider permissions, then chmod to be sure.
	old := umask(0o177)
	ln, err := net.Listen("unix", path)
	umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
