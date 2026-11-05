package auditchain

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/outbox"
)

// AnchorOptions tunes PublishHeads.
type AnchorOptions struct {
	Poll     time.Duration // how often the head is looked at, default 1s: a new head goes out within one poll
	Interval time.Duration // the head is published at least this often even if unchanged, default 1m
	Logger   *slog.Logger
}

// PublishHeads publishes the head of the chain behind q to topic qv.audit.heads whenever it changes, and at least every
// Interval. A publish that fails (Kafka down) is retried on the next poll with the head of that moment, so the anchors catch up
// by themselves; nothing that writes the chain waits for it.
func PublishHeads(ctx context.Context, q audit.Querier, source string, pub outbox.Publisher, opt AnchorOptions) {
	if opt.Poll <= 0 {
		opt.Poll = time.Second
	}
	if opt.Interval <= 0 {
		opt.Interval = time.Minute
	}
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.DiscardHandler)
	}
	var lastSeq int64 = -1
	var lastAt time.Time
	t := time.NewTicker(opt.Poll)
	defer t.Stop()
	for {
		if h, err := audit.Head(ctx, q, source); err != nil {
			if ctx.Err() != nil {
				return
			}
			opt.Logger.Warn("audit head unreadable", "source", source, "error", err.Error())
		} else if h.Seq != lastSeq || time.Since(lastAt) >= opt.Interval {
			if err := PublishHead(ctx, pub, h); err != nil {
				if ctx.Err() != nil {
					return
				}
				opt.Logger.Warn("audit head not published; will retry", "source", source, "seq", h.Seq, "error", err.Error())
			} else {
				lastSeq, lastAt = h.Seq, time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// PublishHead sends one anchor.
func PublishHead(ctx context.Context, pub outbox.Publisher, h audit.Anchor) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return pub.Publish(pctx, outbox.Event{ID: uuid.NewString(), Topic: outbox.TopicAuditHeads, Key: h.Source, Payload: b})
}

// Verify is the check behind `verify` of qv-relay, qv-gateway and qv-cosigner: it checks the chain in dsn against the anchors in
// the file (one JSON object per line, as dumped from qv.audit.heads) and prints the result. A failed check is an error.
func Verify(ctx context.Context, q audit.Querier, source, anchorsPath string, out io.Writer) error {
	var anchors []audit.Anchor
	if anchorsPath != "" {
		f, err := os.Open(anchorsPath)
		if err != nil {
			return err
		}
		defer f.Close()
		if anchors, err = audit.ReadAnchors(f, source); err != nil {
			return err
		}
	}
	rep, err := audit.CheckAnchors(ctx, q, anchors)
	if err != nil {
		return err
	}
	status := "ok"
	if !rep.OK {
		status = "FAILED"
	}
	fmt.Fprintf(out, "audit %s: %s  head seq %d  anchors checked %d\n", source, status, rep.HeadSeq, rep.Anchors)
	if !rep.OK {
		return fmt.Errorf("audit chain %s: %s", source, rep.Problem)
	}
	return nil
}

// VerifyCommand runs `verify [-dsn DSN] [-anchors FILE]` for the chain of one binary (source "core", "gateway" or "cosigner").
// dsnEnv names the environment variable that holds the DSN by default. It exits with an error when the check fails.
func VerifyCommand(ctx context.Context, args []string, source, dsnEnv string, out io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dsn := fs.String("dsn", os.Getenv(dsnEnv), "database that holds the audit chain (env "+dsnEnv+")")
	src := fs.String("source", source, "name the heads of this chain were published under (the -audit-source of the binary)")
	anchors := fs.String("anchors", "", "file of published heads, one JSON object per line (dump of qv.audit.heads); without it only the chain itself is checked")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" {
		return fmt.Errorf("-dsn or %s is required", dsnEnv)
	}
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	return Verify(ctx, pool, *src, *anchors, out)
}
