package auditchain

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ws4charlie/quorum-vault/internal/db"

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
	return VerifyAgainst(ctx, q, source, anchorsPath, nil, out)
}

// VerifyAgainst is Verify with a second source of anchors: the write-once archive. The anchors of the file and of the archive are
// checked together; the chain must contain every one of them and contradict none.
func VerifyAgainst(ctx context.Context, q audit.Querier, source, anchorsPath string, arch Archive, out io.Writer) error {
	var anchors []audit.Anchor
	nFile, nArchive := 0, 0
	if anchorsPath != "" {
		f, err := os.Open(anchorsPath)
		if err != nil {
			return err
		}
		defer f.Close()
		if anchors, err = audit.ReadAnchors(f, source); err != nil {
			return err
		}
		nFile = len(anchors)
	}
	if arch != nil {
		if err := arch.CheckLock(ctx, 0); err != nil {
			fmt.Fprintf(out, "warning: the archive is not write-once: %v\n", err)
		}
		as, err := arch.Anchors(ctx, source)
		if err != nil {
			return fmt.Errorf("audit archive: %w", err)
		}
		nArchive = len(as)
		anchors = append(anchors, as...)
	}
	rep, err := audit.CheckAnchors(ctx, q, anchors)
	if err != nil {
		return err
	}
	status := "ok"
	if !rep.OK {
		status = "FAILED"
	}
	fmt.Fprintf(out, "audit %s: %s  head seq %d  anchors checked %d", source, status, rep.HeadSeq, rep.Anchors)
	if arch != nil {
		fmt.Fprintf(out, " (file %d, archive %d)", nFile, nArchive)
	}
	fmt.Fprintln(out)
	if !rep.OK {
		return fmt.Errorf("audit chain %s: %s", source, rep.Problem)
	}
	return nil
}

// ArchiveFlags registers the flags that name the write-once archive on fs and returns the function that builds it from them (nil when
// no bucket is named). Credentials are never flags: QV_ARCHIVE_ACCESS_KEY and QV_ARCHIVE_SECRET_KEY, or the files named by
// QV_ARCHIVE_ACCESS_KEY_FILE and QV_ARCHIVE_SECRET_KEY_FILE.
func ArchiveFlags(fs *flag.FlagSet) func() (*S3Archive, error) {
	endpoint := fs.String("archive-endpoint", os.Getenv("QV_ARCHIVE_ENDPOINT"), "S3 endpoint of the archive, empty for AWS (env QV_ARCHIVE_ENDPOINT)")
	bucket := fs.String("archive-bucket", os.Getenv("QV_ARCHIVE_BUCKET"), "bucket that holds the archived heads (env QV_ARCHIVE_BUCKET)")
	region := fs.String("archive-region", envOr("QV_ARCHIVE_REGION", "us-east-1"), "region (env QV_ARCHIVE_REGION)")
	pathStyle := fs.Bool("archive-path-style", os.Getenv("QV_ARCHIVE_ENDPOINT") != "", "path-style addressing: on for a store at host:port, off for AWS")
	return func() (*S3Archive, error) {
		if *bucket == "" {
			return nil, nil
		}
		ak, err := envOrFile("QV_ARCHIVE_ACCESS_KEY")
		if err != nil {
			return nil, err
		}
		sk, err := envOrFile("QV_ARCHIVE_SECRET_KEY")
		if err != nil {
			return nil, err
		}
		return NewS3Archive(ArchiveConfig{Endpoint: *endpoint, Region: *region, Bucket: *bucket, AccessKey: ak, SecretKey: sk, PathStyle: *pathStyle})
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envOrFile reads a secret from $name, or from the file named by $name_FILE.
func envOrFile(name string) (string, error) {
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	if f := os.Getenv(name + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", name, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", fmt.Errorf("%s or %s_FILE is required", name, name)
}

// VerifyCommand runs `verify [-dsn DSN] [-anchors FILE] [-archive-bucket B ...]` for the chain of one binary (source "core", "gateway" or "cosigner").
// dsnEnv names the environment variable that holds the DSN by default. It exits with an error when the check fails.
func VerifyCommand(ctx context.Context, args []string, source, dsnEnv string, out io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dsn := fs.String("dsn", os.Getenv(dsnEnv), "database that holds the audit chain (env "+dsnEnv+")")
	src := fs.String("source", source, "name the heads of this chain were published under (the -audit-source of the binary)")
	anchors := fs.String("anchors", "", "file of published heads, one JSON object per line (dump of qv.audit.heads); without it and without -archive-bucket only the chain itself is checked")
	archive := ArchiveFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" {
		return fmt.Errorf("-dsn or %s is required", dsnEnv)
	}
	var arch Archive
	if a, err := archive(); err != nil {
		return err
	} else if a != nil {
		arch = a
	}
	pool, err := db.NewPool(ctx, *dsn, nil, nil)
	if err != nil {
		return err
	}
	defer pool.Close()
	return VerifyAgainst(ctx, pool, *src, *anchors, arch, out)
}
