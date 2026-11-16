package auditchain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/ws4charlie/quorum-vault/internal/audit"
)

// Archive is the write-once copy of the published heads. Everything above it (the archiver, verify) only needs these three calls, so
// tests of the logic can use a map; the guarantees (nobody can delete or overwrite) are the store's and are tested against a real one.
type Archive interface {
	// Put stores the head under its key (source, seq, hash). A head that is already there is not written again: stored is false.
	Put(ctx context.Context, a audit.Anchor) (stored bool, err error)
	// Anchors returns every archived head of source (all sources when empty), by seq.
	Anchors(ctx context.Context, source string) ([]audit.Anchor, error)
	// CheckLock refuses a bucket that is not locked in COMPLIANCE mode with a default retention of at least min.
	CheckLock(ctx context.Context, min time.Duration) error
}

// ArchiveConfig names an S3-compatible bucket. Credentials come from the caller (env or file), never from the repo.
type ArchiveConfig struct {
	Endpoint  string // empty: AWS
	Region    string // default us-east-1
	Bucket    string
	AccessKey string
	SecretKey string
	PathStyle bool // path-style addressing, for stores on a host:port (everything but AWS)
}

// S3Archive is an Archive on an S3 bucket with Object Lock.
type S3Archive struct {
	cl     *s3.Client
	bucket string
}

// NewS3Archive builds the client; it does no request.
func NewS3Archive(c ArchiveConfig) (*S3Archive, error) {
	if c.Bucket == "" || c.AccessKey == "" || c.SecretKey == "" {
		return nil, errors.New("archive: bucket, access key and secret key are required")
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	cl := s3.New(s3.Options{
		Region:       c.Region,
		Credentials:  credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey, ""),
		BaseEndpoint: nonEmpty(c.Endpoint),
		UsePathStyle: c.PathStyle,
		// the default added checksums are not understood by every S3-compatible store
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
	return &S3Archive{cl: cl, bucket: c.Bucket}, nil
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

var safeSource = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ArchiveKey is the object key of a head: one object per (source, seq, hash). The same head always has the same key, so a replay is
// a no-op, and a head that disagrees with its key cannot be read as valid.
func ArchiveKey(a audit.Anchor) (string, error) {
	if !safeSource.MatchString(a.Source) || a.Seq < 0 || len(a.Hash) != 64 || strings.Trim(a.Hash, "0123456789abcdef") != "" {
		return "", fmt.Errorf("archive: not a head: source %q seq %d hash %q", a.Source, a.Seq, a.Hash)
	}
	return fmt.Sprintf("heads/%s/%020d-%s.json", a.Source, a.Seq, a.Hash), nil
}

// CheckLock implements Archive.
func (s *S3Archive) CheckLock(ctx context.Context, min time.Duration) error {
	out, err := s.cl.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: &s.bucket})
	if err != nil {
		return fmt.Errorf("archive: bucket %q has no readable Object Lock configuration (it must be created with Object Lock enabled): %w", s.bucket, err)
	}
	c := out.ObjectLockConfiguration
	if c == nil || c.ObjectLockEnabled != s3types.ObjectLockEnabledEnabled {
		return fmt.Errorf("archive: bucket %q does not have Object Lock enabled; it can only be enabled when the bucket is created", s.bucket)
	}
	if c.Rule == nil || c.Rule.DefaultRetention == nil {
		return fmt.Errorf("archive: bucket %q has no default retention; set a default retention in COMPLIANCE mode", s.bucket)
	}
	r := c.Rule.DefaultRetention
	if r.Mode != s3types.ObjectLockRetentionModeCompliance {
		return fmt.Errorf("archive: bucket %q default retention is in %s mode; only COMPLIANCE cannot be shortened or bypassed by an administrator", s.bucket, r.Mode)
	}
	var have time.Duration
	if r.Days != nil {
		have += time.Duration(*r.Days) * 24 * time.Hour
	}
	if r.Years != nil {
		have += time.Duration(*r.Years) * 365 * 24 * time.Hour
	}
	if have < min {
		return fmt.Errorf("archive: bucket %q default retention is %s, shorter than the required %s", s.bucket, have, min)
	}
	return nil
}

// Put implements Archive. A new version of an existing key is never written: the head is looked up first and the write is
// conditional (If-None-Match), so two archivers racing on the same head also store it once.
func (s *S3Archive) Put(ctx context.Context, a audit.Anchor) (bool, error) {
	key, err := ArchiveKey(a)
	if err != nil {
		return false, err
	}
	if _, err := s.cl.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &s.bucket, Key: &key}); err == nil {
		return false, nil
	} else if !isNotFound(err) {
		return false, fmt.Errorf("archive: look up %s: %w", key, err)
	}
	body, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	_, err = s.cl.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &s.bucket, Key: &key, Body: bytes.NewReader(body), ContentType: aws.String("application/json"),
		IfNoneMatch: aws.String("*"), // the bucket's default retention (COMPLIANCE) applies to the new object
	})
	if err != nil {
		if code := errCode(err); code == "PreconditionFailed" || code == "ConditionalRequestConflict" {
			return false, nil // another writer stored the same head first
		}
		return false, fmt.Errorf("archive: store %s: %w", key, err)
	}
	return true, nil
}

// Anchors implements Archive. An object whose content does not match its key is an error: a file that cannot be read in full proves nothing.
func (s *S3Archive) Anchors(ctx context.Context, source string) ([]audit.Anchor, error) {
	prefix := "heads/"
	if source != "" {
		if !safeSource.MatchString(source) {
			return nil, fmt.Errorf("archive: bad source %q", source)
		}
		prefix += source + "/"
	}
	// Every version is read, not just the latest of each key: a delete marker on top of an object makes it vanish from a plain listing
	// while the locked version is still there, and a later version written over it must not hide the first.
	type ver struct{ key, id string }
	var vers []ver
	pg := s3.NewListObjectVersionsPaginator(s.cl, &s3.ListObjectVersionsInput{Bucket: &s.bucket, Prefix: &prefix})
	for pg.HasMorePages() {
		p, err := pg.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("archive: list: %w", err)
		}
		for _, o := range p.Versions {
			vers = append(vers, ver{*o.Key, aws.ToString(o.VersionId)})
		}
	}
	out := make([]audit.Anchor, len(vers))
	errs := make([]error, len(vers))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i, v := range vers {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out[i], errs[i] = s.read(ctx, v.key, v.id)
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	uniq := out[:0]
	for i, a := range out { // the same head in two versions counts once
		if k := vers[i].key; !seen[k] {
			seen[k] = true
			uniq = append(uniq, a)
		}
	}
	out = uniq
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Seq < out[j].Seq
	})
	return out, nil
}

func (s *S3Archive) read(ctx context.Context, key, versionID string) (audit.Anchor, error) {
	o, err := s.cl.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key, VersionId: nonEmpty(versionID)})
	if err != nil {
		return audit.Anchor{}, fmt.Errorf("archive: read %s: %w", key, err)
	}
	defer o.Body.Close()
	b, err := io.ReadAll(io.LimitReader(o.Body, 1<<16))
	if err != nil {
		return audit.Anchor{}, fmt.Errorf("archive: read %s: %w", key, err)
	}
	as, err := audit.ReadAnchors(bytes.NewReader(b), "")
	if err != nil || len(as) != 1 {
		return audit.Anchor{}, fmt.Errorf("archive: %s is not one head", key)
	}
	if want, err := ArchiveKey(as[0]); err != nil || want != key {
		return audit.Anchor{}, fmt.Errorf("archive: %s holds a head that belongs under %s", key, want)
	}
	return as[0], nil
}

func errCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

func isNotFound(err error) bool {
	switch errCode(err) {
	case "NotFound", "NoSuchKey", "404":
		return true
	}
	return false
}
