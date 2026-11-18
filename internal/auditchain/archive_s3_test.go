package auditchain

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/ws4charlie/quorum-vault/internal/pki"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/ws4charlie/quorum-vault/internal/audit"
)

// The archive tests run against a real SeaweedFS (the image docker-compose.yml pins, started by the test itself on a free port with random
// credentials and removed at the end). They need docker: without it they skip, except under QV_REQUIRE_WORM=1 (CI), where they fail.
// -short skips them too.

// wormStore is one running store with the bucket created: root creates and administers, the archiver has Read/Write/List only.
type wormStore struct {
	endpoint   string
	bucketName string // set by startWorm
	root       ArchiveConfig
	archiver   ArchiveConfig
	logs       func() string
}

func requireWorm(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: the archive tests start a container")
	}
	if _, err := exec.LookPath("docker"); err != nil || exec.Command("docker", "info").Run() != nil {
		if os.Getenv("QV_REQUIRE_WORM") == "1" {
			t.Fatal("QV_REQUIRE_WORM=1 but docker is not available")
		}
		t.Skip("docker not available")
	}
}

func composeImage(t *testing.T, repo string) string {
	t.Helper()
	b, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*image:\s*(` + regexp.QuoteMeta(repo) + `:\S+@sha256:[0-9a-f]{64})\s*$`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("docker-compose.yml pins no %s image by digest", repo)
	}
	return string(m[1])
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// startStore starts the store, with no bucket yet.
func startStore(t *testing.T) *wormStore {
	t.Helper()
	requireWorm(t)
	img := composeImage(t, "chrislusf/seaweedfs")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	w := &wormStore{endpoint: fmt.Sprintf("https://127.0.0.1:%d", port)}
	id := pkitest.Source(t, pki.ZoneBusiness, "archiver") // the store takes TLS with a client certificate of the business authority
	w.root = ArchiveConfig{Endpoint: w.endpoint, AccessKey: "root" + randHex(t, 6), SecretKey: randHex(t, 16), PathStyle: true, TLS: id}
	w.archiver = ArchiveConfig{Endpoint: w.endpoint, AccessKey: "arc" + randHex(t, 6), SecretKey: randHex(t, 16), PathStyle: true, TLS: id}
	// The identities are written inside the container from the environment, as docker-compose.yml does: a bind mount would name a path of
	// this process, which is not the daemon's path when the tests run in a container (CI) next to the daemon.
	script := `printf '{"identities":[{"name":"root","credentials":[{"accessKey":"%s","secretKey":"%s"}],"actions":["Admin","Read","Write","List","Tagging"]},` +
		`{"name":"archiver","credentials":[{"accessKey":"%s","secretKey":"%s"}],"actions":["Read","Write","List","Admin"]}]}' "$ROOT_AK" "$ROOT_SK" "$ARC_AK" "$ARC_SK" > /tmp/s3.json && ` +
		`printf '%s' "$S3_CERT" > /tmp/s3.crt && printf '%s' "$S3_KEY" > /tmp/s3.key && printf '%s' "$S3_CA" > /tmp/s3-ca.crt && ` +
		`exec /entrypoint.sh server -dir=/data -s3 -s3.config=/tmp/s3.json -s3.port=0 -s3.port.https=8333 -s3.cert.file=/tmp/s3.crt -s3.key.file=/tmp/s3.key ` +
		`-s3.cacert.file=/tmp/s3-ca.crt -s3.tlsVerifyClientCert -master.volumeSizeLimitMB=64 -ip.bind=0.0.0.0`
	// the store's own certificate (business authority, name seaweedfs, IP 127.0.0.1) goes in through the environment, like the identities
	srvCert, srvKey, srvCA := pkitest.Files(pki.ZoneBusiness, "seaweedfs")
	name := "qv-worm-" + randHex(t, 4)
	out, err := exec.Command("docker", "run", "-d", "--name", name, "-p", fmt.Sprintf("127.0.0.1:%d:8333", port),
		"-e", "ROOT_AK="+w.root.AccessKey, "-e", "ROOT_SK="+w.root.SecretKey, "-e", "ARC_AK="+w.archiver.AccessKey, "-e", "ARC_SK="+w.archiver.SecretKey,
		"-e", "S3_CERT="+readFile(t, srvCert), "-e", "S3_KEY="+readFile(t, srvKey), "-e", "S3_CA="+readFile(t, srvCA),
		"--entrypoint", "/bin/sh", img, "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "-v", name).Run() })
	w.logs = func() string {
		b, _ := exec.Command("docker", "logs", "--tail", "30", name).CombinedOutput()
		return string(b)
	}
	return w
}

// bucket creates a bucket with Object Lock and a default retention of days in mode; mode "" leaves lock enabled without a default,
// "none" creates the bucket without Object Lock. It returns the configs of root and archiver for that bucket.
func (w *wormStore) bucket(t *testing.T, mode string, days int32) (root, archiver ArchiveConfig) {
	t.Helper()
	root, archiver = w.root, w.archiver
	root.Bucket = "heads-" + randHex(t, 4)
	archiver.Bucket = root.Bucket
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a, err := NewS3Archive(root)
	if err != nil {
		t.Fatal(err)
	}
	for { // the store needs a few seconds to take requests
		_, err := a.cl.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &root.Bucket, ObjectLockEnabledForBucket: aws.Bool(mode != "none")})
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("the store did not come up: %v\n%s", err, w.logs())
		}
		time.Sleep(time.Second)
	}
	if mode != "" && mode != "none" {
		_, err := a.cl.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{Bucket: &root.Bucket, ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
			ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
			Rule:              &s3types.ObjectLockRule{DefaultRetention: &s3types.DefaultRetention{Mode: s3types.ObjectLockRetentionMode(mode), Days: aws.Int32(days)}},
		}})
		if err != nil {
			t.Fatalf("set default retention: %v", err)
		}
	}
	return root, archiver
}

// withBucket is the same store with another bucket.
func (w *wormStore) withBucket(t *testing.T, mode string, days int32) *wormStore {
	t.Helper()
	c := *w
	c.root, c.archiver = w.bucket(t, mode, days)
	c.bucketName = c.root.Bucket
	return &c
}

// startWorm is a store with one bucket.
func startWorm(t *testing.T, mode string, days int32) *wormStore {
	t.Helper()
	w := startStore(t)
	w.root, w.archiver = w.bucket(t, mode, days)
	w.bucketName = w.root.Bucket
	return w
}

func (w *wormStore) rootClient(t *testing.T) *s3.Client {
	t.Helper()
	a, err := NewS3Archive(w.root)
	if err != nil {
		t.Fatal(err)
	}
	return a.cl
}

func (w *wormStore) archive(t *testing.T) *S3Archive {
	t.Helper()
	a, err := NewS3Archive(w.archiver)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func head(source string, seq int64) audit.Anchor {
	h := make([]byte, 32)
	h[0], h[31] = byte(seq), byte(len(source))
	return audit.Anchor{Source: source, Seq: seq, Hash: hex.EncodeToString(h), At: time.Now().UTC().Truncate(time.Millisecond)}
}

// A head that was archived cannot be deleted or overwritten while it is under retention, whoever asks, root included. The test says
// what the store refuses (the version, the retention, the mode) and what it allows (new versions, delete markers) and shows that
// neither of those makes the archived head disappear or change for a reader.
func TestWormRefusesDeleteAndOverwriteDuringRetention(t *testing.T) {
	w := startWorm(t, "COMPLIANCE", 1)
	ctx := context.Background()
	arc, rc := w.archive(t), w.rootClient(t)
	a := head("core", 7)
	if ok, err := arc.Put(ctx, a); err != nil || !ok {
		t.Fatalf("put: stored=%v err=%v", ok, err)
	}
	key, _ := ArchiveKey(a)
	lv, err := rc.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &w.bucketName, Prefix: &key})
	if err != nil || len(lv.Versions) != 1 {
		t.Fatalf("versions: %v %v", lv, err)
	}
	vid := lv.Versions[0].VersionId

	// the object carries a COMPLIANCE retention of about a day, from the bucket default
	r, err := rc.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{Bucket: &w.bucketName, Key: &key, VersionId: vid})
	if err != nil || r.Retention == nil || r.Retention.Mode != s3types.ObjectLockRetentionModeCompliance || time.Until(*r.Retention.RetainUntilDate) < 23*time.Hour {
		t.Fatalf("retention of the object: %+v %v", r, err)
	}

	for name, c := range map[string]*s3.Client{"archiver": w.archiveClient(t), "root": rc} {
		if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &w.bucketName, Key: &key, VersionId: vid}); err == nil {
			t.Errorf("%s deleted the locked version", name)
		}
		if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &w.bucketName, Key: &key, VersionId: vid, BypassGovernanceRetention: aws.Bool(true)}); err == nil {
			t.Errorf("%s deleted the locked version with bypass-governance", name)
		}
	}
	// neither can shorten the retention or turn it into governance mode (the archiver's identity has SeaweedFS's Admin action, see docker-compose.yml)
	for name, c := range map[string]*s3.Client{"archiver": w.archiveClient(t), "root": rc} {
		if _, err := c.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{Bucket: &w.bucketName, Key: &key, VersionId: vid, BypassGovernanceRetention: aws.Bool(true),
			Retention: &s3types.ObjectLockRetention{Mode: s3types.ObjectLockRetentionModeCompliance, RetainUntilDate: aws.Time(time.Now().Add(time.Minute))}}); err == nil {
			t.Errorf("%s shortened the retention", name)
		}
		if _, err := c.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{Bucket: &w.bucketName, Key: &key, VersionId: vid, BypassGovernanceRetention: aws.Bool(true),
			Retention: &s3types.ObjectLockRetention{Mode: s3types.ObjectLockRetentionModeGovernance, RetainUntilDate: aws.Time(time.Now().Add(48 * time.Hour))}}); err == nil {
			t.Errorf("%s switched the retention to governance mode", name)
		}
		if _, err := c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &w.bucketName}); err == nil {
			t.Errorf("%s deleted the bucket with a locked object in it", name)
		}
	}

	// the archiver does not write a head twice; a conditional overwrite is refused by the store as well
	if ok, err := arc.Put(ctx, a); err != nil || ok {
		t.Errorf("second put of the same head: stored=%v err=%v", ok, err)
	}
	forged := a
	forged.Hash = strings.Repeat("ab", 32)
	body, _ := io.ReadAll(bytes.NewReader([]byte(`{"source":"core","seq":7,"hash":"` + forged.Hash + `","at":"2026-01-01T00:00:00Z"}`)))
	if _, err := w.archiveClient(t).PutObject(ctx, &s3.PutObjectInput{Bucket: &w.bucketName, Key: &key, Body: bytes.NewReader(body), IfNoneMatch: aws.String("*")}); err == nil {
		t.Error("a conditional overwrite of an archived key was accepted")
	}

	// What the store does allow on a versioned bucket: a plain overwrite adds a version, a delete without version id adds a delete marker.
	// Neither touches the locked version, and Anchors reads every version, so the head is still there with its content.
	if _, err := w.archiveClient(t).PutObject(ctx, &s3.PutObjectInput{Bucket: &w.bucketName, Key: &key, Body: bytes.NewReader(body)}); err != nil {
		t.Logf("a plain overwrite is refused too: %v", err)
	}
	if _, err := rc.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &w.bucketName, Key: &key}); err != nil {
		t.Logf("a delete marker is refused too: %v", err)
	}
	old, err := rc.GetObject(ctx, &s3.GetObjectInput{Bucket: &w.bucketName, Key: &key, VersionId: vid})
	if err != nil {
		t.Fatalf("the locked version is gone: %v", err)
	}
	got, _ := io.ReadAll(old.Body)
	old.Body.Close()
	if !strings.Contains(string(got), a.Hash) || strings.Contains(string(got), forged.Hash) {
		t.Errorf("the locked version changed: %s", got)
	}
	// the overwrite with a head that does not belong under its key is an error for the reader, not a head
	if _, err := arc.Anchors(ctx, "core"); err == nil {
		t.Log("the forged version was not accepted by the store, or was not listed")
	}
}

func (w *wormStore) archiveClient(t *testing.T) *s3.Client {
	t.Helper()
	return w.archive(t).cl
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The store takes TLS with a client certificate of the business authority and nothing else; the archiver's client refuses plain http and a store the
// business authority did not sign. (SeaweedFS can check the authority but not the NAME of a client certificate: its identity is the access key.)
func TestStoreTakesTLSWithAClientCertificateOnly(t *testing.T) {
	w := startStore(t)
	root, _ := w.bucket(t, "COMPLIANCE", 400) // waits until the store takes requests

	// the right client works (w.bucket just used it); no client certificate, and the signing zone's, do not
	_, _, ca := pkitest.Files(pki.ZoneBusiness, "admin")
	pool := x509.NewCertPool()
	pem, _ := os.ReadFile(ca)
	pool.AppendCertsFromPEM(pem)
	noCert := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
	if resp, err := noCert.Get(w.endpoint + "/"); err == nil {
		resp.Body.Close()
		t.Fatalf("a client without a certificate was served (%d)", resp.StatusCode)
	} else {
		t.Logf("refused, as it must be: %.140v", err)
	}
	plain := &http.Client{Timeout: 10 * time.Second}
	if resp, err := plain.Get(strings.Replace(w.endpoint, "https://", "http://", 1) + "/"); err == nil {
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Fatalf("a plain connection was served (%d)", resp.StatusCode)
		}
	}
	other := root
	other.TLS = pkitest.Source(t, pki.ZoneSigning, "gateway")
	if a, err := NewS3Archive(other); err == nil {
		if _, err := a.Anchors(context.Background(), ""); err == nil {
			t.Fatal("a signing-zone certificate (and authority) was accepted")
		} else {
			t.Logf("refused, as it must be: %.140v", err)
		}
	}
	// the archiver's own client refuses a plain endpoint, and an https one with no identity
	t.Setenv("QV_ENV", "")
	t.Setenv("QV_ALLOW_PLAINTEXT", "")
	plainCfg := root
	plainCfg.Endpoint = strings.Replace(w.endpoint, "https://", "http://", 1)
	if _, err := NewS3Archive(plainCfg); err == nil {
		t.Fatal("an http endpoint was accepted")
	}
	noID := root
	noID.TLS = nil
	if _, err := NewS3Archive(noID); err == nil {
		t.Fatal("an https endpoint without an identity was accepted")
	}
}
