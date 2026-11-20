// Command mkbucket makes the kind lane's audit bucket the way the runbook (docs/runbooks/audit-archive.md) does: created with Object Lock, default retention in COMPLIANCE mode.
// SeaweedFS' shell can create the bucket but cannot set a default retention. It runs on the host against a port-forward; the access keys and the client certificate come from the
// environment and files that up.sh generated (nothing is committed).
//
//	QV_MKBUCKET_ENDPOINT=https://127.0.0.1:PORT QV_MKBUCKET_AK=... QV_MKBUCKET_SK=... go run ./ci/kind/tools/mkbucket -bucket qv-audit -cert c.crt -key c.key -ca ca.crt
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func main() {
	bucket := flag.String("bucket", "qv-audit", "bucket")
	days := flag.Int("days", 1, "default retention, days (COMPLIANCE)")
	certF := flag.String("cert", "", "client certificate")
	keyF := flag.String("key", "", "client key")
	caF := flag.String("ca", "", "CA of the store")
	name := flag.String("server-name", "seaweedfs", "name the store's certificate carries")
	flag.Parse()
	if err := run(*bucket, int32(*days), *certF, *keyF, *caF, *name); err != nil {
		fmt.Fprintln(os.Stderr, "mkbucket:", err)
		os.Exit(1)
	}
}

func run(bucket string, days int32, certF, keyF, caF, name string) error {
	pair, err := tls.LoadX509KeyPair(certF, keyF)
	if err != nil {
		return err
	}
	ca, err := os.ReadFile(caF)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS12}}}
	ep := os.Getenv("QV_MKBUCKET_ENDPOINT")
	cl := s3.New(s3.Options{
		HTTPClient: hc, Region: "us-east-1", BaseEndpoint: &ep, UsePathStyle: true,
		Credentials:                credentials.NewStaticCredentialsProvider(os.Getenv("QV_MKBUCKET_AK"), os.Getenv("QV_MKBUCKET_SK"), ""),
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
	ctx := context.Background()
	if _, err := cl.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket, ObjectLockEnabledForBucket: aws.Bool(true)}); err != nil {
		var exists *s3types.BucketAlreadyOwnedByYou
		if !asErr(err, &exists) && !contains(err.Error(), "BucketAlready") {
			return fmt.Errorf("create bucket: %w", err)
		}
	}
	_, err = cl.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{Bucket: &bucket, ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
		ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
		Rule:              &s3types.ObjectLockRule{DefaultRetention: &s3types.DefaultRetention{Mode: s3types.ObjectLockRetentionModeCompliance, Days: aws.Int32(days)}},
	}})
	if err != nil {
		return fmt.Errorf("object lock configuration: %w", err)
	}
	fmt.Printf("mkbucket: %s has Object Lock, COMPLIANCE, %d day(s)\n", bucket, days)
	return nil
}

func asErr(err error, target **s3types.BucketAlreadyOwnedByYou) bool {
	for e := err; e != nil; {
		if t, ok := e.(*s3types.BucketAlreadyOwnedByYou); ok {
			*target = t
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
