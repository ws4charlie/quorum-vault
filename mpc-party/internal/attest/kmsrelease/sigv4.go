package kmsrelease

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4, for the two KMS calls this package makes. [SIGV4] https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv4-create-signed-request.html
// (read 2026-11-20): canonical request, string to sign, a signing key derived by four HMACs, the Authorization header. Written here, not taken from the AWS
// SDK, because the party then links no AWS module: the SDK's size and dependency tree would sit in the measured image for a two-call client. The
// signer is checked against AWS's published test vector (sigv4_test.go) and, in the tests, against a verifier in the fake KMS that is written from the
// same document, not from this file.

// Creds are AWS credentials (an instance role's temporary ones have a session token).
type Creds struct {
	AccessKeyID, SecretAccessKey, SessionToken string
	Expiration                                 time.Time
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// signedHeaderNames: the headers a request signs. host and x-amz-date are required by SigV4; the others bind the call to its operation and body type.
func canonicalHeaders(h http.Header, host string, names []string) (canon, signed string) {
	var b strings.Builder
	for _, n := range names {
		v := host
		if n != "host" {
			v = strings.Join(strings.Fields(strings.Join(h.Values(n), ",")), " ")
		}
		b.WriteString(n + ":" + v + "\n")
	}
	return b.String(), strings.Join(names, ";")
}

// SignRequest adds X-Amz-Date, X-Amz-Security-Token (when set) and Authorization to req, whose body is body. Region and service name the credential scope.
func SignRequest(req *http.Request, body []byte, c Creds, region, service string, now time.Time) {
	now = now.UTC()
	amzDate, day := now.Format("20060102T150405Z"), now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	names := []string{"host"}
	for k := range req.Header {
		lk := strings.ToLower(k)
		if lk == "content-type" || lk == "x-amz-date" || lk == "x-amz-security-token" || strings.HasPrefix(lk, "x-amz-target") {
			names = append(names, lk)
		}
	}
	sort.Strings(names[1:])
	sort.Strings(names)
	ch, sh := canonicalHeaders(req.Header, req.URL.Host, names)
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonReq := strings.Join([]string{req.Method, path, req.URL.RawQuery, ch, sh, sha256Hex(body)}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonReq))
	k := hmacSHA256(hmacSHA256(hmacSHA256(hmacSHA256([]byte("AWS4"+c.SecretAccessKey), day), region), service), "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKeyID+"/"+scope+", SignedHeaders="+sh+", Signature="+sig)
}
