package kmsrelease

import (
	"net/http"
	"testing"
	"time"
)

// AWS's published SigV4 test suite, case "get-vanilla" (https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html): the example credentials of
// the documentation, never real ones.
func TestSigV4PublishedVector(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	SignRequest(req, nil, Creds{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "us-east-1", "service", now)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
