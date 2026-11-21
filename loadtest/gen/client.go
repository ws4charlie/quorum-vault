package gen

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// Client calls the core API as the actors of the target. Every call is counted by outcome.
type Client struct {
	t    *Target
	hc   *http.Client
	tok  *tokens
	next atomic.Uint64
	Obs  *Observer
}

// Failure is an error with a kind that is stable enough to count: "timeout", "conn", "http_4xx", "http_5xx", "token".
type Failure struct {
	Kind string
	Msg  string
}

func (f *Failure) Error() string { return f.Kind + ": " + f.Msg }

func kindOf(err error) string {
	var f *Failure
	if errors.As(err, &f) {
		return f.Kind
	}
	return "other"
}

func NewClient(t *Target, obs *Observer) (*Client, error) {
	tc, err := tlsConfig(t.CAFile, t.ServerName)
	if err != nil {
		return nil, err
	}
	tk, err := newTokens(t.Token)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, MaxIdleConnsPerHost: 512, MaxIdleConns: 1024, IdleConnTimeout: 90 * time.Second,
		DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext}}
	return &Client{t: t, hc: hc, tok: tk, Obs: obs}, nil
}

// Call makes one request as actor and decodes a JSON object answer. hdr adds headers. It returns the HTTP status; a status of 400 or more is also an error.
func (c *Client) Call(ctx context.Context, actor, method, path string, hdr map[string]string, body any) (int, map[string]any, error) {
	start := time.Now()
	code, out, err := c.call(ctx, actor, method, path, hdr, body)
	c.Obs.request(method, path, time.Since(start), err)
	return code, out, err
}

func (c *Client) call(ctx context.Context, actor, method, path string, hdr map[string]string, body any) (int, map[string]any, error) {
	tok, err := c.tok.bearer(actor)
	if err != nil {
		return 0, nil, &Failure{"token", err.Error()}
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	base := c.t.API[int(c.next.Add(1))%len(c.t.API)]
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
			return 0, nil, &Failure{"timeout", err.Error()}
		}
		return 0, nil, &Failure{"conn", err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode >= 500 {
		return resp.StatusCode, out, &Failure{"http_5xx", fmt.Sprintf("%s %s: %d %s", method, path, resp.StatusCode, trim(raw))}
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, out, &Failure{fmt.Sprintf("http_%d", resp.StatusCode), fmt.Sprintf("%s %s: %s", method, path, trim(raw))}
	}
	return resp.StatusCode, out, nil
}

func trim(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	return string(b)
}
