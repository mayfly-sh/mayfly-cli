// Package client is the reusable Mayfly API HTTP client.
//
// Every future command issues requests through this client and gets, for free:
// Authorization, the full ClientContext, a per-request Request ID, the shared
// Session ID, a versioned User-Agent, sane timeouts, bounded retries, structured
// errors, and (in developer mode) per-phase timing via httptrace. Commands
// should simply call Do().
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/mayfly-ssh/mayfly-cli/internal/clientcontext"
	"github.com/mayfly-ssh/mayfly-cli/internal/performance"
	"github.com/mayfly-ssh/mayfly-cli/internal/version"
)

// TokenSource supplies a bearer token for outgoing requests. It is called per
// request so tokens can be refreshed transparently. Returning ("", nil) sends
// no Authorization header (e.g. for unauthenticated endpoints).
type TokenSource func(ctx context.Context) (string, error)

// Client is the configured API client.
type Client struct {
	base        *url.URL
	httpClient  *http.Client
	cc          *clientcontext.ClientContext
	prof        *performance.Profiler
	tokenSource TokenSource
	retries     int
	userAgent   string
}

// Option configures a Client.
type Option func(*Client)

// WithProfiler attaches a developer-mode profiler.
func WithProfiler(p *performance.Profiler) Option { return func(c *Client) { c.prof = p } }

// WithTokenSource installs a bearer-token source.
func WithTokenSource(ts TokenSource) Option { return func(c *Client) { c.tokenSource = ts } }

// WithRetries sets the maximum retry attempts for retryable failures.
func WithRetries(n int) Option { return func(c *Client) { c.retries = n } }

// WithTimeout sets the per-request timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.httpClient.Timeout = d }
}

// WithHTTPClient overrides the underlying *http.Client (e.g. custom TLS).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.httpClient = h } }

// New builds a Client targeting serverURL with the given ClientContext.
func New(serverURL string, cc *clientcontext.ClientContext, opts ...Option) (*Client, error) {
	if strings.TrimSpace(serverURL) == "" {
		return nil, fmt.Errorf("server URL is required")
	}
	base, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	if base.Scheme != "https" && base.Hostname() != "localhost" && base.Hostname() != "127.0.0.1" {
		return nil, fmt.Errorf("server URL must use https (got %q)", base.Scheme)
	}

	c := &Client{
		base:       base,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		cc:         cc,
		retries:    2,
		userAgent:  version.UserAgent(),
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Meta carries response-level metadata for callers (e.g. `auth status`) that
// need the server clock and round-trip latency in addition to the decoded body.
type Meta struct {
	StatusCode int
	RequestID  string
	// Date is the server's HTTP `Date` header, when present (used for clock-drift
	// estimation). Zero when absent/unparseable.
	Date time.Time
	// Latency is the measured request round-trip time.
	Latency time.Duration
}

// Do performs a JSON request: it marshals reqBody (nil for none), sends it, and
// decodes a JSON response into respOut (nil to ignore). It returns an *APIError
// for non-2xx responses, carrying the request ID for correlation.
func (c *Client) Do(ctx context.Context, method, path string, reqBody, respOut any) error {
	_, err := c.DoWithMeta(ctx, method, path, reqBody, respOut)
	return err
}

// DoWithMeta is Do plus response metadata (status, server Date, latency). The
// decode/encode/error semantics are identical to Do.
func (c *Client) DoWithMeta(ctx context.Context, method, path string, reqBody, respOut any) (*Meta, error) {
	requestID := clientcontext.NewID()

	var payload []byte
	if reqBody != nil {
		if err := c.prof.Measure(performance.PhaseJSONEncode, func() error {
			var e error
			payload, e = json.Marshal(reqBody)
			return e
		}); err != nil {
			return nil, fmt.Errorf("encode request: %w", err)
		}
	}

	start := time.Now()
	resp, raw, err := c.doWithRetry(ctx, method, path, payload, requestID)
	latency := time.Since(start)
	if err != nil {
		return nil, err
	}

	meta := &Meta{StatusCode: resp.StatusCode, RequestID: requestID, Latency: latency}
	if dateStr := resp.Header.Get("Date"); dateStr != "" {
		if t, perr := http.ParseTime(dateStr); perr == nil {
			meta.Date = t
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return meta, parseAPIError(resp.StatusCode, requestID, raw)
	}

	if respOut != nil && len(raw) > 0 {
		if derr := c.prof.Measure(performance.PhaseJSONDecode, func() error {
			return json.Unmarshal(raw, respOut)
		}); derr != nil {
			return meta, fmt.Errorf("decode response: %w", derr)
		}
	}
	return meta, nil
}

func (c *Client) doWithRetry(ctx context.Context, method, path string, payload []byte, requestID string) (*http.Response, []byte, error) {
	endpoint := c.resolve(path)

	var lastErr error
	attempts := c.retries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt*attempt) * 200 * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		resp, raw, err := c.doOnce(ctx, method, endpoint, payload, requestID)
		if err != nil {
			lastErr = err
			if isRetryableErr(err) {
				continue
			}
			return nil, nil, err
		}
		if isRetryableStatus(resp.StatusCode) && attempt < attempts-1 {
			lastErr = fmt.Errorf("server returned status %d", resp.StatusCode)
			continue
		}
		return resp, raw, nil
	}
	return nil, nil, fmt.Errorf("request failed after %d attempts: %w", attempts, lastErr)
}

func (c *Client) doOnce(ctx context.Context, method, endpoint string, payload []byte, requestID string) (*http.Response, []byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cc != nil {
		c.cc.Apply(req.Header, requestID)
	}
	if c.tokenSource != nil {
		token, terr := c.tokenSource(ctx)
		if terr != nil {
			return nil, nil, fmt.Errorf("resolve auth token: %w", terr)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

	if c.prof.Enabled() {
		req = req.WithContext(withTrace(req.Context(), c.prof))
	}

	stop := c.prof.Start(performance.PhaseHTTP)
	resp, err := c.httpClient.Do(req)
	stop()
	if err != nil {
		return nil, nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	return resp, raw, nil
}

func (c *Client) resolve(path string) string {
	ref, err := url.Parse(path)
	if err != nil {
		return c.base.String() + path
	}
	return c.base.ResolveReference(ref).String()
}

// withTrace records DNS and TLS timings into the profiler in developer mode.
func withTrace(ctx context.Context, prof *performance.Profiler) context.Context {
	var dnsStart, tlsStart time.Time
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				prof.Record(performance.PhaseDNS, time.Since(dnsStart))
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			if !tlsStart.IsZero() {
				prof.Record(performance.PhaseTLS, time.Since(tlsStart))
			}
		},
	}
	return httptrace.WithClientTrace(ctx, trace)
}

func isRetryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func isRetryableErr(err error) bool {
	// Context cancellation/deadline must not be retried.
	if err == nil {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, context.Canceled.Error()) ||
		strings.Contains(msg, context.DeadlineExceeded.Error()) {
		return false
	}
	// Transport-level failures (connection refused/reset, EOF) are retryable.
	return strings.Contains(msg, "http request:")
}
