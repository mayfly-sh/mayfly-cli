package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/mayfly-ssh/mayfly-cli/internal/clientcontext"
)

func testContext() *clientcontext.ClientContext {
	cc := clientcontext.New("file")
	cc.SessionID = "sess-1"
	return cc
}

func TestDoInjectsContextAndAuth(t *testing.T) {
	var gotAuth, gotSession, gotUA, gotReqID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotSession = r.Header.Get(clientcontext.HeaderSessionID)
		gotUA = r.Header.Get("User-Agent")
		gotReqID = r.Header.Get(clientcontext.HeaderRequestID)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, testContext(),
		WithTokenSource(func(context.Context) (string, error) { return "tok-123", nil }))
	if err != nil {
		t.Fatal(err)
	}

	var out struct {
		OK bool `json:"ok"`
	}
	if err := c.Do(context.Background(), http.MethodGet, "/api/v1/test", nil, &out); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !out.OK {
		t.Error("response not decoded")
	}
	if gotAuth != "Bearer tok-123" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotSession != "sess-1" {
		t.Errorf("session header = %q", gotSession)
	}
	if gotUA == "" {
		t.Error("User-Agent not set")
	}
	if gotReqID == "" {
		t.Error("Request-Id not set")
	}
}

func TestDoStructuredError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"denied","message":"not allowed"}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, testContext(), WithRetries(0))
	if err != nil {
		t.Fatal(err)
	}
	err = c.Do(context.Background(), http.MethodGet, "/x", nil, nil)
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("error type = %T, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusForbidden || apiErr.Message != "not allowed" {
		t.Errorf("APIError = %+v", apiErr)
	}
}

func TestDoRetriesOn503(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, testContext(), WithRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Do(context.Background(), http.MethodGet, "/x", nil, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if atomic.LoadInt32(&calls) < 2 {
		t.Errorf("expected retry, calls = %d", calls)
	}
}

func TestNewRejectsNonHTTPS(t *testing.T) {
	if _, err := New("http://remote.example", testContext()); err == nil {
		t.Error("expected http:// to be rejected for non-localhost")
	}
	if _, err := New("http://localhost:8080", testContext()); err != nil {
		t.Errorf("localhost http should be allowed: %v", err)
	}
}
