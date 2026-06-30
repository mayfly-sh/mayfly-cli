package mayflyserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/mayfly-ssh/mayfly-cli/internal/clientcontext"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth"
	"github.com/mayfly-ssh/mayfly-cli/internal/performance"
)

func newProvider(server string) *Provider {
	return New(Config{
		ID: "github", DisplayName: "GitHub", Kind: oauth.KindOAuth2Device,
		Server: server, Context: clientcontext.New("test"),
		Profiler: performance.New(false), Retries: 0,
	})
}

func TestServerBackedDeviceFlow(t *testing.T) {
	var polls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/device/start":
			if got := r.URL.Query().Get("provider"); got != "github" {
				t.Errorf("provider query = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": "dc", "user_code": "ABCD-1234",
				"verification_uri": "https://example.test/device", "expires_in": 900, "interval": 1,
			})
		case "/api/v1/auth/device/poll":
			var body pollRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Provider != "github" {
				t.Errorf("poll provider = %q", body.Provider)
			}
			if atomic.AddInt32(&polls, 1) == 1 {
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "approved", "access_token": "tok-xyz",
				"identity": map[string]any{
					"provider": "github", "subject": "42", "username": "vasugarg", "email": "v@example.test",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newProvider(srv.URL)

	auth, err := p.StartDeviceAuthorization(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if auth.UserCode != "ABCD-1234" || auth.Interval != 1 {
		t.Fatalf("auth = %+v", auth)
	}

	first, err := p.PollToken(context.Background(), auth.DeviceCode)
	if err != nil || first.State != oauth.PollPending {
		t.Fatalf("first poll = %+v %v", first, err)
	}

	second, err := p.PollToken(context.Background(), auth.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if second.State != oauth.PollApproved || second.Token.AccessToken != "tok-xyz" {
		t.Fatalf("approved poll = %+v", second)
	}
	if second.Identity == nil || second.Identity.Username != "vasugarg" || second.Identity.Subject != "42" {
		t.Fatalf("identity = %+v", second.Identity)
	}
}

func TestServerBackedFetchIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/whoami" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"github_login": "vasugarg", "github_id": 42, "email": "v@example.test",
		})
	}))
	defer srv.Close()

	p := newProvider(srv.URL)
	id, err := p.FetchIdentity(context.Background(), &oauth.Token{AccessToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if id.Username != "vasugarg" || id.Subject != "42" {
		t.Fatalf("identity = %+v", id)
	}
}

func TestConfigured(t *testing.T) {
	if newProvider("").Configured() {
		t.Fatal("empty server should be unconfigured")
	}
	if !newProvider("https://srv").Configured() {
		t.Fatal("server set should be configured")
	}
}
