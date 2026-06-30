package keycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRefreshExchangesRefreshToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "refresh_token" {
			t.Fatalf("grant_type = %q", got)
		}
		if got := r.Form.Get("refresh_token"); got != "old-refresh" {
			t.Fatalf("refresh_token = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":300,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	p := New(Config{
		IssuerURL:     "https://issuer.test/realms/x",
		ClientID:      "cli",
		TokenEndpoint: srv.URL,
	}, srv.Client())

	tok, err := p.Refresh(context.Background(), "old-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "new-access" {
		t.Fatalf("access = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "new-refresh" {
		t.Fatalf("refresh = %q", tok.RefreshToken)
	}
	if tok.Expiry.IsZero() {
		t.Fatal("expiry should be set from expires_in")
	}
}

func TestRefreshKeepsOldRefreshWhenNotRotated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a2","expires_in":60}`))
	}))
	defer srv.Close()

	p := New(Config{IssuerURL: "https://i.test/realms/x", ClientID: "cli", TokenEndpoint: srv.URL}, srv.Client())
	tok, err := p.Refresh(context.Background(), "keep-me")
	if err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken != "keep-me" {
		t.Fatalf("expected old refresh retained, got %q", tok.RefreshToken)
	}
}

func TestConfigured(t *testing.T) {
	if New(Config{}, nil).Configured() {
		t.Fatal("empty config should be unconfigured")
	}
	if !New(Config{IssuerURL: "https://i", ClientID: "c"}, nil).Configured() {
		t.Fatal("issuer+client should be configured")
	}
}
