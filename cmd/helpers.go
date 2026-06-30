package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/mayfly-ssh/mayfly-cli/internal/account"
	"github.com/mayfly-ssh/mayfly-cli/internal/client"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth"
)

// tokenStore returns the credential-backed OAuth token store.
func (a *App) tokenStore() oauth.TokenStore { return oauth.NewTokenStore(a.Creds) }

// provider resolves a provider id (empty → the effective default).
func (a *App) provider(id string) (oauth.Provider, error) {
	if id == "" {
		id = a.ProviderID()
	}
	p, ok := a.Providers.Get(id)
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", id)
	}
	return p, nil
}

// apiClient builds the reusable HTTP client for the effective server, sharing
// the profiler and (optionally) an auth token source.
func (a *App) apiClient(ts client.TokenSource) (*client.Client, error) {
	if a.Config.ServerURL == "" {
		return nil, fmt.Errorf("no server configured (set --server, MAYFLY_SERVER_URL, or a profile)")
	}
	opts := []client.Option{
		client.WithProfiler(a.Profiler),
		client.WithTimeout(time.Duration(a.Config.RequestTimeoutSec) * time.Second),
		client.WithRetries(a.Config.Retries),
	}
	if ts != nil {
		opts = append(opts, client.WithTokenSource(ts))
	}
	return client.New(a.Config.ServerURL, a.Context, opts...)
}

// loadToken returns the stored token for an account, refreshing it in place when
// it is expired and the provider supports refresh. The refreshed token is
// persisted. Never returns or logs secret material to the caller's output.
func (a *App) loadToken(ctx context.Context, acct account.Account, p oauth.Provider) (*oauth.Token, error) {
	tok, err := a.tokenStore().Load(acct.Provider, acct.CredentialAccount())
	if err != nil {
		return nil, err
	}
	if tok.Expired() {
		ref, ok := p.(oauth.RefreshableProvider)
		if !ok || tok.RefreshToken == "" {
			return tok, fmt.Errorf("token expired and cannot be refreshed; run 'mayfly login %s'", acct.Provider)
		}
		fresh, rerr := ref.Refresh(ctx, tok.RefreshToken)
		if rerr != nil {
			return tok, fmt.Errorf("token refresh failed; run 'mayfly login %s': %w", acct.Provider, rerr)
		}
		if serr := a.tokenStore().Save(acct.Provider, acct.CredentialAccount(), fresh); serr != nil {
			return fresh, fmt.Errorf("storing refreshed token: %w", serr)
		}
		tok = fresh
	}
	return tok, nil
}

// activeTokenSource yields a bearer token for an account, transparently
// refreshing as needed, for use by the HTTP client.
func (a *App) activeTokenSource(acct account.Account, p oauth.Provider) client.TokenSource {
	return func(ctx context.Context) (string, error) {
		tok, err := a.loadToken(ctx, acct, p)
		if err != nil {
			return "", err
		}
		return tok.AccessToken, nil
	}
}

// activeID returns the active account ID for a profile, or "" if none.
func (a *App) activeID(profile string) string {
	if acct, ok := a.Accounts.Active(profile); ok {
		return acct.ID()
	}
	return ""
}

// requireActiveAccount returns the active account for the current profile.
func (a *App) requireActiveAccount() (account.Account, error) {
	acct, ok := a.Accounts.Active(a.ProfileName)
	if !ok {
		return account.Account{}, fmt.Errorf("not logged in (profile %q); run 'mayfly login'", a.ProfileName)
	}
	return acct, nil
}

// serverHealth is the subset of GET /api/v1/health the CLI consumes.
type serverHealth struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// fetchServerInfo calls the unauthenticated health endpoint and returns the
// server version plus response metadata (latency, server Date for clock drift).
func (a *App) fetchServerInfo(ctx context.Context) (serverHealth, *client.Meta, error) {
	c, err := a.apiClient(nil)
	if err != nil {
		return serverHealth{}, nil, err
	}
	var h serverHealth
	meta, err := c.DoWithMeta(ctx, "GET", "/api/v1/health", nil, &h)
	if err != nil {
		return serverHealth{}, meta, err
	}
	return h, meta, nil
}

// printJSON writes v as indented JSON.
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
