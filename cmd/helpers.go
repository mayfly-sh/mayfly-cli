package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mayfly-ssh/mayfly-cli/internal/account"
	"github.com/mayfly-ssh/mayfly-cli/internal/certcache"
	"github.com/mayfly-ssh/mayfly-cli/internal/certs"
	"github.com/mayfly-ssh/mayfly-cli/internal/client"
	"github.com/mayfly-ssh/mayfly-cli/internal/config"
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

// adminClient builds an authenticated API client for the active account, used by
// the admin/operational endpoints (deny-by-default authorized server-side).
func (a *App) adminClient() (*client.Client, error) {
	acct, err := a.requireActiveAccount()
	if err != nil {
		return nil, err
	}
	provider, err := a.provider(acct.Provider)
	if err != nil {
		return nil, err
	}
	return a.apiClient(a.activeTokenSource(acct, provider))
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

// certCacheRoot resolves the effective certificate cache directory.
func (a *App) certCacheRoot() string {
	if a.Config.CertCachePath != "" {
		return a.Config.CertCachePath
	}
	if p := config.DefaultCertCachePath(); p != "" {
		return p
	}
	return filepath.Join(os.TempDir(), "mayfly", "certs")
}

// certCache returns a cache rooted at the effective cache directory.
func (a *App) certCache() *certcache.Cache {
	return certcache.New(a.certCacheRoot())
}

// certManager returns a certificate lifecycle manager over the cache.
func (a *App) certManager() *certs.Manager {
	return certs.NewManager(a.certCache(), a.Profiler)
}

// identityFor maps an account to its cache identity (profile-scoped).
func (a *App) identityFor(acct account.Account) certcache.Identity {
	return certcache.Identity{
		Profile:  a.ProfileName,
		Provider: acct.Provider,
		Subject:  acct.Subject,
		Server:   a.Config.ServerURL,
	}
}

// renewThreshold is the remaining-lifetime below which a cached certificate is
// reissued rather than reused.
func (a *App) renewThreshold() time.Duration {
	return time.Duration(a.Config.RenewThresholdSec) * time.Second
}

// printJSON writes v as indented JSON.
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
