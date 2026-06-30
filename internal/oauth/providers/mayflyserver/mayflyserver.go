// Package mayflyserver implements oauth.Provider by brokering the device flow
// through the mayfly-server rather than talking to the identity provider
// directly. This is the secure, canonical login path: the OAuth client secrets
// stay server-side, the server enforces deny-by-default authorization, and every
// authorization is recorded in the server's tamper-evident audit log.
//
// The same implementation serves every upstream provider (GitHub, Keycloak,
// future OIDC): only the provider id sent to the server (?provider=) differs, so
// the server's 011A provider abstraction selects the real IdP. The client thus
// reuses the 011A oauth.Provider abstraction with a server-backed body.
package mayflyserver

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/mayfly-ssh/mayfly-cli/internal/client"
	"github.com/mayfly-ssh/mayfly-cli/internal/clientcontext"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth"
	"github.com/mayfly-ssh/mayfly-cli/internal/performance"
)

// Config configures a server-backed provider.
type Config struct {
	ID          string // provider id sent to the server (e.g. "github")
	DisplayName string
	Kind        oauth.Kind
	Server      string
	Context     *clientcontext.ClientContext
	Profiler    *performance.Profiler
	Timeout     time.Duration
	Retries     int
}

// Provider brokers a provider's device flow through the mayfly-server.
type Provider struct {
	cfg Config
}

// New builds a server-backed provider.
func New(cfg Config) *Provider { return &Provider{cfg: cfg} }

// Metadata identifies the provider.
func (p *Provider) Metadata() oauth.Metadata {
	return oauth.Metadata{ID: p.cfg.ID, DisplayName: p.cfg.DisplayName, Kind: p.cfg.Kind}
}

// Configured reports whether a server URL is set (required to broker the flow).
func (p *Provider) Configured() bool { return p.cfg.Server != "" }

func (p *Provider) newClient(ts client.TokenSource) (*client.Client, error) {
	opts := []client.Option{client.WithProfiler(p.cfg.Profiler)}
	if p.cfg.Timeout > 0 {
		opts = append(opts, client.WithTimeout(p.cfg.Timeout))
	}
	if p.cfg.Retries >= 0 {
		opts = append(opts, client.WithRetries(p.cfg.Retries))
	}
	if ts != nil {
		opts = append(opts, client.WithTokenSource(ts))
	}
	return client.New(p.cfg.Server, p.cfg.Context, opts...)
}

type deviceStartResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// StartDeviceAuthorization begins the device flow via the server.
func (p *Provider) StartDeviceAuthorization(ctx context.Context) (*oauth.DeviceAuthorization, error) {
	c, err := p.newClient(nil)
	if err != nil {
		return nil, err
	}
	var resp deviceStartResponse
	path := "/api/v1/auth/device/start?provider=" + p.cfg.ID
	if err := c.Do(ctx, "POST", path, nil, &resp); err != nil {
		return nil, err
	}
	return &oauth.DeviceAuthorization{
		DeviceCode:      resp.DeviceCode,
		UserCode:        resp.UserCode,
		VerificationURI: resp.VerificationURI,
		ExpiresIn:       resp.ExpiresIn,
		Interval:        resp.Interval,
	}, nil
}

type pollIdentity struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

type pollResponse struct {
	Status      string        `json:"status"`
	AccessToken string        `json:"access_token"`
	Identity    *pollIdentity `json:"identity"`
}

type pollRequest struct {
	DeviceCode string `json:"device_code"`
	Provider   string `json:"provider"`
}

// PollToken polls the server for the device-flow result.
func (p *Provider) PollToken(ctx context.Context, deviceCode string) (*oauth.PollResult, error) {
	c, err := p.newClient(nil)
	if err != nil {
		return nil, err
	}
	var resp pollResponse
	body := pollRequest{DeviceCode: deviceCode, Provider: p.cfg.ID}
	if err := c.Do(ctx, "POST", "/api/v1/auth/device/poll", body, &resp); err != nil {
		return nil, err
	}

	switch resp.Status {
	case "pending":
		return &oauth.PollResult{State: oauth.PollPending}, nil
	case "slow_down":
		return &oauth.PollResult{State: oauth.PollSlowDown}, nil
	case "expired":
		return &oauth.PollResult{State: oauth.PollExpired}, nil
	case "denied":
		return &oauth.PollResult{State: oauth.PollDenied}, nil
	case "approved":
		res := &oauth.PollResult{
			State: oauth.PollApproved,
			Token: &oauth.Token{AccessToken: resp.AccessToken, TokenType: "bearer"},
		}
		if resp.Identity != nil {
			res.Identity = &oauth.Identity{
				Provider: p.cfg.ID,
				Subject:  resp.Identity.Subject,
				Username: resp.Identity.Username,
				Email:    resp.Identity.Email,
				Name:     resp.Identity.Name,
			}
		}
		return res, nil
	default:
		return nil, fmt.Errorf("server returned unknown poll status %q", resp.Status)
	}
}

type whoamiResponse struct {
	GitHubLogin string `json:"github_login"`
	GitHubID    int64  `json:"github_id"`
	Name        string `json:"name"`
	Email       string `json:"email"`
}

// FetchIdentity resolves the identity for a token via the server's whoami
// endpoint. The endpoint is GitHub-shaped today, so this is most useful for the
// GitHub provider; other providers obtain identity directly from the approved
// poll response and rarely need this call.
func (p *Provider) FetchIdentity(ctx context.Context, token *oauth.Token) (*oauth.Identity, error) {
	c, err := p.newClient(func(context.Context) (string, error) { return token.AccessToken, nil })
	if err != nil {
		return nil, err
	}
	var w whoamiResponse
	if err := c.Do(ctx, "GET", "/api/v1/auth/whoami", nil, &w); err != nil {
		return nil, err
	}
	return &oauth.Identity{
		Provider: p.cfg.ID,
		Subject:  strconv.FormatInt(w.GitHubID, 10),
		Username: w.GitHubLogin,
		Email:    w.Email,
		Name:     w.Name,
	}, nil
}
