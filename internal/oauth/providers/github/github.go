// Package github implements the Mayfly oauth.Provider interface for GitHub's
// OAuth device flow (RFC 8628). It is registered in the provider registry and
// is otherwise indistinguishable to callers from any other provider.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mayfly-ssh/mayfly-cli/internal/oauth"
)

// Config configures the GitHub provider. Defaults target github.com; override
// the base URLs for GitHub Enterprise.
type Config struct {
	ClientID      string
	Scopes        string
	DeviceBaseURL string // default https://github.com
	APIBaseURL    string // default https://api.github.com
}

// Provider is the GitHub device-flow provider.
type Provider struct {
	cfg  Config
	http *http.Client
}

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// New builds a GitHub provider, applying defaults for unset endpoints.
func New(cfg Config, client *http.Client) *Provider {
	if cfg.DeviceBaseURL == "" {
		cfg.DeviceBaseURL = "https://github.com"
	}
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = "https://api.github.com"
	}
	cfg.DeviceBaseURL = strings.TrimRight(cfg.DeviceBaseURL, "/")
	cfg.APIBaseURL = strings.TrimRight(cfg.APIBaseURL, "/")
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Provider{cfg: cfg, http: client}
}

// Metadata identifies the provider.
func (p *Provider) Metadata() oauth.Metadata {
	return oauth.Metadata{ID: "github", DisplayName: "GitHub", Kind: oauth.KindOAuth2Device}
}

// Configured reports whether a client id is set (required for the device flow).
func (p *Provider) Configured() bool {
	return strings.TrimSpace(p.cfg.ClientID) != ""
}

// StartDeviceAuthorization begins the device flow.
func (p *Provider) StartDeviceAuthorization(ctx context.Context) (*oauth.DeviceAuthorization, error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("scope", p.cfg.Scopes)

	var body struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := p.postForm(ctx, p.cfg.DeviceBaseURL+"/login/device/code", form, &body); err != nil {
		return nil, err
	}
	return &oauth.DeviceAuthorization{
		DeviceCode:      body.DeviceCode,
		UserCode:        body.UserCode,
		VerificationURI: body.VerificationURI,
		ExpiresIn:       body.ExpiresIn,
		Interval:        body.Interval,
	}, nil
}

// PollToken exchanges the device code for a token, classifying GitHub's pending
// states.
func (p *Provider) PollToken(ctx context.Context, deviceCode string) (*oauth.PollResult, error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("device_code", deviceCode)
	form.Set("grant_type", deviceGrantType)

	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
	}
	if err := p.postForm(ctx, p.cfg.DeviceBaseURL+"/login/oauth/access_token", form, &body); err != nil {
		return nil, err
	}

	if body.AccessToken != "" {
		return &oauth.PollResult{
			State: oauth.PollApproved,
			Token: &oauth.Token{
				AccessToken: body.AccessToken,
				TokenType:   body.TokenType,
				Scope:       body.Scope,
			},
		}, nil
	}

	switch body.Error {
	case "authorization_pending":
		return &oauth.PollResult{State: oauth.PollPending}, nil
	case "slow_down":
		return &oauth.PollResult{State: oauth.PollSlowDown}, nil
	case "expired_token":
		return &oauth.PollResult{State: oauth.PollExpired}, nil
	case "access_denied":
		return &oauth.PollResult{State: oauth.PollDenied}, nil
	default:
		return nil, fmt.Errorf("github: unexpected token response error %q", body.Error)
	}
}

// FetchIdentity resolves the GitHub user behind the token.
func (p *Provider) FetchIdentity(ctx context.Context, token *oauth.Token) (*oauth.Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.APIBaseURL+"/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: identity lookup returned status %d", resp.StatusCode)
	}

	var u struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("github: decode identity: %w", err)
	}
	return &oauth.Identity{
		Provider: "github",
		Subject:  fmt.Sprintf("%d", u.ID),
		Username: u.Login,
		Email:    u.Email,
		Name:     u.Name,
	}, nil
}

func (p *Provider) postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("github: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github: endpoint returned status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("github: decode response: %w", err)
	}
	return nil
}
