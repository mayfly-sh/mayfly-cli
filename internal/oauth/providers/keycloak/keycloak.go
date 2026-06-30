// Package keycloak implements the Mayfly oauth.Provider interface for Keycloak
// (and, by extension, generic OIDC servers that expose the device flow).
//
// It demonstrates that a second, structurally different provider plugs into the
// same framework as GitHub without changing any calling code: only this file is
// added and the provider is registered.
package keycloak

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

// Config configures the Keycloak/OIDC provider. IssuerURL is the realm base,
// e.g. https://kc.example.com/realms/engineering. Endpoint overrides allow
// non-Keycloak OIDC servers; when empty, Keycloak conventions are derived from
// the issuer.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string // optional; public clients omit it
	Scopes       string // default "openid profile email"

	DeviceAuthEndpoint string
	TokenEndpoint      string
	UserinfoEndpoint   string
}

// Provider is the Keycloak/OIDC device-flow provider.
type Provider struct {
	cfg  Config
	http *http.Client
}

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// New builds the provider, deriving standard Keycloak endpoints from the issuer
// when explicit endpoints are not supplied.
func New(cfg Config, client *http.Client) *Provider {
	issuer := strings.TrimRight(cfg.IssuerURL, "/")
	if cfg.Scopes == "" {
		cfg.Scopes = "openid profile email"
	}
	if cfg.DeviceAuthEndpoint == "" {
		cfg.DeviceAuthEndpoint = issuer + "/protocol/openid-connect/auth/device"
	}
	if cfg.TokenEndpoint == "" {
		cfg.TokenEndpoint = issuer + "/protocol/openid-connect/token"
	}
	if cfg.UserinfoEndpoint == "" {
		cfg.UserinfoEndpoint = issuer + "/protocol/openid-connect/userinfo"
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Provider{cfg: cfg, http: client}
}

// Metadata identifies the provider.
func (p *Provider) Metadata() oauth.Metadata {
	return oauth.Metadata{ID: "keycloak", DisplayName: "Keycloak", Kind: oauth.KindOIDCDevice}
}

// StartDeviceAuthorization begins the OIDC device flow.
func (p *Provider) StartDeviceAuthorization(ctx context.Context) (*oauth.DeviceAuthorization, error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("scope", p.cfg.Scopes)
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}

	var body struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := p.postForm(ctx, p.cfg.DeviceAuthEndpoint, form, &body); err != nil {
		return nil, err
	}
	return &oauth.DeviceAuthorization{
		DeviceCode:              body.DeviceCode,
		UserCode:                body.UserCode,
		VerificationURI:         body.VerificationURI,
		VerificationURIComplete: body.VerificationURIComplete,
		ExpiresIn:               body.ExpiresIn,
		Interval:                body.Interval,
	}, nil
}

// PollToken exchanges the device code for an OIDC token set.
func (p *Provider) PollToken(ctx context.Context, deviceCode string) (*oauth.PollResult, error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("device_code", deviceCode)
	form.Set("grant_type", deviceGrantType)
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}

	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
	}
	// The token endpoint returns 400 for the pending states, so we accept both
	// 200 and 400 and classify on the body.
	if err := p.postFormAllow(ctx, p.cfg.TokenEndpoint, form, &body, http.StatusOK, http.StatusBadRequest); err != nil {
		return nil, err
	}

	if body.AccessToken != "" {
		var expiry time.Time
		if body.ExpiresIn > 0 {
			expiry = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
		}
		return &oauth.PollResult{
			State: oauth.PollApproved,
			Token: &oauth.Token{
				AccessToken:  body.AccessToken,
				RefreshToken: body.RefreshToken,
				IDToken:      body.IDToken,
				TokenType:    body.TokenType,
				Scope:        body.Scope,
				Expiry:       expiry,
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
		return nil, fmt.Errorf("keycloak: unexpected token response error %q", body.Error)
	}
}

// FetchIdentity resolves the OIDC userinfo for the token.
func (p *Provider) FetchIdentity(ctx context.Context, token *oauth.Token) (*oauth.Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak: userinfo returned status %d", resp.StatusCode)
	}

	var u struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
		Name              string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("keycloak: decode userinfo: %w", err)
	}
	return &oauth.Identity{
		Provider: "keycloak",
		Subject:  u.Sub,
		Username: u.PreferredUsername,
		Email:    u.Email,
		Name:     u.Name,
	}, nil
}

func (p *Provider) postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	return p.postFormAllow(ctx, endpoint, form, out, http.StatusOK)
}

func (p *Provider) postFormAllow(ctx context.Context, endpoint string, form url.Values, out any, okStatuses ...int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("keycloak: %w", err)
	}
	defer resp.Body.Close()

	allowed := false
	for _, s := range okStatuses {
		if resp.StatusCode == s {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("keycloak: endpoint returned status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("keycloak: decode response: %w", err)
	}
	return nil
}
