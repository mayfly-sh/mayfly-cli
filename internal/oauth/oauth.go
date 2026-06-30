// Package oauth defines Mayfly's provider-agnostic authentication framework.
//
// Every identity provider (GitHub, Keycloak, and future GitLab/Okta/Azure/
// Google/generic OIDC) implements the same Provider interface and registers in
// a Registry. Calling code selects a provider by ID and never branches on the
// concrete provider type, so adding a provider is "write one implementation and
// register it" rather than editing authentication logic.
package oauth

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Kind classifies a provider's protocol, for diagnostics only.
type Kind string

const (
	KindOAuth2Device Kind = "oauth2-device"
	KindOIDCDevice   Kind = "oidc-device"
)

// Metadata is non-secret descriptive information about a provider.
type Metadata struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Kind        Kind   `json:"kind"`
}

// DeviceAuthorization is the result of starting an RFC 8628 device flow.
type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Token is a normalized OAuth/OIDC token set. Secrets here must never be logged.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
}

// Expired reports whether the token is past its expiry (with no skew). A zero
// Expiry is treated as "never expires (unknown)".
func (t *Token) Expired() bool {
	return !t.Expiry.IsZero() && time.Now().After(t.Expiry)
}

// Identity is the normalized, provider-agnostic authenticated identity.
type Identity struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"` // stable provider-unique id
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
}

// PollState is the coarse outcome of polling a device flow.
type PollState string

const (
	PollPending  PollState = "pending"
	PollSlowDown PollState = "slow_down"
	PollApproved PollState = "approved"
	PollExpired  PollState = "expired"
	PollDenied   PollState = "denied"
)

// PollResult carries the poll state and, when approved, the token and
// (optionally) the resolved identity. Providers that can return the identity
// alongside the token (e.g. the server-brokered flow) set Identity to spare the
// caller a separate identity lookup.
type PollResult struct {
	State    PollState
	Token    *Token
	Identity *Identity
}

// Provider is the single interface every identity provider implements.
type Provider interface {
	Metadata() Metadata
	// StartDeviceAuthorization begins an RFC 8628 device flow.
	StartDeviceAuthorization(ctx context.Context) (*DeviceAuthorization, error)
	// PollToken exchanges a device code for a token, reporting the poll state.
	PollToken(ctx context.Context, deviceCode string) (*PollResult, error)
	// FetchIdentity resolves the authenticated identity for a token.
	FetchIdentity(ctx context.Context, token *Token) (*Identity, error)
}

// Registry holds the available providers keyed by ID. It is the single place
// the rest of the CLI resolves a provider, eliminating provider switch
// statements elsewhere.
type Registry struct {
	providers map[string]Provider
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{providers: map[string]Provider{}}
}

// Register adds a provider. It errors on a duplicate or empty ID so
// misconfiguration is caught at startup.
func (r *Registry) Register(p Provider) error {
	id := p.Metadata().ID
	if id == "" {
		return fmt.Errorf("provider has empty ID")
	}
	if _, exists := r.providers[id]; exists {
		return fmt.Errorf("provider %q already registered", id)
	}
	r.providers[id] = p
	return nil
}

// Get resolves a provider by ID.
func (r *Registry) Get(id string) (Provider, bool) {
	p, ok := r.providers[id]
	return p, ok
}

// List returns provider metadata sorted by ID for deterministic output.
func (r *Registry) List() []Metadata {
	out := make([]Metadata, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p.Metadata())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Session is an in-progress device-flow authentication bound to a provider.
type Session struct {
	Provider      Provider
	Authorization *DeviceAuthorization
	StartedAt     time.Time
}

// StartSession begins a device flow with the given provider.
func StartSession(ctx context.Context, p Provider) (*Session, error) {
	auth, err := p.StartDeviceAuthorization(ctx)
	if err != nil {
		return nil, err
	}
	return &Session{Provider: p, Authorization: auth, StartedAt: time.Now()}, nil
}

// Poll performs a single poll of the session.
func (s *Session) Poll(ctx context.Context) (*PollResult, error) {
	return s.Provider.PollToken(ctx, s.Authorization.DeviceCode)
}

// Interval returns the polling interval, defaulting to 5s if the provider
// omitted one.
func (s *Session) Interval() time.Duration {
	if s.Authorization.Interval <= 0 {
		return 5 * time.Second
	}
	return time.Duration(s.Authorization.Interval) * time.Second
}

// RefreshableProvider is an OPTIONAL capability: providers that issue refresh
// tokens implement it so the CLI can renew access without a new device flow.
// Providers without refresh (e.g. GitHub device flow) simply do not implement
// it. This is additive to the 011A Provider abstraction — callers type-assert.
type RefreshableProvider interface {
	Provider
	// Refresh exchanges a refresh token for a fresh Token.
	Refresh(ctx context.Context, refreshToken string) (*Token, error)
}

// Configurable is an OPTIONAL capability: providers report whether they have the
// configuration required to be usable (e.g. a client id / issuer). Used by
// `auth providers` discovery.
type Configurable interface {
	// Configured reports whether the provider has its required settings.
	Configured() bool
}

// Capabilities describes what a provider supports, for `auth providers`.
type Capabilities struct {
	DeviceFlow    bool `json:"device_flow"`
	BrowserFlow   bool `json:"browser_flow"`
	Refresh       bool `json:"refresh"`
	OIDCDiscovery bool `json:"oidc_discovery"`
}

// CapabilitiesOf derives a provider's capabilities from the interfaces it
// implements and its metadata, so capability reporting needs no per-provider
// boilerplate. BrowserFlow is a declared future extension point (false today).
func CapabilitiesOf(p Provider) Capabilities {
	caps := Capabilities{DeviceFlow: true}
	if _, ok := p.(RefreshableProvider); ok {
		caps.Refresh = true
	}
	if p.Metadata().Kind == KindOIDCDevice {
		caps.OIDCDiscovery = true
	}
	return caps
}

// IsConfigured reports whether a provider is configured, defaulting to true for
// providers that do not implement Configurable.
func IsConfigured(p Provider) bool {
	if c, ok := p.(Configurable); ok {
		return c.Configured()
	}
	return true
}
