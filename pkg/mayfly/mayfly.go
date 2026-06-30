// Package mayfly is the stable public API surface of the Mayfly CLI SDK.
//
// Everything under internal/ is private and may change without notice. External
// consumers (and future Mayfly tooling) should depend only on the aliases and
// constructors re-exported here. These are intentionally thin aliases so the
// implementation can evolve while the import path and types stay stable.
package mayfly

import (
	"context"

	"github.com/mayfly-ssh/mayfly-cli/internal/account"
	"github.com/mayfly-ssh/mayfly-cli/internal/authflow"
	"github.com/mayfly-ssh/mayfly-cli/internal/certcache"
	"github.com/mayfly-ssh/mayfly-cli/internal/certs"
	"github.com/mayfly-ssh/mayfly-cli/internal/clientcontext"
	"github.com/mayfly-ssh/mayfly-cli/internal/credentials"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth"
	"github.com/mayfly-ssh/mayfly-cli/internal/profile"
	"github.com/mayfly-ssh/mayfly-cli/internal/ssh"
	"github.com/mayfly-ssh/mayfly-cli/internal/version"
)

// Build identity.
type Info = version.Info

// VersionInfo returns the CLI build identity.
func VersionInfo() Info { return version.Get() }

// Client identity / context.
type ClientContext = clientcontext.ClientContext

// NewClientContext builds a per-invocation client context using the given
// credential backend name.
func NewClientContext(storageBackend string) *ClientContext {
	return clientcontext.New(storageBackend)
}

// OAuth framework public types.
type (
	Provider            = oauth.Provider
	RefreshableProvider = oauth.RefreshableProvider
	Registry            = oauth.Registry
	Metadata            = oauth.Metadata
	Capabilities        = oauth.Capabilities
	OAuthSession        = oauth.Session
	OAuthToken          = oauth.Token
	OAuthIdent          = oauth.Identity
	TokenStore          = oauth.TokenStore
)

// NewRegistry returns an empty provider registry.
func NewRegistry() *Registry { return oauth.NewRegistry() }

// CapabilitiesOf reports a provider's capabilities.
func CapabilitiesOf(p Provider) Capabilities { return oauth.CapabilitiesOf(p) }

// Account management public types.
type (
	Account      = account.Account
	AccountStore = account.Store
	Profile      = profile.Profile
	ProfileStore = profile.Store
)

// NewAccountStore opens the account index at path.
func NewAccountStore(path string) *AccountStore { return account.NewStore(path) }

// NewProfileStore opens the profiles file at path.
func NewProfileStore(path string) *ProfileStore { return profile.NewStore(path) }

// Login runs the interactive device-authorization flow and persists the result.
type LoginOptions = authflow.Options

// Login executes the device-flow login described by opts.
func Login(ctx context.Context, opts LoginOptions) (*Account, error) {
	return authflow.Login(ctx, opts)
}

// Credential storage public types.
type (
	CredentialStore   = credentials.Store
	CredentialBackend = credentials.Backend
)

// Credential backend selectors.
const (
	BackendAuto    = credentials.BackendAuto
	BackendKeyring = credentials.BackendKeyring
	BackendFile    = credentials.BackendFile
)

// OpenCredentialStore opens the requested credential backend.
func OpenCredentialStore(b CredentialBackend) (CredentialStore, error) {
	return credentials.Open(b)
}

// NewTokenStore wraps a credential store as an OAuth token store.
func NewTokenStore(s CredentialStore) TokenStore { return oauth.NewTokenStore(s) }

// SSH / certificate lifecycle public types (011C).
type (
	CertManager      = certs.Manager
	CertEnsureResult = certs.Result
	CertEnsureOption = certs.EnsureOptions
	CertCache        = certcache.Cache
	CertIdentity     = certcache.Identity
	CertEntry        = certcache.Entry
	CertInfo         = ssh.CertInfo
	SSHOptions       = ssh.Options
	SSHParsedArgs    = ssh.Parsed
)

// NewCertCache opens a certificate cache rooted at dir.
func NewCertCache(root string) *CertCache { return certcache.New(root) }

// NewCertManager returns a certificate lifecycle manager over a cache.
func NewCertManager(c *CertCache) *CertManager { return certs.NewManager(c, nil) }

// InspectCertificate parses an OpenSSH certificate (authorized_keys line).
func InspectCertificate(authorizedKey []byte) (*CertInfo, error) {
	return ssh.InspectCertificate(authorizedKey)
}

// ParseSSHArgs splits a `mayfly ssh` invocation into Mayfly flags and OpenSSH passthrough.
func ParseSSHArgs(args []string) (*SSHParsedArgs, error) { return ssh.ParseArgs(args) }
