// Package mayfly is the stable public API surface of the Mayfly CLI SDK.
//
// Everything under internal/ is private and may change without notice. External
// consumers (and future Mayfly tooling) should depend only on the aliases and
// constructors re-exported here. These are intentionally thin aliases so the
// implementation can evolve while the import path and types stay stable.
package mayfly

import (
	"github.com/mayfly-ssh/mayfly-cli/internal/clientcontext"
	"github.com/mayfly-ssh/mayfly-cli/internal/credentials"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth"
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
	Provider     = oauth.Provider
	Registry     = oauth.Registry
	Metadata     = oauth.Metadata
	OAuthSession = oauth.Session
	OAuthToken   = oauth.Token
	OAuthIdent   = oauth.Identity
	TokenStore   = oauth.TokenStore
)

// NewRegistry returns an empty provider registry.
func NewRegistry() *Registry { return oauth.NewRegistry() }

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
