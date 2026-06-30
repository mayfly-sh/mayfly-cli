// Package credentials provides a platform-independent secure credential store.
//
// Commands never know where a secret lives: they depend only on the Store
// interface. The factory selects the strongest backend available on the host
// (OS keystore first, encrypted file as a fallback) and exposes extension
// points for Windows Credential Manager, TPM/Secure Enclave-sealed storage, and
// HSMs without changing callers.
package credentials

import (
	"errors"
	"fmt"
)

// ErrNotFound is returned when a key is absent from the store.
var ErrNotFound = errors.New("credential not found")

// Store is the abstraction every command depends on. Implementations must be
// safe for use by a single CLI process; concurrency across processes is the
// backend's concern (OS keystores handle it; the file backend uses 0600 files).
type Store interface {
	// Name returns a stable, non-secret backend identifier (e.g. "keychain",
	// "secret-service", "encrypted-file"). It is recorded in ClientContext.
	Name() string
	// Get returns the secret for key, or ErrNotFound.
	Get(key string) (string, error)
	// Set stores (or replaces) the secret for key.
	Set(key, secret string) error
	// Delete removes key. Deleting a missing key returns nil.
	Delete(key string) error
}

// Key builds a namespaced credential key from a provider id and an account
// (typically the server URL or username). Keeping key construction central
// guarantees every backend uses identical names.
func Key(provider, account string) string {
	return fmt.Sprintf("%s:%s", provider, account)
}
