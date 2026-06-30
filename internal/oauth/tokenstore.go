package oauth

import (
	"encoding/json"
	"errors"

	"github.com/mayfly-ssh/mayfly-cli/internal/credentials"
)

// TokenStore persists normalized tokens behind the platform credential store.
// Callers depend on this interface and never touch the credential backend
// directly.
type TokenStore interface {
	Save(provider, account string, t *Token) error
	Load(provider, account string) (*Token, error)
	Delete(provider, account string) error
}

// credentialTokenStore serializes Tokens as JSON into a credentials.Store.
type credentialTokenStore struct {
	store credentials.Store
}

// NewTokenStore wraps a credential store as a TokenStore.
func NewTokenStore(store credentials.Store) TokenStore {
	return &credentialTokenStore{store: store}
}

func (c *credentialTokenStore) Save(provider, account string, t *Token) error {
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return c.store.Set(credentials.Key(provider, account), string(data))
}

func (c *credentialTokenStore) Load(provider, account string) (*Token, error) {
	raw, err := c.store.Get(credentials.Key(provider, account))
	if err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			return nil, ErrNoToken
		}
		return nil, err
	}
	var t Token
	if err := json.Unmarshal([]byte(raw), &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (c *credentialTokenStore) Delete(provider, account string) error {
	return c.store.Delete(credentials.Key(provider, account))
}

// ErrNoToken indicates no stored token for the provider/account.
var ErrNoToken = errors.New("no stored token")
