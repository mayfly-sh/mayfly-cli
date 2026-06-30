package credentials

import (
	"errors"

	"github.com/zalando/go-keyring"
)

// keyringService is the service name under which secrets are filed in the OS
// keystore (macOS Keychain, Linux Secret Service, Windows Credential Manager).
const keyringService = "mayfly-cli"

// keyringStore is backed by the OS keystore via go-keyring. The concrete
// backend (Keychain vs Secret Service) is chosen by the OS at runtime; we report
// a name reflecting the platform for observability.
type keyringStore struct {
	name string
}

func (k *keyringStore) Name() string { return k.name }

func (k *keyringStore) Get(key string) (string, error) {
	secret, err := keyring.Get(keyringService, key)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", err
	}
	return secret, nil
}

func (k *keyringStore) Set(key, secret string) error {
	return keyring.Set(keyringService, key, secret)
}

func (k *keyringStore) Delete(key string) error {
	err := keyring.Delete(keyringService, key)
	if err != nil && errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}
