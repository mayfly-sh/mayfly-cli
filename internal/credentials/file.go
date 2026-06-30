package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/scrypt"

	"github.com/mayfly-ssh/mayfly-cli/internal/machine"
)

// fileStore is the fallback backend used when no OS keystore is available.
//
// Secrets are encrypted at rest with AES-256-GCM. The key is derived with
// scrypt from a passphrase: MAYFLY_CREDENTIAL_PASSPHRASE when set, otherwise a
// machine-bound value. NOTE: when relying on the machine-bound key this is
// obfuscation-at-rest, not strong protection — confidentiality then rests on
// the 0600 file permissions. Operators wanting strong protection should set a
// passphrase or use an OS keystore. Each entry has its own random salt + nonce.
type fileStore struct {
	path       string
	passphrase []byte
	mu         sync.Mutex
}

type fileEntry struct {
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

const (
	scryptN     = 1 << 15
	scryptR     = 8
	scryptP     = 1
	scryptKeyLn = 32
)

// newFileStore constructs the file backend at the given path.
func newFileStore(path string) *fileStore {
	pass := os.Getenv("MAYFLY_CREDENTIAL_PASSPHRASE")
	if pass == "" {
		pass = "machine:" + machine.ID()
	}
	return &fileStore{path: path, passphrase: []byte(pass)}
}

func (f *fileStore) Name() string { return "encrypted-file" }

func (f *fileStore) Get(key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entries, err := f.load()
	if err != nil {
		return "", err
	}
	entry, ok := entries[key]
	if !ok {
		return "", ErrNotFound
	}
	return f.decrypt(entry)
}

func (f *fileStore) Set(key, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	entries, err := f.load()
	if err != nil {
		return err
	}
	entry, err := f.encrypt(secret)
	if err != nil {
		return err
	}
	entries[key] = entry
	return f.save(entries)
}

func (f *fileStore) Delete(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	entries, err := f.load()
	if err != nil {
		return err
	}
	if _, ok := entries[key]; !ok {
		return nil
	}
	delete(entries, key)
	return f.save(entries)
}

func (f *fileStore) load() (map[string]fileEntry, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]fileEntry{}, nil
		}
		return nil, err
	}
	entries := map[string]fileEntry{}
	if len(data) == 0 {
		return entries, nil
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("credential store is corrupt: %w", err)
	}
	return entries, nil
}

func (f *fileStore) save(entries map[string]fileEntry) error {
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

func (f *fileStore) deriveKey(salt []byte) ([]byte, error) {
	return scrypt.Key(f.passphrase, salt, scryptN, scryptR, scryptP, scryptKeyLn)
}

func (f *fileStore) encrypt(plaintext string) (fileEntry, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fileEntry{}, err
	}
	key, err := f.deriveKey(salt)
	if err != nil {
		return fileEntry{}, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return fileEntry{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fileEntry{}, err
	}
	ct := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return fileEntry{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

func (f *fileStore) decrypt(e fileEntry) (string, error) {
	salt, err := base64.StdEncoding.DecodeString(e.Salt)
	if err != nil {
		return "", err
	}
	nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil {
		return "", err
	}
	ct, err := base64.StdEncoding.DecodeString(e.Ciphertext)
	if err != nil {
		return "", err
	}
	key, err := f.deriveKey(salt)
	if err != nil {
		return "", err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("credential decryption failed (wrong passphrase or tampered store): %w", err)
	}
	return string(pt), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
