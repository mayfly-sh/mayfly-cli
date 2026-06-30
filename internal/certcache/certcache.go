// Package certcache implements a secure on-disk cache of short-lived SSH user
// certificates and their Ed25519 private keys, keyed by identity
// (profile + provider + subject + server).
//
// Layout (root defaults to <user-config>/mayfly/certs):
//
//	<root>/<id-hash>/
//	    id_ed25519         private key   (0600)
//	    id_ed25519.pub     public key    (0644)
//	    id_ed25519-cert.pub certificate  (0644)
//	    meta.json          metadata      (0600)
//
// Security: the root and per-identity directories are 0700, the private key is
// 0600, writes are atomic (temp + rename), and symlinked directories are
// rejected so a hostile symlink cannot redirect a 0600 key write. The private
// key must live on disk (not in the credential store) because the system `ssh`
// client consumes it via `-i` and ControlMaster/ProxyJump require a stable path
// — this mirrors how OpenSSH stores `~/.ssh/id_*`. Certificates are short-lived,
// so a private key without a current certificate is useless.
package certcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	keyFile  = "id_ed25519"
	pubFile  = "id_ed25519.pub"
	certFile = "id_ed25519-cert.pub"
	metaFile = "meta.json"
)

// Identity uniquely scopes a cached certificate.
type Identity struct {
	Profile  string
	Provider string
	Subject  string
	Server   string
}

func (id Identity) key() string {
	return id.Profile + "|" + id.Provider + "|" + id.Subject + "|" + id.Server
}

func (id Identity) dirName() string {
	sum := sha256.Sum256([]byte(id.key()))
	return hex.EncodeToString(sum[:8])
}

// Entry is the non-secret metadata describing a cached certificate.
type Entry struct {
	Profile        string    `json:"profile"`
	Provider       string    `json:"provider"`
	Subject        string    `json:"subject"`
	Server         string    `json:"server"`
	Serial         uint64    `json:"serial"`
	Principal      string    `json:"principal"`
	KeyFingerprint string    `json:"key_fingerprint"`
	CAKeyID        string    `json:"ca_key_id"`
	CAFingerprint  string    `json:"ca_fingerprint"`
	Hostname       string    `json:"hostname"`
	IssuedAt       time.Time `json:"issued_at"`
	Expiry         time.Time `json:"expiry"`

	// Filesystem paths, populated on load/save (never serialized).
	Dir      string `json:"-"`
	KeyPath  string `json:"-"`
	CertPath string `json:"-"`
}

// Expired reports whether the certificate is no longer valid at now.
func (e Entry) Expired(now time.Time) bool { return !now.Before(e.Expiry) }

// Remaining reports how long the certificate stays valid from now (<=0 if expired).
func (e Entry) Remaining(now time.Time) time.Duration { return e.Expiry.Sub(now) }

// Cache is a directory-backed certificate cache.
type Cache struct {
	root string
}

// New returns a cache rooted at dir.
func New(root string) *Cache { return &Cache{root: root} }

// Root returns the cache root directory.
func (c *Cache) Root() string { return c.root }

// Lookup returns the cached entry for an identity, or (nil, nil) when absent.
func (c *Cache) Lookup(id Identity) (*Entry, error) {
	dir := filepath.Join(c.root, id.dirName())
	return c.loadEntry(dir)
}

func (c *Cache) loadEntry(dir string) (*Entry, error) {
	raw, err := os.ReadFile(filepath.Join(dir, metaFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var e Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("cache metadata is corrupt: %w", err)
	}
	e.Dir = dir
	e.KeyPath = filepath.Join(dir, keyFile)
	e.CertPath = filepath.Join(dir, certFile)
	return &e, nil
}

// Save persists the key pair, certificate, and metadata for an identity
// atomically and returns the stored entry with filesystem paths populated.
func (c *Cache) Save(id Identity, privPEM []byte, pubAuthorizedKey, certificate string, e Entry) (*Entry, error) {
	if err := ensureSecureDir(c.root); err != nil {
		return nil, err
	}
	dir := filepath.Join(c.root, id.dirName())
	if err := ensureSecureDir(dir); err != nil {
		return nil, err
	}

	e.Profile, e.Provider, e.Subject, e.Server = id.Profile, id.Provider, id.Subject, id.Server

	if err := writeFileAtomic(filepath.Join(dir, keyFile), privPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write private key: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, pubFile), []byte(ensureNewline(pubAuthorizedKey)), 0o644); err != nil {
		return nil, fmt.Errorf("write public key: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, certFile), []byte(ensureNewline(certificate)), 0o644); err != nil {
		return nil, fmt.Errorf("write certificate: %w", err)
	}
	meta, err := json.MarshalIndent(&e, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(dir, metaFile), meta, 0o600); err != nil {
		return nil, fmt.Errorf("write metadata: %w", err)
	}

	e.Dir = dir
	e.KeyPath = filepath.Join(dir, keyFile)
	e.CertPath = filepath.Join(dir, certFile)
	return &e, nil
}

// Remove deletes the cached material for an identity. It reports whether
// anything was removed.
func (c *Cache) Remove(id Identity) (bool, error) {
	dir := filepath.Join(c.root, id.dirName())
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if err := os.RemoveAll(dir); err != nil {
		return false, err
	}
	return true, nil
}

// List returns all cached entries, sorted by identity for determinism.
func (c *Cache) List() ([]Entry, error) {
	ents, err := os.ReadDir(c.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Entry
	for _, de := range ents {
		if !de.IsDir() {
			continue
		}
		e, err := c.loadEntry(filepath.Join(c.root, de.Name()))
		if err != nil {
			return nil, err
		}
		if e != nil {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Server < out[j].Server
	})
	return out, nil
}

// Prune removes every cached certificate that has expired at now and returns the
// number of entries removed.
func (c *Cache) Prune(now time.Time) (int, error) {
	entries, err := c.List()
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if e.Expired(now) {
			if err := os.RemoveAll(e.Dir); err != nil {
				return removed, err
			}
			removed++
		}
	}
	return removed, nil
}

// ensureSecureDir creates dir (0700 if missing) and rejects symlinked dirs.
func ensureSecureDir(dir string) error {
	info, err := os.Lstat(dir)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to use symlinked cache path %q", dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("cache path %q is not a directory", dir)
		}
		return nil
	case errors.Is(err, os.ErrNotExist):
		return os.MkdirAll(dir, 0o700)
	default:
		return err
	}
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	// WriteFile honors umask; force the exact mode.
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func ensureNewline(s string) string {
	if s == "" || s[len(s)-1] == '\n' {
		return s
	}
	return s + "\n"
}
