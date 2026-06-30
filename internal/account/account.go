// Package account manages the CLI's known identities and which one is active.
//
// Account *metadata* (provider, username, email, server, timestamps) lives in a
// plaintext index file; the *secret* token never does — tokens are stored only
// through the credential store. The index supports multiple simultaneous
// accounts across providers and profiles, an active selection per profile, and
// rename/remove.
package account

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Account is a known identity. It holds no secrets.
type Account struct {
	Provider   string    `json:"provider"`
	Subject    string    `json:"subject"`
	Username   string    `json:"username"`
	Email      string    `json:"email,omitempty"`
	Name       string    `json:"name,omitempty"`
	Alias      string    `json:"alias,omitempty"`
	Server     string    `json:"server"`
	Profile    string    `json:"profile"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// ID is the stable, unique identifier (provider + subject).
func (a Account) ID() string { return a.Provider + ":" + a.Subject }

// Display is the human label (provider/username, or alias when set).
func (a Account) Display() string {
	name := a.Username
	if a.Alias != "" {
		name = a.Alias
	}
	return a.Provider + "/" + name
}

// CredentialAccount is the per-account key component used with the credential
// store, namespaced by profile so the same identity in two profiles/servers does
// not collide.
func (a Account) CredentialAccount() string { return a.Profile + "|" + a.Subject }

type data struct {
	// Active maps a profile name to the active account ID for that profile.
	Active   map[string]string `json:"active"`
	Accounts []Account         `json:"accounts"`
}

// Store is a persistent account index.
type Store struct {
	path string
	mu   sync.Mutex
	d    data
}

// NewStore opens (lazily) the account index at path.
func NewStore(path string) *Store {
	return &Store{path: path, d: data{Active: map[string]string{}}}
}

// DefaultPath returns the standard account index path.
func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "mayfly", "accounts.json")
	}
	return filepath.Join(dir, "mayfly", "accounts.json")
}

// Load reads the index from disk. A missing file is not an error.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.d = data{Active: map[string]string{}}
			return nil
		}
		return err
	}
	var d data
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &d); err != nil {
			return fmt.Errorf("account index is corrupt: %w", err)
		}
	}
	if d.Active == nil {
		d.Active = map[string]string{}
	}
	s.d = d
	return nil
}

func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Upsert inserts or replaces an account (matched by ID) and persists.
func (s *Store) Upsert(a Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.d.Accounts {
		if s.d.Accounts[i].ID() == a.ID() {
			// Preserve an existing alias/created-at unless explicitly provided.
			if a.Alias == "" {
				a.Alias = s.d.Accounts[i].Alias
			}
			if a.CreatedAt.IsZero() {
				a.CreatedAt = s.d.Accounts[i].CreatedAt
			}
			s.d.Accounts[i] = a
			return s.save()
		}
	}
	s.d.Accounts = append(s.d.Accounts, a)
	return s.save()
}

// Get returns the account with the given ID.
func (s *Store) Get(id string) (Account, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.d.Accounts {
		if a.ID() == id {
			return a, true
		}
	}
	return Account{}, false
}

// List returns all accounts sorted by display name.
func (s *Store) List() []Account { return s.filtered("") }

// ListByProfile returns accounts belonging to a profile, sorted.
func (s *Store) ListByProfile(profile string) []Account { return s.filtered(profile) }

func (s *Store) filtered(profile string) []Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Account
	for _, a := range s.d.Accounts {
		if profile == "" || a.Profile == profile {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Display() < out[j].Display() })
	return out
}

// Remove deletes an account by ID and clears it from any active selection.
func (s *Store) Remove(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, a := range s.d.Accounts {
		if a.ID() == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false, nil
	}
	s.d.Accounts = append(s.d.Accounts[:idx], s.d.Accounts[idx+1:]...)
	for profile, active := range s.d.Active {
		if active == id {
			delete(s.d.Active, profile)
		}
	}
	return true, s.save()
}

// SetActive marks id as the active account for a profile.
func (s *Store) SetActive(profile, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, a := range s.d.Accounts {
		if a.ID() == id {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("account %q not found", id)
	}
	s.d.Active[profile] = id
	return s.save()
}

// Active returns the active account for a profile, if any.
func (s *Store) Active(profile string) (Account, bool) {
	s.mu.Lock()
	id := s.d.Active[profile]
	s.mu.Unlock()
	if id == "" {
		return Account{}, false
	}
	return s.Get(id)
}

// Rename sets a display alias for an account.
func (s *Store) Rename(id, alias string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.d.Accounts {
		if s.d.Accounts[i].ID() == id {
			s.d.Accounts[i].Alias = alias
			return s.save()
		}
	}
	return fmt.Errorf("account %q not found", id)
}

// Touch updates an account's LastUsedAt.
func (s *Store) Touch(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.d.Accounts {
		if s.d.Accounts[i].ID() == id {
			s.d.Accounts[i].LastUsedAt = time.Now()
			return s.save()
		}
	}
	return nil
}

// Find resolves a user-supplied selector to a single account, optionally scoped
// to a profile. It matches (case-insensitive) ID, Display (provider/username),
// alias, or bare username. Ambiguous or missing matches return an error.
func (s *Store) Find(profile, query string) (Account, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return Account{}, fmt.Errorf("an account selector is required")
	}
	var matches []Account
	for _, a := range s.filtered(profile) {
		if strings.ToLower(a.ID()) == q ||
			strings.ToLower(a.Display()) == q ||
			strings.ToLower(a.Username) == q ||
			(a.Alias != "" && strings.ToLower(a.Alias) == q) {
			matches = append(matches, a)
		}
	}
	switch len(matches) {
	case 0:
		return Account{}, fmt.Errorf("no account matches %q", query)
	case 1:
		return matches[0], nil
	default:
		return Account{}, fmt.Errorf("%q is ambiguous; use the full provider/username form", query)
	}
}
