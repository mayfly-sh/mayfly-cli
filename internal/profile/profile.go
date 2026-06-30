// Package profile manages named CLI profiles. A profile bundles a target
// server and default provider, so a user can keep several environments (e.g.
// "work", "staging") and switch with --profile without editing config or
// deleting credentials.
package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// DefaultName is the profile used when none is selected.
const DefaultName = "default"

// Profile is a named server+provider target.
type Profile struct {
	Name     string `json:"name"`
	Server   string `json:"server,omitempty"`
	Provider string `json:"provider,omitempty"`
}

type data struct {
	Default  string    `json:"default"`
	Profiles []Profile `json:"profiles"`
}

// Store is a persistent set of profiles.
type Store struct {
	path string
	mu   sync.Mutex
	d    data
}

// NewStore opens (lazily) the profile file at path.
func NewStore(path string) *Store { return &Store{path: path} }

// DefaultPath returns the standard profiles file path.
func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "mayfly", "profiles.json")
	}
	return filepath.Join(dir, "mayfly", "profiles.json")
}

// Load reads profiles from disk. A missing file is not an error.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.d = data{}
			return nil
		}
		return err
	}
	var d data
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &d); err != nil {
			return fmt.Errorf("profiles file is corrupt: %w", err)
		}
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

// DefaultProfile returns the configured default profile name, or DefaultName.
func (s *Store) DefaultProfile() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.Default != "" {
		return s.d.Default
	}
	return DefaultName
}

// SetDefault sets the default profile name (must exist or be DefaultName).
func (s *Store) SetDefault(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name != DefaultName {
		found := false
		for _, p := range s.d.Profiles {
			if p.Name == name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("profile %q not found", name)
		}
	}
	s.d.Default = name
	return s.save()
}

// Get returns the named profile.
func (s *Store) Get(name string) (Profile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.d.Profiles {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// Upsert inserts or replaces a profile by name.
func (s *Store) Upsert(p Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.d.Profiles {
		if s.d.Profiles[i].Name == p.Name {
			s.d.Profiles[i] = p
			return s.save()
		}
	}
	s.d.Profiles = append(s.d.Profiles, p)
	return s.save()
}

// List returns all profiles sorted by name.
func (s *Store) List() []Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Profile(nil), s.d.Profiles...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Resolved is a profile's effective server+provider after applying fallbacks.
type Resolved struct {
	Name     string
	Server   string
	Provider string
	// ServerFromProfile / ProviderFromProfile indicate the value came from the
	// profile (vs a fallback), for precedence/origin reporting.
	ServerFromProfile   bool
	ProviderFromProfile bool
}

// Resolve returns the effective server/provider for a profile, falling back to
// the supplied defaults when the profile is absent or leaves a field empty.
func (s *Store) Resolve(name, fallbackServer, fallbackProvider string) Resolved {
	r := Resolved{Name: name, Server: fallbackServer, Provider: fallbackProvider}
	if p, ok := s.Get(name); ok {
		if p.Server != "" {
			r.Server, r.ServerFromProfile = p.Server, true
		}
		if p.Provider != "" {
			r.Provider, r.ProviderFromProfile = p.Provider, true
		}
	}
	return r
}
