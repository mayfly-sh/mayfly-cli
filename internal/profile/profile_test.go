package profile

import (
	"path/filepath"
	"testing"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s := NewStore(filepath.Join(t.TempDir(), "profiles.json"))
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDefaultProfileFallback(t *testing.T) {
	s := newStore(t)
	if s.DefaultProfile() != DefaultName {
		t.Fatalf("DefaultProfile = %q", s.DefaultProfile())
	}
}

func TestUpsertAndSetDefault(t *testing.T) {
	s := newStore(t)
	if err := s.Upsert(Profile{Name: "work", Server: "https://work", Provider: "keycloak"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDefault("work"); err != nil {
		t.Fatal(err)
	}
	if s.DefaultProfile() != "work" {
		t.Fatalf("DefaultProfile = %q", s.DefaultProfile())
	}
	if err := s.SetDefault("ghost"); err == nil {
		t.Fatal("SetDefault on missing profile should error")
	}
}

func TestResolvePrecedence(t *testing.T) {
	s := newStore(t)
	_ = s.Upsert(Profile{Name: "work", Server: "https://work", Provider: "keycloak"})

	// Profile defines both → both come from profile.
	r := s.Resolve("work", "https://fallback", "github")
	if r.Server != "https://work" || !r.ServerFromProfile {
		t.Fatalf("server = %+v", r)
	}
	if r.Provider != "keycloak" || !r.ProviderFromProfile {
		t.Fatalf("provider = %+v", r)
	}

	// Unknown profile → fallbacks, not marked from-profile.
	r = s.Resolve("missing", "https://fallback", "github")
	if r.Server != "https://fallback" || r.ServerFromProfile {
		t.Fatalf("fallback server = %+v", r)
	}

	// Partial profile (provider only) → server falls back.
	_ = s.Upsert(Profile{Name: "partial", Provider: "keycloak"})
	r = s.Resolve("partial", "https://fallback", "github")
	if r.Server != "https://fallback" || r.ServerFromProfile {
		t.Fatalf("partial server = %+v", r)
	}
	if r.Provider != "keycloak" || !r.ProviderFromProfile {
		t.Fatalf("partial provider = %+v", r)
	}
}
