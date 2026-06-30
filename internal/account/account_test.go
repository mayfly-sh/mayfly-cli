package account

import (
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s := NewStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	return s
}

func acct(provider, subject, username, profile string) Account {
	return Account{
		Provider: provider, Subject: subject, Username: username,
		Profile: profile, Server: "https://srv", CreatedAt: time.Now(),
	}
}

func TestUpsertGetListRemove(t *testing.T) {
	s := newStore(t)
	a := acct("github", "1", "vasugarg", "default")
	if err := s.Upsert(a); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(acct("keycloak", "k1", "vasu", "default")); err != nil {
		t.Fatal(err)
	}

	got, ok := s.Get("github:1")
	if !ok || got.Username != "vasugarg" {
		t.Fatalf("Get = %+v ok=%v", got, ok)
	}
	if len(s.List()) != 2 {
		t.Fatalf("List len = %d", len(s.List()))
	}

	// Persistence across reloads.
	s2 := NewStore(s.path)
	if err := s2.Load(); err != nil {
		t.Fatal(err)
	}
	if len(s2.List()) != 2 {
		t.Fatalf("reloaded List len = %d", len(s2.List()))
	}

	removed, err := s.Remove("github:1")
	if err != nil || !removed {
		t.Fatalf("Remove = %v %v", removed, err)
	}
	if _, ok := s.Get("github:1"); ok {
		t.Fatal("account should be gone")
	}
}

func TestActiveAndRemoveClearsActive(t *testing.T) {
	s := newStore(t)
	_ = s.Upsert(acct("github", "1", "vasugarg", "default"))
	if err := s.SetActive("default", "github:1"); err != nil {
		t.Fatal(err)
	}
	if a, ok := s.Active("default"); !ok || a.ID() != "github:1" {
		t.Fatalf("Active = %+v ok=%v", a, ok)
	}
	if err := s.SetActive("default", "missing:0"); err == nil {
		t.Fatal("SetActive on missing should error")
	}
	if _, err := s.Remove("github:1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Active("default"); ok {
		t.Fatal("active should be cleared after removing the active account")
	}
}

func TestFindAndAmbiguity(t *testing.T) {
	s := newStore(t)
	_ = s.Upsert(acct("github", "1", "vasugarg", "default"))
	_ = s.Upsert(acct("keycloak", "k1", "vasugarg", "default")) // same username, diff provider

	if _, err := s.Find("default", "vasugarg"); err == nil {
		t.Fatal("ambiguous username should error")
	}
	a, err := s.Find("default", "github/vasugarg")
	if err != nil || a.Provider != "github" {
		t.Fatalf("Find display = %+v %v", a, err)
	}
	if _, err := s.Find("default", "nope"); err == nil {
		t.Fatal("missing should error")
	}
}

func TestRenameAffectsDisplayAndFind(t *testing.T) {
	s := newStore(t)
	_ = s.Upsert(acct("github", "1", "vasugarg", "default"))
	if err := s.Rename("github:1", "work"); err != nil {
		t.Fatal(err)
	}
	a, _ := s.Get("github:1")
	if a.Display() != "github/work" {
		t.Fatalf("Display = %q", a.Display())
	}
	if _, err := s.Find("default", "work"); err != nil {
		t.Fatalf("Find by alias: %v", err)
	}
}

func TestCredentialAccountNamespacedByProfile(t *testing.T) {
	a := acct("github", "1", "v", "work")
	b := acct("github", "1", "v", "home")
	if a.CredentialAccount() == b.CredentialAccount() {
		t.Fatal("same subject in different profiles must not collide")
	}
}
