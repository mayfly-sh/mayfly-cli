package credentials

import (
	"path/filepath"
	"testing"
)

func newTestFileStore(t *testing.T) *fileStore {
	t.Helper()
	t.Setenv("MAYFLY_CREDENTIAL_PASSPHRASE", "test-passphrase")
	return newFileStore(filepath.Join(t.TempDir(), "creds.json"))
}

func TestFileStoreRoundTrip(t *testing.T) {
	s := newTestFileStore(t)

	if _, err := s.Get("absent"); err != ErrNotFound {
		t.Errorf("Get absent = %v, want ErrNotFound", err)
	}

	if err := s.Set("github:https://srv", "secret-token"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("github:https://srv")
	if err != nil {
		t.Fatal(err)
	}
	if got != "secret-token" {
		t.Errorf("Get = %q, want secret-token", got)
	}

	if err := s.Delete("github:https://srv"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("github:https://srv"); err != ErrNotFound {
		t.Errorf("after delete Get = %v, want ErrNotFound", err)
	}
	if err := s.Delete("github:https://srv"); err != nil {
		t.Errorf("delete missing should be nil, got %v", err)
	}
}

func TestFileStoreWrongPassphraseFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	t.Setenv("MAYFLY_CREDENTIAL_PASSPHRASE", "right")
	s1 := newFileStore(path)
	if err := s1.Set("k", "v"); err != nil {
		t.Fatal(err)
	}

	t.Setenv("MAYFLY_CREDENTIAL_PASSPHRASE", "wrong")
	s2 := newFileStore(path)
	if _, err := s2.Get("k"); err == nil {
		t.Error("expected decryption failure with wrong passphrase")
	}
}

func TestKeyFormat(t *testing.T) {
	if got := Key("github", "acct"); got != "github:acct" {
		t.Errorf("Key = %q", got)
	}
}

func TestOpenFileBackend(t *testing.T) {
	s, err := Open(BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != "encrypted-file" {
		t.Errorf("Name = %q", s.Name())
	}
}

func TestOpenUnknownBackend(t *testing.T) {
	if _, err := Open(Backend("bogus")); err == nil {
		t.Error("expected error for unknown backend")
	}
}
