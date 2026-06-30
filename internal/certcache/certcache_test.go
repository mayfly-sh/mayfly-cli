package certcache

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func testIdentity() Identity {
	return Identity{Profile: "default", Provider: "github", Subject: "123", Server: "https://s.example"}
}

func sampleEntry(expiry time.Time) Entry {
	return Entry{
		Serial: 1, Principal: "tester", KeyFingerprint: "SHA256:k",
		CAKeyID: "ca", CAFingerprint: "SHA256:ca", Hostname: "h",
		IssuedAt: time.Now().Add(-time.Minute), Expiry: expiry,
	}
}

func TestSaveLookupRoundTrip(t *testing.T) {
	c := New(t.TempDir())
	id := testIdentity()
	exp := time.Now().Add(time.Hour)
	saved, err := c.Save(id, []byte("PRIVKEY"), "ssh-ed25519 AAAA pub\n", "ssh-ed25519-cert-v01@openssh.com BBBB\n", sampleEntry(exp))
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if saved.KeyPath == "" || saved.CertPath == "" {
		t.Fatal("paths not populated")
	}

	got, err := c.Lookup(id)
	if err != nil || got == nil {
		t.Fatalf("lookup: %v entry=%v", err, got)
	}
	if got.Principal != "tester" || got.Serial != 1 {
		t.Errorf("entry=%+v", got)
	}
	if got.Expired(time.Now()) {
		t.Error("entry should not be expired")
	}
}

func TestPrivateKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	c := New(t.TempDir())
	id := testIdentity()
	saved, err := c.Save(id, []byte("PRIVKEY"), "pub\n", "cert\n", sampleEntry(time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(saved.KeyPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key perm = %o, want 600", perm)
	}
	dirInfo, _ := os.Stat(saved.Dir)
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir perm = %o, want 700", perm)
	}
}

func TestLookupMissingReturnsNil(t *testing.T) {
	c := New(t.TempDir())
	got, err := c.Lookup(testIdentity())
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestListAndRemove(t *testing.T) {
	c := New(t.TempDir())
	id := testIdentity()
	if _, err := c.Save(id, []byte("k"), "pub\n", "cert\n", sampleEntry(time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("save: %v", err)
	}
	list, err := c.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}
	removed, err := c.Remove(id)
	if err != nil || !removed {
		t.Fatalf("remove: %v removed=%v", err, removed)
	}
	if list2, _ := c.List(); len(list2) != 0 {
		t.Fatalf("expected empty after remove, got %d", len(list2))
	}
}

func TestPruneRemovesExpired(t *testing.T) {
	c := New(t.TempDir())
	fresh := Identity{Profile: "default", Provider: "github", Subject: "fresh", Server: "s"}
	stale := Identity{Profile: "default", Provider: "github", Subject: "stale", Server: "s"}
	_, _ = c.Save(fresh, []byte("k"), "pub\n", "cert\n", sampleEntry(time.Now().Add(time.Hour)))
	_, _ = c.Save(stale, []byte("k"), "pub\n", "cert\n", sampleEntry(time.Now().Add(-time.Hour)))

	n, err := c.Prune(time.Now())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	if got, _ := c.Lookup(stale); got != nil {
		t.Error("stale entry survived prune")
	}
	if got, _ := c.Lookup(fresh); got == nil {
		t.Error("fresh entry wrongly pruned")
	}
}

func TestSymlinkedRootRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics")
	}
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	c := New(link)
	_, err := c.Save(testIdentity(), []byte("k"), "pub\n", "cert\n", sampleEntry(time.Now().Add(time.Hour)))
	if err == nil {
		t.Fatal("expected symlinked cache root to be rejected")
	}
}
