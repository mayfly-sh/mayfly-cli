package cmd

import (
	"os/exec"
	"strings"
	"testing"
)

func TestSSHDryRunPassthrough(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("system ssh client not available")
	}
	srv := newIssueServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "ssh", "--dry-run", "-p", "2222", "-o", "BatchMode=yes", "user@host", "uptime")
	if err != nil {
		t.Fatalf("ssh dry-run: %v\n%s", err, out)
	}

	// OpenSSH options are passed through.
	for _, want := range []string{"-p 2222", "BatchMode=yes", "user@host", "uptime"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q:\n%s", want, out)
		}
	}
	// Mayfly injects the cert + key and pins identities.
	for _, want := range []string{"-i ", "CertificateFile=", "IdentitiesOnly=yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing injected %q:\n%s", want, out)
		}
	}
	// Mayfly control flags must not leak to OpenSSH.
	if strings.Contains(out, "--dry-run") {
		t.Errorf("mayfly --dry-run leaked into ssh args:\n%s", out)
	}
}

func TestSSHRequiresTarget(t *testing.T) {
	srv := newIssueServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	_, err := execCLI(t, "ssh", "--dry-run")
	if err == nil {
		t.Fatal("expected error when no target host is given")
	}
}

func TestSSHReusesCachedCertificate(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("system ssh client not available")
	}
	srv := newIssueServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	// First connection issues + caches.
	if out, err := execCLI(t, "ssh", "--dry-run", "host"); err != nil {
		t.Fatalf("first: %v\n%s", err, out)
	}
	// Second --dry-run reuses; the cache should hold exactly one cert.
	if out, err := execCLI(t, "ssh", "--dry-run", "host"); err != nil {
		t.Fatalf("second: %v\n%s", err, out)
	}
	out, err := execCLI(t, "cert", "cache", "--json")
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	if strings.Count(out, "\"serial\"") != 1 {
		t.Fatalf("expected exactly one cached certificate after reuse:\n%s", out)
	}
}
