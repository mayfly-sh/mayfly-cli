package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/mayfly-ssh/mayfly-cli/internal/account"
	"github.com/mayfly-ssh/mayfly-cli/internal/credentials"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth"
	"github.com/mayfly-ssh/mayfly-cli/internal/ssh"
)

// newIssueServer returns a mock mayfly-server that signs issuance requests with
// a throwaway CA, mirroring the real /api/v1/certificates/issue wire shape.
func newIssueServer(t *testing.T) *httptest.Server {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := cryptossh.NewSignerFromSigner(caPriv)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/certificates/issue", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PublicKey  string `json:"public_key"`
			Hostname   string `json:"hostname"`
			TTLSeconds int    `json:"ttl_seconds"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		userPub, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(req.PublicKey))
		if err != nil {
			http.Error(w, `{"error":{"code":"bad_request","message":"bad key"}}`, http.StatusBadRequest)
			return
		}
		ttl := req.TTLSeconds
		if ttl == 0 {
			ttl = 300
		}
		now := time.Now()
		cert := &cryptossh.Certificate{
			Key:             userPub,
			Serial:          uint64(now.Unix()),
			CertType:        cryptossh.UserCert,
			KeyId:           "tester@" + req.Hostname,
			ValidPrincipals: []string{"tester"},
			ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
			ValidBefore:     uint64(now.Add(time.Duration(ttl) * time.Second).Unix()),
			Permissions: cryptossh.Permissions{
				Extensions: map[string]string{"permit-pty": "", "permit-port-forwarding": ""},
			},
		}
		if err := cert.SignCert(rand.Reader, caSigner); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificate":    string(cryptossh.MarshalAuthorizedKey(cert)),
			"serial":         cert.Serial,
			"valid_after":    time.Unix(int64(cert.ValidAfter), 0).UTC().Format(time.RFC3339),
			"valid_before":   time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339),
			"ttl_seconds":    ttl,
			"principal":      "tester",
			"fingerprint":    cryptossh.FingerprintSHA256(userPub),
			"ca_key_id":      "mayfly-ca",
			"ca_fingerprint": cryptossh.FingerprintSHA256(caSigner.PublicKey()),
		})
	})
	return httptest.NewServer(mux)
}

// certEnv isolates config/credential/cache state and points at serverURL.
func certEnv(t *testing.T, serverURL string) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("XDG_DATA_HOME", tmp)
	t.Setenv("MAYFLY_CREDENTIAL_BACKEND", "file")
	t.Setenv("MAYFLY_CREDENTIAL_PASSPHRASE", "test-passphrase")
	t.Setenv("MAYFLY_SERVER_URL", serverURL)
	t.Setenv("MAYFLY_CERT_CACHE_PATH", filepath.Join(tmp, "certs"))
}

// seedActive records a logged-in GitHub account + token for the default profile.
func seedActive(t *testing.T, serverURL string) {
	t.Helper()
	accts := account.NewStore(account.DefaultPath())
	if err := accts.Load(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a := account.Account{Provider: "github", Subject: "123", Username: "tester", Server: serverURL, Profile: "default", CreatedAt: now, LastUsedAt: now}
	if err := accts.Upsert(a); err != nil {
		t.Fatal(err)
	}
	if err := accts.SetActive("default", a.ID()); err != nil {
		t.Fatal(err)
	}
	store, err := credentials.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	if err := oauth.NewTokenStore(store).Save("github", a.CredentialAccount(), &oauth.Token{AccessToken: "gho_test", TokenType: "bearer"}); err != nil {
		t.Fatal(err)
	}
}

// execCLI runs the root command with buffered output.
func execCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	exitCode = 0
	root := NewRootCommand()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestCertIssueJSONGolden(t *testing.T) {
	srv := newIssueServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "cert", "issue", "web-01", "--json")
	if err != nil {
		t.Fatalf("issue: %v\n%s", err, out)
	}
	var sum certSummary
	if err := json.Unmarshal([]byte(out), &sum); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if sum.Action != "issue" {
		t.Errorf("action=%q", sum.Action)
	}
	if sum.Principal != "tester" {
		t.Errorf("principal=%q", sum.Principal)
	}
	if sum.Serial == 0 || sum.KeyFingerprint == "" {
		t.Errorf("summary=%+v", sum)
	}
	if sum.Hostname != "web-01" {
		t.Errorf("hostname=%q", sum.Hostname)
	}
}

func TestCertInspectJSONGolden(t *testing.T) {
	srv := newIssueServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	if out, err := execCLI(t, "cert", "issue", "--json"); err != nil {
		t.Fatalf("issue: %v\n%s", err, out)
	}
	out, err := execCLI(t, "cert", "inspect", "--json")
	if err != nil {
		t.Fatalf("inspect: %v\n%s", err, out)
	}
	var info ssh.CertInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if info.Type != "user" {
		t.Errorf("type=%q", info.Type)
	}
	if len(info.Principals) != 1 || info.Principals[0] != "tester" {
		t.Errorf("principals=%v", info.Principals)
	}
	if len(info.Extensions) == 0 {
		t.Errorf("expected extensions, got none")
	}
}

func TestCertCacheJSONGolden(t *testing.T) {
	srv := newIssueServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	if _, err := execCLI(t, "cert", "issue", "--json"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	out, err := execCLI(t, "cert", "cache", "--json")
	if err != nil {
		t.Fatalf("cache: %v\n%s", err, out)
	}
	var payload struct {
		Root         string        `json:"root"`
		Certificates []certSummary `json:"certificates"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(payload.Certificates) != 1 {
		t.Fatalf("want 1 cached cert, got %d", len(payload.Certificates))
	}
	if payload.Certificates[0].Principal != "tester" {
		t.Errorf("principal=%q", payload.Certificates[0].Principal)
	}
}

func TestCertRemoveClearsCache(t *testing.T) {
	srv := newIssueServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	if _, err := execCLI(t, "cert", "issue", "--json"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if out, err := execCLI(t, "cert", "remove"); err != nil {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	out, err := execCLI(t, "cert", "cache", "--json")
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	var payload struct {
		Certificates []certSummary `json:"certificates"`
	}
	_ = json.Unmarshal([]byte(out), &payload)
	if len(payload.Certificates) != 0 {
		t.Fatalf("expected empty cache after remove, got %d", len(payload.Certificates))
	}
}
