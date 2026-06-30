package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mayfly-ssh/mayfly-cli/internal/caadmin"
)

// newCAServer returns a mock mayfly-server CA admin API backed by an in-memory
// set, mirroring the real wire shapes.
func newCAServer(t *testing.T) *httptest.Server {
	t.Helper()
	cas := map[string]*caadmin.CA{
		"id-a": {ID: "id-a", KeyID: "mayfly-ca", PublicKey: "ssh-ed25519 AAAA", Fingerprint: "SHA256:aaaa", Enabled: true, Status: "active", InCurrentBundle: true, IssuedCertificates: 9, BundleGeneration: 3, CreatedAt: "2026-06-24T11:00:00Z"},
		"id-b": {ID: "id-b", KeyID: "ca-old", PublicKey: "ssh-ed25519 BBBB", Fingerprint: "SHA256:bbbb", Enabled: false, Status: "disabled", InCurrentBundle: false, IssuedCertificates: 2, BundleGeneration: 3, CreatedAt: "2026-06-20T11:00:00Z"},
	}
	order := []string{"id-a", "id-b"}
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/admin/ca/generate", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		c := &caadmin.CA{ID: "id-new", KeyID: body["key_id"], Enabled: true, Status: "active", InCurrentBundle: true, BundleGeneration: 4, PublicKey: "ssh-ed25519 NEW", Fingerprint: "SHA256:new"}
		cas[c.ID] = c
		order = append(order, c.ID)
		writeJSON(w, http.StatusCreated, c)
	})
	mux.HandleFunc("/api/v1/admin/ca/rotate", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusCreated, caadmin.RotationResult{
			NewCA:          caadmin.CA{KeyID: "ca-rotated", Fingerprint: "SHA256:rot", Status: "active"},
			PreviousActive: []caadmin.CA{{KeyID: "mayfly-ca"}},
			Rollout:        caadmin.Rollout{LatestGeneration: 4, TotalMachines: 2, RolloutPercentage: 0.0, Generations: []caadmin.GenerationCount{{Generation: 3, Count: 2}}},
			Warnings:       []string{"Do NOT retire the old CA yet."},
		})
	})
	mux.HandleFunc("/api/v1/admin/ca/stats", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, caadmin.Stats{TotalCAs: 2, EnabledCAs: 1, DisabledCAs: 1, TotalIssuedCertificates: 11, Generation: 3, BundleFingerprint: "sha256:abc", PerCA: []caadmin.Usage{{KeyID: "mayfly-ca", Enabled: true, IssuedCertificates: 9}}})
	})
	mux.HandleFunc("/api/v1/admin/ca/bundle", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, caadmin.PublicBundle{Generation: 3, Fingerprint: "sha256:abc", Keys: []caadmin.BundleKey{{KeyID: "mayfly-ca", PublicKey: "ssh-ed25519 AAAA", Fingerprint: "SHA256:aaaa"}}})
	})
	mux.HandleFunc("/api/v1/admin/bundle/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, caadmin.Rollout{LatestGeneration: 3, TotalMachines: 2, Online: 2, RolloutPercentage: 100.0, Generations: []caadmin.GenerationCount{{Generation: 3, Count: 2}}})
	})
	mux.HandleFunc("/api/v1/admin/ca", func(w http.ResponseWriter, _ *http.Request) {
		var out []caadmin.CA
		for _, id := range order {
			if c, ok := cas[id]; ok {
				out = append(out, *c)
			}
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("/api/v1/admin/ca/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/ca/")
		parts := strings.Split(rest, "/")
		id := parts[0]
		c, ok := cas[id]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "not_found", "message": "no ca"}})
			return
		}
		if len(parts) == 1 {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, http.StatusOK, c)
			case http.MethodDelete:
				if c.Enabled {
					writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]string{"code": "conflict", "message": "active"}})
					return
				}
				delete(cas, id)
				writeJSON(w, http.StatusOK, caadmin.DeleteResult{Deleted: true, ID: id, KeyID: c.KeyID})
			}
			return
		}
		switch parts[1] {
		case "enable":
			c.Enabled, c.Status, c.InCurrentBundle = true, "active", true
			writeJSON(w, http.StatusOK, c)
		case "disable":
			c.Enabled, c.Status, c.InCurrentBundle = false, "disabled", false
			writeJSON(w, http.StatusOK, c)
		case "retire":
			c.Enabled, c.Status = false, "disabled"
			writeJSON(w, http.StatusOK, c)
		case "public-key":
			writeJSON(w, http.StatusOK, caadmin.PublicKey{KeyID: c.KeyID, PublicKey: c.PublicKey, Fingerprint: c.Fingerprint})
		}
	})
	return httptest.NewServer(mux)
}

func TestCAListTable(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "ca", "list")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "mayfly-ca") || !strings.Contains(out, "ca-old") || !strings.Contains(out, "KEY ID") {
		t.Errorf("unexpected list output:\n%s", out)
	}
}

func TestCAListJSON(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "ca", "list", "-o", "json")
	if err != nil {
		t.Fatalf("list json: %v\n%s", err, out)
	}
	var cas []caadmin.CA
	if err := json.Unmarshal([]byte(out), &cas); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(cas) != 2 || cas[0].KeyID != "mayfly-ca" {
		t.Errorf("cas=%+v", cas)
	}
}

func TestCAShowYAML(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "ca", "show", "id-a", "-o", "yaml")
	if err != nil {
		t.Fatalf("show yaml: %v\n%s", err, out)
	}
	if !strings.Contains(out, "key_id: mayfly-ca") {
		t.Errorf("unexpected yaml:\n%s", out)
	}
}

func TestCACreate(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "ca", "create", "ca-q3", "--passphrase", "pw", "-o", "json")
	if err != nil {
		t.Fatalf("create: %v\n%s", err, out)
	}
	var c caadmin.CA
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if c.KeyID != "ca-q3" || !c.Enabled {
		t.Errorf("ca=%+v", c)
	}
}

func TestCACreateRequiresPassphrase(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)
	t.Setenv(caPassphraseEnv, "")

	if _, err := execCLI(t, "ca", "create", "ca-q3"); err == nil {
		t.Error("expected error when no passphrase is provided")
	}
}

func TestCARotateGuided(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "ca", "rotate", "--passphrase", "pw")
	if err != nil {
		t.Fatalf("rotate: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ca-rotated") || !strings.Contains(out, "previous active") || !strings.Contains(out, "Do NOT retire") {
		t.Errorf("guided rotation output:\n%s", out)
	}
}

func TestCADisableLifecycle(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "ca", "disable", "id-a", "-o", "json")
	if err != nil {
		t.Fatalf("disable: %v\n%s", err, out)
	}
	var c caadmin.CA
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if c.Status != "disabled" {
		t.Errorf("status=%q", c.Status)
	}
}

func TestCADeleteRefusesActive(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	// id-a is active → server returns 409.
	if _, err := execCLI(t, "ca", "delete", "id-a", "--yes"); err == nil {
		t.Error("expected conflict deleting an active CA")
	}
	// id-b is disabled → deletes.
	out, err := execCLI(t, "ca", "delete", "id-b", "--yes")
	if err != nil {
		t.Fatalf("delete: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Deleted CA ca-old") {
		t.Errorf("unexpected delete output:\n%s", out)
	}
}

func TestCADeleteRequiresConfirm(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	if _, err := execCLI(t, "ca", "delete", "id-b"); err == nil {
		t.Error("expected refusal without --yes")
	}
}

func TestCAStats(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "ca", "stats", "-o", "json")
	if err != nil {
		t.Fatalf("stats: %v\n%s", err, out)
	}
	var s caadmin.Stats
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if s.TotalCAs != 2 || s.TotalIssuedCertificates != 11 {
		t.Errorf("stats=%+v", s)
	}
}

func TestCARolloutFromBundleStatus(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "ca", "rollout", "-o", "json")
	if err != nil {
		t.Fatalf("rollout: %v\n%s", err, out)
	}
	var r caadmin.Rollout
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if r.TotalMachines != 2 || r.RolloutPercentage != 100.0 {
		t.Errorf("rollout=%+v", r)
	}
}

func TestCACurrentBundle(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "ca", "current")
	if err != nil {
		t.Fatalf("current: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Active CA bundle") || !strings.Contains(out, "mayfly-ca") {
		t.Errorf("unexpected current output:\n%s", out)
	}
}

func TestCAPublicKeyAndFingerprint(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "ca", "public-key", "id-a")
	if err != nil {
		t.Fatalf("public-key: %v\n%s", err, out)
	}
	if strings.TrimSpace(out) != "ssh-ed25519 AAAA" {
		t.Errorf("public-key output=%q", out)
	}

	out, err = execCLI(t, "ca", "fingerprint", "id-a")
	if err != nil {
		t.Fatalf("fingerprint: %v\n%s", err, out)
	}
	if !strings.Contains(out, "SHA256:aaaa") || !strings.Contains(out, "mayfly-ca") {
		t.Errorf("fingerprint output=%q", out)
	}

	out, err = execCLI(t, "ca", "fingerprint")
	if err != nil {
		t.Fatalf("bundle fingerprint: %v\n%s", err, out)
	}
	if !strings.Contains(out, "sha256:abc") || !strings.Contains(out, "bundle") {
		t.Errorf("bundle fingerprint output=%q", out)
	}
}

func TestCAExportAll(t *testing.T) {
	srv := newCAServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "ca", "export", "--all")
	if err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	if strings.TrimSpace(out) != "ssh-ed25519 AAAA" {
		t.Errorf("export --all output=%q", out)
	}
}
