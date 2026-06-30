package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mayfly-ssh/mayfly-cli/internal/opsadmin"
)

func newDoctorServer(t *testing.T, caConfigured bool, totalMachines, offline int64) *httptest.Server {
	t.Helper()
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": "0.1.0", "uptime_seconds": 10})
	})
	mux.HandleFunc("/api/v1/admin/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, opsadmin.Status{
			Version: "0.1.0", Database: "ok",
			CertificateAuthority: opsadmin.CAStatus{Configured: caConfigured, Total: 2, Enabled: 1, Generation: ip(3)},
			Bundle:               opsadmin.BundleHealth{Configured: true, Generation: ip(3)},
			Audit:                opsadmin.AuditHealth{Entries: 10, Verified: true},
			Providers:            []string{"github"},
		})
	})
	mux.HandleFunc("/api/v1/admin/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, opsadmin.Health{
			Status:   "ok",
			Machines: opsadmin.MachineHealth{Total: totalMachines, Online: totalMachines - offline, Offline: offline},
			Bundle:   opsadmin.BundleHealth{Configured: true, Generation: ip(3)},
			Audit:    opsadmin.AuditHealth{Entries: 10, Verified: true},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDoctorHealthyish(t *testing.T) {
	srv := newDoctorServer(t, true, 3, 1)
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "doctor")
	// Overall is WARN (plaintext endpoint + an offline agent), which is not a
	// hard failure, so the command should succeed.
	if err != nil {
		t.Fatalf("doctor: %v\n%s", err, out)
	}
	for _, want := range []string{
		"server connectivity", "[PASS]",
		"oauth session",
		"provider availability",
		"machine enrollment",
		"ca consistency",
		"agent status",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor output missing %q:\n%s", want, out)
		}
	}
}

func TestDoctorJSON(t *testing.T) {
	srv := newDoctorServer(t, true, 1, 0)
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "doctor", "-o", "json")
	if err != nil {
		t.Fatalf("doctor json: %v\n%s", err, out)
	}
	var report opsadmin.DoctorReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(report.Checks) == 0 {
		t.Fatal("expected checks")
	}
	// Find the connectivity check and assert it passed.
	var found bool
	for _, c := range report.Checks {
		if c.Name == "server connectivity" {
			found = true
			if c.Status != opsadmin.CheckPass {
				t.Errorf("connectivity=%q", c.Status)
			}
		}
	}
	if !found {
		t.Error("connectivity check missing")
	}
}

func TestDoctorFailsWhenCAMissing(t *testing.T) {
	srv := newDoctorServer(t, false, 1, 0)
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "doctor")
	// No CA configured is a FAIL → the command exits with an error.
	if err == nil {
		t.Fatalf("expected doctor to fail when CA missing:\n%s", out)
	}
	if !strings.Contains(out, "[FAIL]") || !strings.Contains(out, "ca consistency") {
		t.Errorf("expected ca consistency FAIL:\n%s", out)
	}
}

func TestDoctorDiagnoseAlias(t *testing.T) {
	srv := newDoctorServer(t, true, 1, 0)
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "diagnose")
	if err != nil {
		t.Fatalf("diagnose: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Mayfly doctor") {
		t.Errorf("diagnose alias output:\n%s", out)
	}
}
