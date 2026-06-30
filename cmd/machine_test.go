package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mayfly-ssh/mayfly-cli/internal/machineadmin"
)

// newMachineServer returns a mock mayfly-server admin-machines API backed by an
// in-memory fleet, mirroring the real wire shapes.
func newMachineServer(t *testing.T) *httptest.Server {
	t.Helper()
	fleet := map[string]*machineadmin.Machine{
		"srv_a": {MachineID: "srv_a", Hostname: "web-01", Status: "active", Liveness: "ONLINE", OS: "linux", Arch: "x86_64", AgentVersion: "0.1.0", Fingerprint: "SHA256:aaaa", CurrentGeneration: 5, SyncedGeneration: i64p(5), LatestGeneration: i64p(5), UpToDate: true, LastSeen: "2026-06-24T12:00:00Z", EnrolledAt: "2026-06-24T11:00:00Z"},
		"srv_b": {MachineID: "srv_b", Hostname: "db-01", Status: "disabled", Liveness: "OFFLINE", OS: "linux", Arch: "arm64", AgentVersion: "0.1.0", Fingerprint: "SHA256:bbbb", CurrentGeneration: 4, SyncedGeneration: i64p(4), LatestGeneration: i64p(5), UpToDate: false, EnrolledAt: "2026-06-24T11:30:00Z"},
	}
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/machines", func(w http.ResponseWriter, r *http.Request) {
		status := r.URL.Query().Get("status")
		var out []machineadmin.Machine
		for _, id := range []string{"srv_a", "srv_b"} { // deterministic order
			m := fleet[id]
			if status != "" && m.Status != status {
				continue
			}
			out = append(out, *m)
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("/api/v1/admin/machines/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/machines/")
		parts := strings.Split(rest, "/")
		id := parts[0]
		m, ok := fleet[id]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "not_found", "message": "no machine"}})
			return
		}
		if len(parts) == 1 {
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, http.StatusOK, m)
			case http.MethodDelete:
				delete(fleet, id)
				writeJSON(w, http.StatusOK, machineadmin.DeleteResult{Deleted: true, MachineID: id, Hostname: m.Hostname})
			}
			return
		}
		switch parts[1] {
		case "disable":
			m.Status = "disabled"
			writeJSON(w, http.StatusOK, m)
		case "enable", "approve":
			m.Status = "active"
			writeJSON(w, http.StatusOK, m)
		case "revoke":
			m.Status = "revoked"
			writeJSON(w, http.StatusOK, m)
		case "reenroll", "rotate-identity":
			delete(fleet, id)
			writeJSON(w, http.StatusCreated, machineadmin.EnrollmentToken{Token: "mf_enroll_new", ID: "tok-1", ExpiresAt: "2026-06-24T13:00:00Z", SingleUse: true})
		}
	})
	mux.HandleFunc("/api/v1/admin/bundle/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, machineadmin.Fleet{LatestGeneration: 5, TotalMachines: 2, Online: 1, Offline: 1, RolloutPercentage: 50.0, Generations: []machineadmin.GenerationCount{{Generation: 5, Count: 1}}})
	})
	return httptest.NewServer(mux)
}

func i64p(v int64) *int64 { return &v }

func TestMachineListTable(t *testing.T) {
	srv := newMachineServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "machine", "list")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "web-01") || !strings.Contains(out, "db-01") || !strings.Contains(out, "HOSTNAME") {
		t.Errorf("unexpected list output:\n%s", out)
	}
}

func TestMachineListJSON(t *testing.T) {
	srv := newMachineServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "machine", "list", "-o", "json")
	if err != nil {
		t.Fatalf("list json: %v\n%s", err, out)
	}
	var machines []machineadmin.Machine
	if err := json.Unmarshal([]byte(out), &machines); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(machines) != 2 || machines[0].Hostname != "web-01" {
		t.Errorf("machines=%+v", machines)
	}
}

func TestMachineListFilterByStatus(t *testing.T) {
	srv := newMachineServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "machine", "list", "--status", "active", "-o", "json")
	if err != nil {
		t.Fatalf("list filter: %v\n%s", err, out)
	}
	var machines []machineadmin.Machine
	if err := json.Unmarshal([]byte(out), &machines); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(machines) != 1 || machines[0].Hostname != "web-01" {
		t.Errorf("expected only active web-01, got %+v", machines)
	}
}

func TestMachineListContradictoryLivenessFlags(t *testing.T) {
	srv := newMachineServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	if _, err := execCLI(t, "machine", "list", "--online", "--offline"); err == nil {
		t.Error("expected error for contradictory liveness flags")
	}
}

func TestMachineShowYAML(t *testing.T) {
	srv := newMachineServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "machine", "show", "srv_a", "-o", "yaml")
	if err != nil {
		t.Fatalf("show yaml: %v\n%s", err, out)
	}
	if !strings.Contains(out, "machine_id: srv_a") || !strings.Contains(out, "hostname: web-01") {
		t.Errorf("unexpected yaml:\n%s", out)
	}
}

func TestMachineDisableLifecycle(t *testing.T) {
	srv := newMachineServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "machine", "disable", "srv_a", "-o", "json")
	if err != nil {
		t.Fatalf("disable: %v\n%s", err, out)
	}
	var m machineadmin.Machine
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if m.Status != "disabled" {
		t.Errorf("status=%q", m.Status)
	}
}

func TestMachineDeleteRequiresConfirm(t *testing.T) {
	srv := newMachineServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	// Without --yes the table path refuses.
	if _, err := execCLI(t, "machine", "delete", "srv_a"); err == nil {
		t.Error("expected refusal without --yes")
	}
	// With --yes it proceeds.
	out, err := execCLI(t, "machine", "delete", "srv_a", "--yes")
	if err != nil {
		t.Fatalf("delete: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Deleted machine web-01") {
		t.Errorf("unexpected delete output:\n%s", out)
	}
}

func TestMachineReenrollReturnsToken(t *testing.T) {
	srv := newMachineServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "machine", "reenroll", "srv_a", "--yes", "-o", "json")
	if err != nil {
		t.Fatalf("reenroll: %v\n%s", err, out)
	}
	var tok machineadmin.EnrollmentToken
	if err := json.Unmarshal([]byte(out), &tok); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if tok.Token != "mf_enroll_new" {
		t.Errorf("token=%q", tok.Token)
	}
}

func TestMachineStatusFleet(t *testing.T) {
	srv := newMachineServer(t)
	defer srv.Close()
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)

	out, err := execCLI(t, "machine", "status", "-o", "json")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	var fleet machineadmin.Fleet
	if err := json.Unmarshal([]byte(out), &fleet); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if fleet.TotalMachines != 2 || fleet.RolloutPercentage != 50.0 {
		t.Errorf("fleet=%+v", fleet)
	}
}
