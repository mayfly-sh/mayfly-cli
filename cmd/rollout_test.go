package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mayfly-ssh/mayfly-cli/internal/rolloutadmin"
)

// rolloutRecorder captures the last query string per rollout path.
type rolloutRecorder struct {
	mu      sync.Mutex
	queries map[string]string
}

func (r *rolloutRecorder) record(path, query string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries[path] = query
}

func (r *rolloutRecorder) get(path string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.queries[path]
}

func newRolloutServer(t *testing.T, rec *rolloutRecorder) *httptest.Server {
	t.Helper()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(v)
	}
	status := rolloutadmin.Status{
		Configured: true, LatestGeneration: ip(4), BundleFingerprint: "sha256:abcd",
		TotalMachines: 3, ActiveMachines: 3, Completed: 1, Remaining: 2, NeverSynced: 1, Percentage: 33.3,
		Online: 2, Stale: 0, Offline: 1,
		Breakdown:   rolloutadmin.Breakdown{Healthy: 1, Pending: 1, Offline: 1},
		Generations: []rolloutadmin.GenerationDetail{{Generation: 4, Machines: 1, Percentage: 33.3, IsLatest: true}},
		ETA:         rolloutadmin.ETA{Complete: false, Remaining: 2, AppliesLastHour: 2, PerHour: 2, ETASeconds: ip(3600)},
		Health:      rolloutadmin.Health{Status: "Degraded", Score: 33, Reasons: []string{"2 behind"}},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/rollout", func(w http.ResponseWriter, r *http.Request) {
		rec.record("/api/v1/admin/rollout", r.URL.RawQuery)
		writeJSON(w, status)
	})
	mux.HandleFunc("/api/v1/admin/rollout/generations", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, rolloutadmin.GenerationsResponse{LatestGeneration: ip(4), Generations: status.Generations})
	})
	mux.HandleFunc("/api/v1/admin/rollout/machines", func(w http.ResponseWriter, r *http.Request) {
		rec.record("/api/v1/admin/rollout/machines", r.URL.RawQuery)
		writeJSON(w, rolloutadmin.MachinesResponse{Count: 1, Machines: []rolloutadmin.MachineRollout{
			{Hostname: "host-c", MachineID: "srv_c", Status: "active", Liveness: "OFFLINE", LatestGeneration: ip(4), GenerationsBehind: 4, State: "stuck", Category: "offline"},
		}})
	})
	mux.HandleFunc("/api/v1/admin/rollout/stuck", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, rolloutadmin.StuckReport{Count: 1, Stuck: []rolloutadmin.StuckMachine{
			{Hostname: "host-c", Category: "offline", GenerationsBehind: 4, Liveness: "OFFLINE", Recommendation: "power on the host"},
		}})
	})
	mux.HandleFunc("/api/v1/admin/rollout/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, status.Health)
	})
	mux.HandleFunc("/api/v1/admin/rollout/explain", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, rolloutadmin.Explanation{Complete: false, Remaining: 2, Categories: []rolloutadmin.ExplainCategory{
			{Category: "offline", Count: 1, Description: "no recent heartbeat", Recommendation: "power on the host", Machines: []string{"host-c"}},
		}})
	})
	mux.HandleFunc("/api/v1/admin/rollout/timeline", func(w http.ResponseWriter, r *http.Request) {
		rec.record("/api/v1/admin/rollout/timeline", r.URL.RawQuery)
		writeJSON(w, rolloutadmin.Timeline{Count: 1, Events: []rolloutadmin.TimelineEvent{
			{Position: 1, At: "2026-06-24T12:00:01Z", EventType: "bundle.applied", Outcome: "applied", MachineID: "srv_a", Generation: ip(4)},
		}})
	})
	mux.HandleFunc("/api/v1/admin/rollout/history", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, rolloutadmin.History{LatestGeneration: ip(4), Generations: []rolloutadmin.GenerationHistory{
			{Generation: 4, IsLatest: true, MachinesOnGeneration: 1, TotalApplies: 1, FirstAppliedAt: "2026-06-24T12:00:01Z", LastAppliedAt: "2026-06-24T12:00:01Z"},
		}})
	})
	return httptest.NewServer(mux)
}

func newRolloutEnv(t *testing.T) (*httptest.Server, *rolloutRecorder) {
	t.Helper()
	rec := &rolloutRecorder{queries: map[string]string{}}
	srv := newRolloutServer(t, rec)
	t.Cleanup(srv.Close)
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)
	return srv, rec
}

func TestRolloutStatusTable(t *testing.T) {
	_, _ = newRolloutEnv(t)
	out, err := execCLI(t, "rollout", "status")
	if err != nil {
		t.Fatalf("rollout status: %v\n%s", err, out)
	}
	for _, want := range []string{"Fleet rollout", "33.3%", "Degraded", "healthy 1", "ETA:"} {
		if !strings.Contains(out, want) {
			t.Errorf("status missing %q:\n%s", want, out)
		}
	}
}

func TestRolloutStatusJSON(t *testing.T) {
	_, _ = newRolloutEnv(t)
	out, err := execCLI(t, "rollout", "status", "-o", "json")
	if err != nil {
		t.Fatalf("rollout status json: %v\n%s", err, out)
	}
	var s rolloutadmin.Status
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if s.Completed != 1 || s.Health.Status != "Degraded" {
		t.Errorf("status=%+v", s)
	}
}

func TestRolloutSummary(t *testing.T) {
	_, _ = newRolloutEnv(t)
	out, err := execCLI(t, "rollout", "summary")
	if err != nil {
		t.Fatalf("rollout summary: %v\n%s", err, out)
	}
	if !strings.Contains(out, "health: Degraded") {
		t.Errorf("summary:\n%s", out)
	}
}

func TestRolloutGenerations(t *testing.T) {
	_, _ = newRolloutEnv(t)
	out, err := execCLI(t, "rollout", "generations")
	if err != nil {
		t.Fatalf("generations: %v\n%s", err, out)
	}
	if !strings.Contains(out, "GENERATION") || !strings.Contains(out, "33.3%") {
		t.Errorf("generations:\n%s", out)
	}
}

func TestRolloutMachinesForwardsFilters(t *testing.T) {
	_, rec := newRolloutEnv(t)
	out, err := execCLI(t, "rollout", "machines", "--state", "stuck", "--generation", "2")
	if err != nil {
		t.Fatalf("machines: %v\n%s", err, out)
	}
	q := rec.get("/api/v1/admin/rollout/machines")
	for _, want := range []string{"state=stuck", "generation=2"} {
		if !strings.Contains(q, want) {
			t.Errorf("query %q missing %q", q, want)
		}
	}
	if !strings.Contains(out, "host-c") || !strings.Contains(out, "offline") {
		t.Errorf("machines output:\n%s", out)
	}
}

func TestRolloutStuck(t *testing.T) {
	_, _ = newRolloutEnv(t)
	out, err := execCLI(t, "rollout", "stuck")
	if err != nil {
		t.Fatalf("stuck: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Stuck machines: 1") || !strings.Contains(out, "power on the host") {
		t.Errorf("stuck:\n%s", out)
	}
}

func TestRolloutHealth(t *testing.T) {
	_, _ = newRolloutEnv(t)
	out, err := execCLI(t, "rollout", "health")
	if err != nil {
		t.Fatalf("health: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Rollout health: Degraded") {
		t.Errorf("health:\n%s", out)
	}
}

func TestRolloutExplain(t *testing.T) {
	_, _ = newRolloutEnv(t)
	out, err := execCLI(t, "rollout", "explain")
	if err != nil {
		t.Fatalf("explain: %v\n%s", err, out)
	}
	for _, want := range []string{"incomplete", "offline (1)", "power on the host"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain missing %q:\n%s", want, out)
		}
	}
}

func TestRolloutTimelineForwardsLimit(t *testing.T) {
	_, rec := newRolloutEnv(t)
	out, err := execCLI(t, "rollout", "timeline", "--limit", "10")
	if err != nil {
		t.Fatalf("timeline: %v\n%s", err, out)
	}
	if !strings.Contains(rec.get("/api/v1/admin/rollout/timeline"), "limit=10") {
		t.Errorf("timeline did not forward limit: %q", rec.get("/api/v1/admin/rollout/timeline"))
	}
	if !strings.Contains(out, "applied") {
		t.Errorf("timeline output:\n%s", out)
	}
}

func TestRolloutHistory(t *testing.T) {
	_, _ = newRolloutEnv(t)
	out, err := execCLI(t, "rollout", "history")
	if err != nil {
		t.Fatalf("history: %v\n%s", err, out)
	}
	if !strings.Contains(out, "GENERATION") || !strings.Contains(out, "APPLIES") {
		t.Errorf("history:\n%s", out)
	}
}

func TestRolloutBadFormat(t *testing.T) {
	_, _ = newRolloutEnv(t)
	if _, err := execCLI(t, "rollout", "status", "-o", "toml"); err == nil {
		t.Error("expected error for unknown format")
	}
}
