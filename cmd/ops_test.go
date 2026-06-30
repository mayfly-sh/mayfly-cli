package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mayfly-ssh/mayfly-cli/internal/opsadmin"
)

// opsRecorder captures the last query string seen per path so tests can assert
// the CLI sent the right filters.
type opsRecorder struct {
	mu      sync.Mutex
	queries map[string]string
}

func (r *opsRecorder) record(path, query string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries[path] = query
}

func (r *opsRecorder) get(path string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.queries[path]
}

func strp(s string) *string { return &s }
func ip(i int64) *int64     { return &i }

func newOpsServer(t *testing.T, rec *opsRecorder) *httptest.Server {
	t.Helper()
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	allEntries := []opsadmin.AuditEntry{
		{Position: 3, EventType: "machine.approved", Actor: "octocat", Subject: strp("m-1"), Result: "success", RecordedAt: "2026-06-24T12:00:03.000Z", Metadata: map[string]any{"provider": "github"}},
		{Position: 2, EventType: "certificate.denied", Actor: "mallory", Subject: strp("web-01"), Result: "failure", RecordedAt: "2026-06-24T12:00:02.000Z", Metadata: map[string]any{"provider": "github"}},
		{Position: 1, EventType: "certificate.issued", Actor: "octocat", Subject: strp("web-01"), Result: "success", RecordedAt: "2026-06-24T12:00:01.000Z", Metadata: map[string]any{"provider": "github", "serial": "0001"}},
	}
	filterEntries := func(q map[string][]string) []opsadmin.AuditEntry {
		out := []opsadmin.AuditEntry{}
		for _, e := range allEntries {
			if et := q["event_type"]; len(et) == 1 {
				if strings.HasSuffix(et[0], ".") {
					if !strings.HasPrefix(e.EventType, et[0]) {
						continue
					}
				} else if e.EventType != et[0] {
					continue
				}
			}
			if res := q["result"]; len(res) == 1 && e.Result != res[0] {
				continue
			}
			out = append(out, e)
		}
		return out
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/audit", func(w http.ResponseWriter, r *http.Request) {
		rec.record("/api/v1/admin/audit", r.URL.RawQuery)
		entries := filterEntries(r.URL.Query())
		var last *int64
		if len(entries) > 0 {
			last = ip(entries[0].Position)
		}
		writeJSON(w, http.StatusOK, opsadmin.AuditPage{Entries: entries, Count: len(entries), HasMore: false, LastPosition: last, Order: "desc"})
	})
	mux.HandleFunc("/api/v1/admin/audit/stream", func(w http.ResponseWriter, r *http.Request) {
		rec.record("/api/v1/admin/audit/stream", r.URL.RawQuery)
		writeJSON(w, http.StatusOK, opsadmin.AuditPage{Entries: nil, Count: 0, Order: "asc"})
	})
	mux.HandleFunc("/api/v1/admin/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, opsadmin.Health{
			Status: "degraded", Version: "0.1.0", UptimeSeconds: 120,
			Machines:       opsadmin.MachineHealth{Total: 3, Online: 2, Offline: 1, LatestGeneration: ip(4), RolloutPercentage: 66.7, Behind: 1},
			Certificates:   opsadmin.CertActivity{Issued: 5, Denied: 1},
			Authentication: opsadmin.AuthActivity{Total: 7, ByProvider: []opsadmin.ProviderStat{{Provider: "github", Authentications: 7}}},
			Bundle:         opsadmin.BundleHealth{Configured: true, Generation: ip(4)},
			Audit:          opsadmin.AuditHealth{Entries: 42, Verified: true, ChainPosition: ip(42)},
			WindowHours:    24,
		})
	})
	mux.HandleFunc("/api/v1/admin/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, opsadmin.Status{
			Version: "0.1.0", UptimeSeconds: 99, StartedAt: "2026-06-24T12:00:00Z", Database: "ok",
			CertificateAuthority: opsadmin.CAStatus{Configured: true, Total: 2, Enabled: 1, Generation: ip(3)},
			Bundle:               opsadmin.BundleHealth{Configured: true, Generation: ip(3)},
			Audit:                opsadmin.AuditHealth{Entries: 10, Verified: true},
			Providers:            []string{"github", "keycloak"},
			API:                  opsadmin.APISummary{TotalRequests: 17, RoutesTracked: 4},
		})
	})
	mux.HandleFunc("/api/v1/admin/metrics", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, opsadmin.Metrics{TotalRequests: 5, Routes: []opsadmin.RouteMetric{{Route: "GET /api/v1/admin/health", Count: 3, Status2xx: 3, AvgMs: 1.5, MaxMs: 4.2}}})
	})
	return httptest.NewServer(mux)
}

func newOpsEnv(t *testing.T) (*httptest.Server, *opsRecorder) {
	t.Helper()
	rec := &opsRecorder{queries: map[string]string{}}
	srv := newOpsServer(t, rec)
	t.Cleanup(srv.Close)
	certEnv(t, srv.URL)
	seedActive(t, srv.URL)
	return srv, rec
}

func TestAuditTable(t *testing.T) {
	_, _ = newOpsEnv(t)
	out, err := execCLI(t, "audit")
	if err != nil {
		t.Fatalf("audit: %v\n%s", err, out)
	}
	for _, want := range []string{"POS", "certificate.issued", "machine.approved"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit table missing %q:\n%s", want, out)
		}
	}
}

func TestAuditJSON(t *testing.T) {
	_, _ = newOpsEnv(t)
	out, err := execCLI(t, "audit", "-o", "json")
	if err != nil {
		t.Fatalf("audit json: %v\n%s", err, out)
	}
	var page opsadmin.AuditPage
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if page.Count != 3 {
		t.Errorf("count=%d", page.Count)
	}
}

func TestAuditFiltersForwarded(t *testing.T) {
	_, rec := newOpsEnv(t)
	out, err := execCLI(t, "audit", "--event-type", "certificate.", "--result", "failure", "--limit", "10")
	if err != nil {
		t.Fatalf("audit filtered: %v\n%s", err, out)
	}
	q := rec.get("/api/v1/admin/audit")
	for _, want := range []string{"event_type=certificate.", "result=failure", "limit=10"} {
		if !strings.Contains(q, want) {
			t.Errorf("query %q missing %q", q, want)
		}
	}
	if !strings.Contains(out, "certificate.denied") || strings.Contains(out, "certificate.issued") {
		t.Errorf("expected only failure entry:\n%s", out)
	}
}

func TestEventsCategoryPreset(t *testing.T) {
	_, rec := newOpsEnv(t)
	out, err := execCLI(t, "events", "machine")
	if err != nil {
		t.Fatalf("events: %v\n%s", err, out)
	}
	if !strings.Contains(rec.get("/api/v1/admin/audit"), "event_type=machine.") {
		t.Errorf("events did not forward machine. prefix: %q", rec.get("/api/v1/admin/audit"))
	}
	if !strings.Contains(out, "machine.approved") || strings.Contains(out, "certificate.issued") {
		t.Errorf("events machine output:\n%s", out)
	}
}

func TestEventsUnknownCategory(t *testing.T) {
	_, _ = newOpsEnv(t)
	if _, err := execCLI(t, "events", "bogus"); err == nil {
		t.Error("expected error for unknown category")
	}
}

func TestHistoryFailures(t *testing.T) {
	_, rec := newOpsEnv(t)
	out, err := execCLI(t, "history", "failures")
	if err != nil {
		t.Fatalf("history: %v\n%s", err, out)
	}
	if !strings.Contains(rec.get("/api/v1/admin/audit"), "result=failure") {
		t.Errorf("history failures did not forward result=failure: %q", rec.get("/api/v1/admin/audit"))
	}
}

func TestHistoryUnknownKind(t *testing.T) {
	_, _ = newOpsEnv(t)
	if _, err := execCLI(t, "history", "nope"); err == nil {
		t.Error("expected error for unknown history kind")
	}
}

func TestHealthCommand(t *testing.T) {
	_, _ = newOpsEnv(t)
	out, err := execCLI(t, "health")
	if err != nil {
		t.Fatalf("health: %v\n%s", err, out)
	}
	for _, want := range []string{"DEGRADED", "online 2", "offline 1", "issued 5"} {
		if !strings.Contains(out, want) {
			t.Errorf("health missing %q:\n%s", want, out)
		}
	}
}

func TestHealthJSON(t *testing.T) {
	_, _ = newOpsEnv(t)
	out, err := execCLI(t, "health", "-o", "json")
	if err != nil {
		t.Fatalf("health json: %v\n%s", err, out)
	}
	var h opsadmin.Health
	if err := json.Unmarshal([]byte(out), &h); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if h.Status != "degraded" || h.Machines.Offline != 1 {
		t.Errorf("health=%+v", h)
	}
}

func TestStatusCommand(t *testing.T) {
	_, _ = newOpsEnv(t)
	out, err := execCLI(t, "status")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if !strings.Contains(out, "github, keycloak") || !strings.Contains(out, "database") {
		t.Errorf("status output:\n%s", out)
	}
}

func TestMetricsCommand(t *testing.T) {
	_, _ = newOpsEnv(t)
	out, err := execCLI(t, "metrics", "-o", "json")
	if err != nil {
		t.Fatalf("metrics: %v\n%s", err, out)
	}
	var m opsadmin.Metrics
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if m.TotalRequests != 5 || len(m.Routes) != 1 {
		t.Errorf("metrics=%+v", m)
	}
}
