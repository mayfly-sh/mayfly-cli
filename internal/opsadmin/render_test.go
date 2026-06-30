package opsadmin

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func strPtr(s string) *string { return &s }
func i64Ptr(i int64) *int64   { return &i }

func sampleEntries() []AuditEntry {
	return []AuditEntry{
		{Position: 2, EventType: "certificate.denied", Actor: "mallory", Subject: strPtr("web-01"), Result: "failure", RecordedAt: "2026-06-24T12:00:01.000Z", Metadata: map[string]any{"provider": "github"}},
		{Position: 1, EventType: "certificate.issued", Actor: "octocat", Subject: strPtr("web-01"), Result: "success", RecordedAt: "2026-06-24T12:00:00.000Z", Metadata: map[string]any{"provider": "github", "serial": "0001", "client": map[string]any{"request_id": "req-aaa"}}},
	}
}

func TestParseFormat(t *testing.T) {
	for _, in := range []string{"", "table", "wide", "json", "yaml", "yml"} {
		if _, err := ParseFormat(in); err != nil {
			t.Errorf("ParseFormat(%q) unexpected error: %v", in, err)
		}
	}
	if _, err := ParseFormat("toml"); err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestRenderAuditTable(t *testing.T) {
	var buf bytes.Buffer
	page := AuditPage{Entries: sampleEntries(), Count: 2, HasMore: false, Order: "desc"}
	if err := RenderAudit(&buf, page, FormatTable); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"POS", "EVENT", "certificate.denied", "certificate.issued", "failure", "success"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
}

func TestRenderAuditWideIncludesProviderAndRequestID(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderAuditEntries(&buf, sampleEntries(), FormatWide); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"PROVIDER", "REQUEST ID", "github", "req-aaa"} {
		if !strings.Contains(out, want) {
			t.Errorf("wide missing %q:\n%s", want, out)
		}
	}
}

func TestRenderAuditJSONRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	page := AuditPage{Entries: sampleEntries(), Count: 2, Order: "desc"}
	if err := RenderAudit(&buf, page, FormatJSON); err != nil {
		t.Fatal(err)
	}
	var got AuditPage
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got.Count != 2 || len(got.Entries) != 2 || got.Entries[0].EventType != "certificate.denied" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestRenderAuditEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderAudit(&buf, AuditPage{}, FormatTable); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No matching audit events") {
		t.Errorf("expected empty message, got %q", buf.String())
	}
}

func sampleHealth() Health {
	return Health{
		Status: "degraded", Version: "0.1.0", UptimeSeconds: 120,
		Machines:       MachineHealth{Total: 3, Online: 2, Stale: 0, Offline: 1, LatestGeneration: i64Ptr(4), RolloutPercentage: 66.7, Behind: 1},
		Certificates:   CertActivity{Issued: 5, Denied: 1},
		Authentication: AuthActivity{Total: 7, ByProvider: []ProviderStat{{Provider: "github", Authentications: 7}}},
		Bundle:         BundleHealth{Configured: true, Generation: i64Ptr(4), Fingerprint: strPtr("sha256:abc")},
		Audit:          AuditHealth{Entries: 42, Verified: true, ChainPosition: i64Ptr(42)},
		WindowHours:    24,
	}
}

func TestRenderHealthTable(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHealth(&buf, sampleHealth(), FormatTable); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"DEGRADED", "online 2", "offline 1", "issued 5", "denied 1", "github: 7", "verified=yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("health table missing %q:\n%s", want, out)
		}
	}
}

func TestRenderHealthYAML(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHealth(&buf, sampleHealth(), FormatYAML); err != nil {
		t.Fatal(err)
	}
	var got Health
	if err := yaml.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, buf.String())
	}
	if got.Status != "degraded" || got.Machines.Offline != 1 {
		t.Errorf("yaml mismatch: %+v", got)
	}
}

func TestRenderStatusTable(t *testing.T) {
	var buf bytes.Buffer
	s := Status{
		Version: "0.1.0", UptimeSeconds: 99, StartedAt: "2026-06-24T12:00:00Z", Database: "ok",
		CertificateAuthority: CAStatus{Configured: true, Total: 2, Enabled: 1, Generation: i64Ptr(3)},
		Bundle:               BundleHealth{Configured: true, Generation: i64Ptr(3)},
		Audit:                AuditHealth{Entries: 10, Verified: true},
		Providers:            []string{"github", "keycloak"},
		API:                  APISummary{TotalRequests: 17, RoutesTracked: 4},
	}
	if err := RenderStatus(&buf, s, FormatTable); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"database", "ok", "github, keycloak", "api requests", "17"} {
		if !strings.Contains(out, want) {
			t.Errorf("status table missing %q:\n%s", want, out)
		}
	}
}

func TestRenderMetricsTable(t *testing.T) {
	var buf bytes.Buffer
	m := Metrics{TotalRequests: 5, Routes: []RouteMetric{{Route: "GET /api/v1/admin/health", Count: 3, Status2xx: 3, AvgMs: 1.5, MaxMs: 4.2}}}
	if err := RenderMetrics(&buf, m, FormatTable); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"total requests: 5", "ROUTE", "GET /api/v1/admin/health", "1.50"} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics table missing %q:\n%s", want, out)
		}
	}
}

func TestRenderDoctorAndOverall(t *testing.T) {
	checks := []CheckResult{
		{Name: "server connectivity", Status: CheckPass, Detail: "reachable"},
		{Name: "clock drift", Status: CheckWarn, Detail: "6s", Guidance: "enable NTP"},
	}
	if got := OverallStatus(checks); got != CheckWarn {
		t.Errorf("overall=%q want WARN", got)
	}
	checks = append(checks, CheckResult{Name: "ca consistency", Status: CheckFail, Detail: "no ca", Guidance: "create a ca"})
	if got := OverallStatus(checks); got != CheckFail {
		t.Errorf("overall=%q want FAIL", got)
	}

	var buf bytes.Buffer
	if err := RenderDoctor(&buf, DoctorReport{Overall: CheckFail, Checks: checks}, FormatTable); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"overall: FAIL", "[PASS]", "[WARN]", "[FAIL]", "guidance:", "enable NTP", "create a ca"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor output missing %q:\n%s", want, out)
		}
	}
}

func TestOverallAllPass(t *testing.T) {
	checks := []CheckResult{{Status: CheckPass}, {Status: CheckSkip}, {Status: CheckPass}}
	if got := OverallStatus(checks); got != CheckPass {
		t.Errorf("overall=%q want PASS", got)
	}
}
