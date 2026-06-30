// Package opsadmin holds the client-side DTOs and renderers for the operational
// console (`mayfly audit`/`events`/`history`/`health`/`status`/`doctor`). The
// structs mirror the additive JSON shapes returned by the mayfly-server
// operational admin API (013C / ADR-0024); they are read-only views and never
// carry secrets.
package opsadmin

// AuditEntry is one row of the tamper-evident audit log, projected for display.
type AuditEntry struct {
	Position   int64          `json:"position"`
	EventType  string         `json:"event_type"`
	Actor      string         `json:"actor"`
	Subject    *string        `json:"subject"`
	Result     string         `json:"result"`
	RecordedAt string         `json:"recorded_at"`
	Metadata   map[string]any `json:"metadata"`
	EntryHash  string         `json:"entry_hash"`
}

// AuditPage is a bounded page of audit search results.
type AuditPage struct {
	Entries      []AuditEntry `json:"entries"`
	Count        int          `json:"count"`
	HasMore      bool         `json:"has_more"`
	LastPosition *int64       `json:"last_position"`
	Order        string       `json:"order"`
}

// Health is the operational health rollup (`GET /admin/health`).
type Health struct {
	Status         string        `json:"status"`
	Version        string        `json:"version"`
	UptimeSeconds  int64         `json:"uptime_seconds"`
	Machines       MachineHealth `json:"machines"`
	Certificates   CertActivity  `json:"certificates"`
	Authentication AuthActivity  `json:"authentication"`
	Bundle         BundleHealth  `json:"bundle"`
	Audit          AuditHealth   `json:"audit"`
	WindowHours    int64         `json:"window_hours"`
}

// MachineHealth summarizes fleet liveness and rollout.
type MachineHealth struct {
	Total             int64   `json:"total"`
	Online            int64   `json:"online"`
	Stale             int64   `json:"stale"`
	Offline           int64   `json:"offline"`
	LatestGeneration  *int64  `json:"latest_generation"`
	RolloutPercentage float64 `json:"rollout_percentage"`
	Behind            int64   `json:"behind"`
}

// CertActivity counts certificate issuance/denials in the recent window.
type CertActivity struct {
	Issued int64 `json:"issued"`
	Denied int64 `json:"denied"`
}

// AuthActivity counts authentications, with a per-provider breakdown.
type AuthActivity struct {
	Total      int64          `json:"total"`
	ByProvider []ProviderStat `json:"by_provider"`
}

// ProviderStat is a per-provider authentication count.
type ProviderStat struct {
	Provider        string `json:"provider"`
	Authentications int64  `json:"authentications"`
}

// BundleHealth describes the CA trust bundle status.
type BundleHealth struct {
	Configured  bool    `json:"configured"`
	Generation  *int64  `json:"generation"`
	Fingerprint *string `json:"fingerprint"`
}

// AuditHealth describes the audit chain health.
type AuditHealth struct {
	Entries       int64  `json:"entries"`
	Verified      bool   `json:"verified"`
	ChainPosition *int64 `json:"chain_position"`
}

// Status is the lower-level system/cluster status (`GET /admin/status`).
type Status struct {
	Version              string       `json:"version"`
	UptimeSeconds        int64        `json:"uptime_seconds"`
	StartedAt            string       `json:"started_at"`
	Database             string       `json:"database"`
	CertificateAuthority CAStatus     `json:"certificate_authority"`
	Bundle               BundleHealth `json:"bundle"`
	Audit                AuditHealth  `json:"audit"`
	Providers            []string     `json:"providers"`
	API                  APISummary   `json:"api"`
}

// CAStatus summarizes the certificate authority.
type CAStatus struct {
	Configured bool   `json:"configured"`
	Total      int64  `json:"total"`
	Enabled    int64  `json:"enabled"`
	Generation *int64 `json:"generation"`
}

// APISummary is the request-statistics summary embedded in status.
type APISummary struct {
	TotalRequests int64 `json:"total_requests"`
	RoutesTracked int   `json:"routes_tracked"`
}

// Metrics is the API request statistics + timings (`GET /admin/metrics`).
type Metrics struct {
	TotalRequests int64         `json:"total_requests"`
	Routes        []RouteMetric `json:"routes"`
}

// RouteMetric is per-route request statistics.
type RouteMetric struct {
	Route     string  `json:"route"`
	Count     int64   `json:"count"`
	Status2xx int64   `json:"status_2xx"`
	Status4xx int64   `json:"status_4xx"`
	Status5xx int64   `json:"status_5xx"`
	AvgMs     float64 `json:"avg_ms"`
	MinMs     float64 `json:"min_ms"`
	MaxMs     float64 `json:"max_ms"`
}

// Check status constants for `mayfly doctor`.
const (
	CheckPass = "PASS"
	CheckWarn = "WARN"
	CheckFail = "FAIL"
	CheckSkip = "SKIP"
)

// CheckResult is one diagnostic outcome with actionable guidance.
type CheckResult struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
	Guidance string `json:"guidance,omitempty"`
}

// DoctorReport is the full `mayfly doctor` result.
type DoctorReport struct {
	Overall string        `json:"overall"`
	Checks  []CheckResult `json:"checks"`
}
