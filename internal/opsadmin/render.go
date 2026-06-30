package opsadmin

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// Format selects how operational data is rendered.
type Format string

const (
	// FormatTable is the default compact human table.
	FormatTable Format = "table"
	// FormatWide is the table plus extra columns.
	FormatWide Format = "wide"
	// FormatJSON is machine-readable indented JSON.
	FormatJSON Format = "json"
	// FormatYAML is machine-readable YAML.
	FormatYAML Format = "yaml"
)

// ParseFormat resolves an -o/--output value (empty → table).
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "table":
		return FormatTable, nil
	case "wide":
		return FormatWide, nil
	case "json":
		return FormatJSON, nil
	case "yaml", "yml":
		return FormatYAML, nil
	default:
		return "", fmt.Errorf("unknown output format %q (want table|wide|json|yaml)", s)
	}
}

// Structured reports whether the format is a machine-readable encoding.
func (f Format) Structured() bool { return f == FormatJSON || f == FormatYAML }

func encode(w io.Writer, f Format, v any) error {
	switch f {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	case FormatYAML:
		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		defer enc.Close()
		return enc.Encode(v)
	default:
		return fmt.Errorf("encode called for non-structured format %q", f)
	}
}

// RenderAudit writes a page of audit entries in the requested format.
func RenderAudit(w io.Writer, page AuditPage, f Format) error {
	if f.Structured() {
		return encode(w, f, page)
	}
	return RenderAuditEntries(w, page.Entries, f)
}

// RenderAuditEntries writes audit entries as a table (used by both search and
// follow, which streams entry-by-entry without an enclosing page).
func RenderAuditEntries(w io.Writer, entries []AuditEntry, f Format) error {
	if f.Structured() {
		return encode(w, f, entries)
	}
	if len(entries) == 0 {
		_, err := fmt.Fprintln(w, "No matching audit events.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if f == FormatWide {
		fmt.Fprintln(tw, "POS\tTIME\tEVENT\tACTOR\tSUBJECT\tRESULT\tPROVIDER\tREQUEST ID")
		for _, e := range entries {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				e.Position, e.RecordedAt, e.EventType, e.Actor, orDash(deref(e.Subject)),
				e.Result, orDash(metaString(e.Metadata, "provider")),
				orDash(metaNested(e.Metadata, "client", "request_id")))
		}
	} else {
		fmt.Fprintln(tw, "POS\tTIME\tEVENT\tACTOR\tSUBJECT\tRESULT")
		for _, e := range entries {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n",
				e.Position, e.RecordedAt, e.EventType, e.Actor, orDash(deref(e.Subject)), e.Result)
		}
	}
	return tw.Flush()
}

// RenderHealth writes the operational health rollup.
func RenderHealth(w io.Writer, h Health, f Format) error {
	if f.Structured() {
		return encode(w, f, h)
	}
	p := func(k, v string) { fmt.Fprintf(w, "  %-22s %s\n", k+":", v) }
	fmt.Fprintf(w, "Mayfly health: %s\n", strings.ToUpper(h.Status))
	p("version", h.Version)
	p("uptime", fmt.Sprintf("%ds", h.UptimeSeconds))
	fmt.Fprintln(w, "  machines:")
	fmt.Fprintf(w, "    online %d  stale %d  offline %d  (total %d)\n",
		h.Machines.Online, h.Machines.Stale, h.Machines.Offline, h.Machines.Total)
	fmt.Fprintf(w, "    rollout %.1f%% on generation %s  (%d behind)\n",
		h.Machines.RolloutPercentage, orDash(intPtr(h.Machines.LatestGeneration)), h.Machines.Behind)
	fmt.Fprintf(w, "  certificates (%dh):    issued %d  denied %d\n",
		h.WindowHours, h.Certificates.Issued, h.Certificates.Denied)
	fmt.Fprintf(w, "  authentication (%dh):  %d\n", h.WindowHours, h.Authentication.Total)
	for _, prov := range h.Authentication.ByProvider {
		fmt.Fprintf(w, "    - %s: %d\n", prov.Provider, prov.Authentications)
	}
	fmt.Fprintf(w, "  bundle:                configured=%s generation=%s\n",
		yesNo(h.Bundle.Configured), orDash(intPtr(h.Bundle.Generation)))
	fmt.Fprintf(w, "  audit:                 entries=%d verified=%s\n",
		h.Audit.Entries, yesNo(h.Audit.Verified))
	return nil
}

// RenderStatus writes the system/cluster status.
func RenderStatus(w io.Writer, s Status, f Format) error {
	if f.Structured() {
		return encode(w, f, s)
	}
	p := func(k, v string) { fmt.Fprintf(w, "  %-20s %s\n", k+":", v) }
	fmt.Fprintln(w, "Mayfly status")
	p("version", s.Version)
	p("uptime", fmt.Sprintf("%ds", s.UptimeSeconds))
	p("started at", s.StartedAt)
	p("database", s.Database)
	p("ca", fmt.Sprintf("configured=%s total=%d enabled=%d generation=%s",
		yesNo(s.CertificateAuthority.Configured), s.CertificateAuthority.Total,
		s.CertificateAuthority.Enabled, orDash(intPtr(s.CertificateAuthority.Generation))))
	p("bundle", fmt.Sprintf("configured=%s generation=%s",
		yesNo(s.Bundle.Configured), orDash(intPtr(s.Bundle.Generation))))
	p("audit", fmt.Sprintf("entries=%d verified=%s", s.Audit.Entries, yesNo(s.Audit.Verified)))
	p("providers", strings.Join(s.Providers, ", "))
	p("api requests", strconv.FormatInt(s.API.TotalRequests, 10))
	return nil
}

// RenderMetrics writes API request statistics + timings.
func RenderMetrics(w io.Writer, m Metrics, f Format) error {
	if f.Structured() {
		return encode(w, f, m)
	}
	fmt.Fprintf(w, "API metrics (total requests: %d)\n", m.TotalRequests)
	if len(m.Routes) == 0 {
		_, err := fmt.Fprintln(w, "  (no requests recorded yet)")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "  ROUTE\tCOUNT\t2XX\t4XX\t5XX\tAVG(ms)\tMAX(ms)")
	for _, r := range m.Routes {
		fmt.Fprintf(tw, "  %s\t%d\t%d\t%d\t%d\t%.2f\t%.2f\n",
			r.Route, r.Count, r.Status2xx, r.Status4xx, r.Status5xx, r.AvgMs, r.MaxMs)
	}
	return tw.Flush()
}

// RenderDoctor writes the diagnostic report.
func RenderDoctor(w io.Writer, r DoctorReport, f Format) error {
	if f.Structured() {
		return encode(w, f, r)
	}
	fmt.Fprintf(w, "Mayfly doctor — overall: %s\n\n", r.Overall)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for _, c := range r.Checks {
		fmt.Fprintf(tw, "  [%s]\t%s\t%s\n", c.Status, c.Name, c.Detail)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	// Print guidance for anything not PASS, so remediation is actionable.
	var advised bool
	for _, c := range r.Checks {
		if c.Status != CheckPass && c.Guidance != "" {
			if !advised {
				fmt.Fprintln(w, "\nguidance:")
				advised = true
			}
			fmt.Fprintf(w, "  - %s: %s\n", c.Name, c.Guidance)
		}
	}
	return nil
}

// OverallStatus folds individual check statuses into a single verdict: FAIL if
// any check failed, else WARN if any warned, else PASS.
func OverallStatus(checks []CheckResult) string {
	overall := CheckPass
	for _, c := range checks {
		switch c.Status {
		case CheckFail:
			return CheckFail
		case CheckWarn:
			overall = CheckWarn
		}
	}
	return overall
}

func metaString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func metaNested(m map[string]any, outer, inner string) string {
	if m == nil {
		return ""
	}
	if sub, ok := m[outer].(map[string]any); ok {
		if v, ok := sub[inner].(string); ok {
			return v
		}
	}
	return ""
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func intPtr(p *int64) string {
	if p == nil {
		return ""
	}
	return strconv.FormatInt(*p, 10)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
