package cmd

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mayfly-ssh/mayfly-cli/internal/client"
	"github.com/mayfly-ssh/mayfly-cli/internal/opsadmin"
)

// auditFilterFlags holds the shared audit/event/history filter flags.
type auditFilterFlags struct {
	output    string
	eventType string
	actor     string
	machine   string
	provider  string
	serial    string
	requestID string
	result    string
	since     string
	until     string
	limit     int
	tail      int
	follow    bool
	watch     bool
	interval  time.Duration
}

// query builds the audit search query string from the filter flags.
func (f *auditFilterFlags) query() (url.Values, error) {
	v := url.Values{}
	set := func(key, val string) {
		if strings.TrimSpace(val) != "" {
			v.Set(key, val)
		}
	}
	set("event_type", f.eventType)
	set("actor", f.actor)
	set("machine", f.machine)
	set("provider", f.provider)
	set("serial", f.serial)
	set("request_id", f.requestID)
	set("result", f.result)
	if since, err := resolveTime(f.since); err != nil {
		return nil, fmt.Errorf("invalid --since: %w", err)
	} else if since != "" {
		v.Set("since", since)
	}
	if until, err := resolveTime(f.until); err != nil {
		return nil, fmt.Errorf("invalid --until: %w", err)
	} else if until != "" {
		v.Set("until", until)
	}
	limit := f.limit
	if f.tail > 0 {
		limit = f.tail
	}
	if limit > 0 {
		v.Set("limit", strconv.Itoa(limit))
	}
	return v, nil
}

// resolveTime accepts an RFC3339 timestamp, or a relative duration like "24h",
// "30m", or "7d" (interpreted as "ago"), and returns an RFC3339 UTC string.
func resolveTime(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	// Relative duration: support a trailing "d" (days) on top of Go durations.
	dur := s
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return "", fmt.Errorf("not a timestamp or duration: %q", s)
		}
		dur = fmt.Sprintf("%dh", days*24)
	}
	d, err := time.ParseDuration(dur)
	if err != nil {
		return "", fmt.Errorf("not a timestamp or duration: %q", s)
	}
	return time.Now().Add(-d).UTC().Format(time.RFC3339), nil
}

func addAuditFilterFlags(cmd *cobra.Command, f *auditFilterFlags) {
	cmd.Flags().StringVarP(&f.output, "output", "o", "table", "output format: table|wide|json|yaml")
	cmd.Flags().StringVar(&f.eventType, "event-type", "", "event type (exact, or prefix ending in '.')")
	cmd.Flags().StringVar(&f.actor, "actor", "", "actor (operator/username)")
	cmd.Flags().StringVar(&f.actor, "operator", "", "alias for --actor")
	cmd.Flags().StringVar(&f.actor, "username", "", "alias for --actor")
	cmd.Flags().StringVar(&f.machine, "machine", "", "machine id or hostname")
	cmd.Flags().StringVar(&f.provider, "provider", "", "auth provider id")
	cmd.Flags().StringVar(&f.serial, "serial", "", "certificate serial")
	cmd.Flags().StringVar(&f.requestID, "request-id", "", "correlation request id")
	cmd.Flags().StringVar(&f.result, "result", "", "result: success|failure")
	cmd.Flags().StringVar(&f.since, "since", "", "lower time bound (RFC3339 or duration like 24h, 7d)")
	cmd.Flags().StringVar(&f.until, "until", "", "upper time bound (RFC3339 or duration like 1h)")
	cmd.Flags().IntVar(&f.limit, "limit", 50, "maximum entries to return")
	cmd.Flags().IntVar(&f.tail, "tail", 0, "show only the most recent N entries (overrides --limit)")
	cmd.Flags().BoolVarP(&f.follow, "follow", "f", false, "stream new entries until interrupted")
	cmd.Flags().BoolVarP(&f.watch, "watch", "w", false, "continuously refresh the view until interrupted")
	cmd.Flags().DurationVar(&f.interval, "interval", 2*time.Second, "refresh/poll interval for --watch/--follow")
}

// runAudit executes an audit search command with the given fixed event-type
// prefix preset (empty for the generic `audit` command).
func runAudit(cmd *cobra.Command, f *auditFilterFlags, presetEventType string) error {
	app := FromContext(cmd.Context())
	format, err := opsadmin.ParseFormat(f.output)
	if err != nil {
		return err
	}
	if presetEventType != "" && strings.TrimSpace(f.eventType) == "" {
		f.eventType = presetEventType
	}
	api, err := app.adminClient()
	if err != nil {
		return err
	}
	q, err := f.query()
	if err != nil {
		return err
	}

	if f.follow {
		return runAuditFollow(cmd, api, q, format, f.interval)
	}

	render := func() error {
		var page opsadmin.AuditPage
		if derr := api.Do(cmd.Context(), "GET", "/api/v1/admin/audit?"+q.Encode(), nil, &page); derr != nil {
			return derr
		}
		return opsadmin.RenderAudit(cmd.OutOrStdout(), page, format)
	}
	return runMaybeWatchOps(cmd, f.watch, f.interval, format.Structured(), render)
}

// runAuditFollow streams new audit entries by advancing a chain-position cursor.
func runAuditFollow(cmd *cobra.Command, api *client.Client, base url.Values, format opsadmin.Format, interval time.Duration) error {
	if format.Structured() {
		return fmt.Errorf("--follow is not supported with %s output", format)
	}
	if interval < time.Second {
		interval = time.Second
	}
	out := cmd.OutOrStdout()

	// Seed the cursor from the most recent entry so follow tails the live log
	// rather than replaying the whole history.
	var last int64
	seed := cloneValues(base)
	seed.Set("limit", "1")
	var head opsadmin.AuditPage
	if err := api.Do(cmd.Context(), "GET", "/api/v1/admin/audit?"+seed.Encode(), nil, &head); err != nil {
		return err
	}
	if head.LastPosition != nil {
		last = *head.LastPosition
	}

	for {
		q := cloneValues(base)
		q.Set("after", strconv.FormatInt(last, 10))
		q.Set("order", "asc")
		q.Del("limit")
		var page opsadmin.AuditPage
		if err := api.Do(cmd.Context(), "GET", "/api/v1/admin/audit/stream?"+q.Encode(), nil, &page); err != nil {
			return err
		}
		if len(page.Entries) > 0 {
			if err := opsadmin.RenderAuditEntries(out, page.Entries, format); err != nil {
				return err
			}
			if page.LastPosition != nil {
				last = *page.LastPosition
			}
		}
		select {
		case <-cmd.Context().Done():
			return nil
		case <-time.After(interval):
		}
	}
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vals := range v {
		for _, val := range vals {
			out.Add(k, val)
		}
	}
	return out
}

func newAuditCommand() *cobra.Command {
	f := &auditFilterFlags{}
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Search the tamper-evident audit log",
		Long: "Search the append-only audit log with rich filters (event type, actor/operator, " +
			"machine, provider, certificate serial, request id, result, date range) and stream new " +
			"events with --follow. This is the operator's window into everything that happened.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAudit(cmd, f, "")
		},
	}
	addAuditFilterFlags(cmd, f)
	return cmd
}

// eventCategories maps `mayfly events <category>` to an event-type prefix.
var eventCategories = map[string]string{
	"certificate":    "certificate.",
	"certificates":   "certificate.",
	"cert":           "certificate.",
	"machine":        "machine.",
	"machines":       "machine.",
	"ca":             "ca.",
	"auth":           "auth.",
	"authentication": "auth.",
	"bundle":         "bundle.",
	"ops":            "ops.",
}

func newEventsCommand() *cobra.Command {
	f := &auditFilterFlags{}
	cmd := &cobra.Command{
		Use:   "events [category]",
		Short: "Show events by category (certificate|machine|ca|auth|bundle)",
		Long: "Convenience over `mayfly audit`: filter the audit log by a category. With no " +
			"category, shows all recent events. Categories: certificate, machine, ca, auth, bundle, ops.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			preset := ""
			if len(args) == 1 {
				p, ok := eventCategories[strings.ToLower(args[0])]
				if !ok {
					return fmt.Errorf("unknown category %q (want certificate|machine|ca|auth|bundle|ops)", args[0])
				}
				preset = p
			}
			return runAudit(cmd, f, preset)
		},
	}
	addAuditFilterFlags(cmd, f)
	return cmd
}

// historyKinds maps `mayfly history <kind>` to a curated audit preset.
type historyPreset struct {
	eventType string
	result    string
}

var historyKinds = map[string]historyPreset{
	"certificates": {eventType: "certificate."},
	"issuance":     {eventType: "certificate.issued"},
	"logins":       {eventType: "auth."},
	"auth":         {eventType: "auth."},
	"machines":     {eventType: "machine."},
	"ca":           {eventType: "ca."},
	"bundles":      {eventType: "bundle."},
	"rollout":      {eventType: "bundle."},
	"failures":     {result: "failure"},
}

func newHistoryCommand() *cobra.Command {
	f := &auditFilterFlags{}
	cmd := &cobra.Command{
		Use:   "history <kind>",
		Short: "Named history reports (certificates|logins|machines|ca|bundles|failures)",
		Long: "Curated views over the audit log. Kinds: certificates, issuance, logins, auth, " +
			"machines, ca, bundles, rollout, failures. All the audit filters and --since/--until apply.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			preset, ok := historyKinds[strings.ToLower(args[0])]
			if !ok {
				return fmt.Errorf("unknown history kind %q", args[0])
			}
			if preset.result != "" && strings.TrimSpace(f.result) == "" {
				f.result = preset.result
			}
			return runAudit(cmd, f, preset.eventType)
		},
	}
	addAuditFilterFlags(cmd, f)
	return cmd
}

func newHealthCommand() *cobra.Command {
	var (
		output   string
		watch    bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Show overall platform health (fleet, certs, auth, bundle, audit)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := opsadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.adminClient()
			if err != nil {
				return err
			}
			render := func() error {
				var h opsadmin.Health
				if derr := api.Do(cmd.Context(), "GET", "/api/v1/admin/health", nil, &h); derr != nil {
					return derr
				}
				return opsadmin.RenderHealth(cmd.OutOrStdout(), h, format)
			}
			return runMaybeWatchOps(cmd, watch, interval, format.Structured(), render)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table|wide|json|yaml")
	cmd.Flags().BoolVarP(&watch, "watch", "w", false, "continuously refresh until interrupted")
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "refresh interval in --watch mode")
	return cmd
}

func newStatusCommand() *cobra.Command {
	var (
		output   string
		watch    bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show system/cluster status (version, ca, bundle, audit, api)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := opsadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.adminClient()
			if err != nil {
				return err
			}
			render := func() error {
				var s opsadmin.Status
				if derr := api.Do(cmd.Context(), "GET", "/api/v1/admin/status", nil, &s); derr != nil {
					return derr
				}
				return opsadmin.RenderStatus(cmd.OutOrStdout(), s, format)
			}
			return runMaybeWatchOps(cmd, watch, interval, format.Structured(), render)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table|wide|json|yaml")
	cmd.Flags().BoolVarP(&watch, "watch", "w", false, "continuously refresh until interrupted")
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "refresh interval in --watch mode")
	return cmd
}

func newMetricsCommand() *cobra.Command {
	var (
		output   string
		watch    bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Show API request statistics and timings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := opsadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.adminClient()
			if err != nil {
				return err
			}
			render := func() error {
				var m opsadmin.Metrics
				if derr := api.Do(cmd.Context(), "GET", "/api/v1/admin/metrics", nil, &m); derr != nil {
					return derr
				}
				return opsadmin.RenderMetrics(cmd.OutOrStdout(), m, format)
			}
			return runMaybeWatchOps(cmd, watch, interval, format.Structured(), render)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table|wide|json|yaml")
	cmd.Flags().BoolVarP(&watch, "watch", "w", false, "continuously refresh until interrupted")
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "refresh interval in --watch mode")
	return cmd
}

// runMaybeWatchOps renders once, or repeatedly when watch is set. Watch mode is
// disabled for structured output (json/yaml) where a single document is wanted.
func runMaybeWatchOps(cmd *cobra.Command, watch bool, interval time.Duration, structured bool, render func() error) error {
	if !watch || structured {
		return render()
	}
	if interval < time.Second {
		interval = time.Second
	}
	out := cmd.OutOrStdout()
	for {
		fmt.Fprint(out, "\033[H\033[2J")
		fmt.Fprintf(out, "%s — refreshing every %s (Ctrl-C to stop)\n\n", time.Now().Format(time.RFC3339), interval)
		if err := render(); err != nil {
			return err
		}
		select {
		case <-cmd.Context().Done():
			return nil
		case <-time.After(interval):
		}
	}
}
