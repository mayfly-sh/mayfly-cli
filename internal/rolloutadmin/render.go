package rolloutadmin

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// Format selects how rollout data is rendered.
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

// progressBarWidth is the character width of the rendered progress bar.
const progressBarWidth = 30

// ProgressBar renders a fixed-width [#####-----] bar for a 0–100 percentage.
func ProgressBar(percentage float64) string {
	if percentage < 0 {
		percentage = 0
	}
	if percentage > 100 {
		percentage = 100
	}
	filled := int(percentage/100*float64(progressBarWidth) + 0.5)
	if filled > progressBarWidth {
		filled = progressBarWidth
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", progressBarWidth-filled) + "]"
}

// RenderStatus writes the headline rollout status.
func RenderStatus(w io.Writer, s Status, f Format) error {
	if f.Structured() {
		return encode(w, f, s)
	}
	writeDashboard(w, s, false)
	if f == FormatWide && len(s.Generations) > 0 {
		fmt.Fprintln(w, "  generations:")
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "    GENERATION\tMACHINES\tSHARE\tLATEST")
		for _, g := range s.Generations {
			fmt.Fprintf(tw, "    %d\t%d\t%.1f%%\t%s\n", g.Generation, g.Machines, g.Percentage, yesNo(g.IsLatest))
		}
		return tw.Flush()
	}
	return nil
}

// RenderSummary writes a richer one-screen narrative of the rollout.
func RenderSummary(w io.Writer, s Status, f Format) error {
	if f.Structured() {
		return encode(w, f, s)
	}
	writeDashboard(w, s, true)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  health: %s\n", s.Health.Status)
	for _, r := range s.Health.Reasons {
		fmt.Fprintf(w, "    - %s\n", r)
	}
	if len(s.Generations) > 0 {
		fmt.Fprintln(w, "  generations:")
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "    GENERATION\tMACHINES\tSHARE\tLATEST")
		for _, g := range s.Generations {
			fmt.Fprintf(tw, "    %d\t%d\t%.1f%%\t%s\n", g.Generation, g.Machines, g.Percentage, yesNo(g.IsLatest))
		}
		return tw.Flush()
	}
	return nil
}

// writeDashboard renders the progress bar, %, ETA, and the
// healthy/stale/offline/failed/pending breakdown shared by status/watch/summary.
func writeDashboard(w io.Writer, s Status, withFingerprint bool) {
	gen := "-"
	if s.LatestGeneration != nil {
		gen = strconv.FormatInt(*s.LatestGeneration, 10)
	}
	fmt.Fprintf(w, "Fleet rollout — generation %s  [%s]\n", gen, s.Health.Status)
	fmt.Fprintf(w, "  %s %.1f%%  (%d/%d active machines)\n",
		ProgressBar(s.Percentage), s.Percentage, s.Completed, s.ActiveMachines)
	fmt.Fprintf(w, "  healthy %d  pending %d  stale %d  offline %d  failed %d\n",
		s.Breakdown.Healthy, s.Breakdown.Pending, s.Breakdown.Stale, s.Breakdown.Offline, s.Breakdown.Failed)
	fmt.Fprintf(w, "  liveness: online %d  stale %d  offline %d  (total %d)\n",
		s.Online, s.Stale, s.Offline, s.TotalMachines)
	fmt.Fprintf(w, "  ETA: %s\n", etaText(s.ETA))
	if withFingerprint && s.BundleFingerprint != "" {
		fmt.Fprintf(w, "  bundle: %s\n", s.BundleFingerprint)
	}
}

func etaText(e ETA) string {
	if e.Complete {
		return "complete"
	}
	if e.ETASeconds == nil {
		return fmt.Sprintf("unknown (%d remaining, no recent applies)", e.Remaining)
	}
	return fmt.Sprintf("~%s (%d remaining at %.0f/h)", humanDuration(*e.ETASeconds), e.Remaining, e.PerHour)
}

// humanDuration formats seconds as a compact h/m/s string.
func humanDuration(secs int64) string {
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	}
	if secs < 3600 {
		return fmt.Sprintf("%dm", secs/60)
	}
	h := secs / 3600
	m := (secs % 3600) / 60
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

// RenderHealth writes the rollout health verdict.
func RenderHealth(w io.Writer, h Health, f Format) error {
	if f.Structured() {
		return encode(w, f, h)
	}
	fmt.Fprintf(w, "Rollout health: %s (score %d)\n", h.Status, h.Score)
	if len(h.Reasons) == 0 {
		return nil
	}
	fmt.Fprintln(w, "  reasons:")
	for _, r := range h.Reasons {
		fmt.Fprintf(w, "    - %s\n", r)
	}
	return nil
}

// RenderGenerations writes the per-generation population.
func RenderGenerations(w io.Writer, g GenerationsResponse, f Format) error {
	if f.Structured() {
		return encode(w, f, g)
	}
	if len(g.Generations) == 0 {
		_, err := fmt.Fprintln(w, "No machines have synced a generation yet.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "GENERATION\tMACHINES\tSHARE\tLATEST")
	for _, d := range g.Generations {
		fmt.Fprintf(tw, "%d\t%d\t%.1f%%\t%s\n", d.Generation, d.Machines, d.Percentage, yesNo(d.IsLatest))
	}
	return tw.Flush()
}

// RenderMachines writes the per-machine rollout view.
func RenderMachines(w io.Writer, m MachinesResponse, f Format) error {
	if f.Structured() {
		return encode(w, f, m)
	}
	if len(m.Machines) == 0 {
		_, err := fmt.Fprintln(w, "No matching machines.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if f == FormatWide {
		fmt.Fprintln(tw, "HOSTNAME\tMACHINE ID\tSTATUS\tLIVENESS\tSYNCED\tLATEST\tBEHIND\tSTATE\tCATEGORY\tLAST SYNC")
		for _, mc := range m.Machines {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
				mc.Hostname, mc.MachineID, mc.Status, mc.Liveness,
				genStr(mc.SyncedGeneration), genStr(mc.LatestGeneration), mc.GenerationsBehind,
				mc.State, mc.Category, orDash(mc.LastSync))
		}
	} else {
		fmt.Fprintln(tw, "HOSTNAME\tLIVENESS\tSYNCED\tLATEST\tBEHIND\tSTATE\tCATEGORY")
		for _, mc := range m.Machines {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
				mc.Hostname, mc.Liveness, genStr(mc.SyncedGeneration), genStr(mc.LatestGeneration),
				mc.GenerationsBehind, mc.State, mc.Category)
		}
	}
	return tw.Flush()
}

// RenderStuck writes the stuck-machine report with remediation.
func RenderStuck(w io.Writer, r StuckReport, f Format) error {
	if f.Structured() {
		return encode(w, f, r)
	}
	if r.Count == 0 {
		_, err := fmt.Fprintln(w, "No stuck machines — every machine is converging.")
		return err
	}
	fmt.Fprintf(w, "Stuck machines: %d\n", r.Count)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "  HOSTNAME\tCATEGORY\tBEHIND\tLIVENESS\tRECOMMENDATION")
	for _, m := range r.Stuck {
		fmt.Fprintf(tw, "  %s\t%s\t%d\t%s\t%s\n",
			m.Hostname, m.Category, m.GenerationsBehind, m.Liveness, m.Recommendation)
	}
	return tw.Flush()
}

// RenderExplain writes the categorized explanation of incompleteness.
func RenderExplain(w io.Writer, e Explanation, f Format) error {
	if f.Structured() {
		return encode(w, f, e)
	}
	if e.Complete {
		_, err := fmt.Fprintln(w, "Rollout is complete — every active machine is on the latest generation.")
		return err
	}
	fmt.Fprintf(w, "Rollout incomplete: %d machine(s) behind the latest generation.\n\n", e.Remaining)
	for _, c := range e.Categories {
		fmt.Fprintf(w, "  %s (%d): %s\n", c.Category, c.Count, c.Description)
		fmt.Fprintf(w, "    → %s\n", c.Recommendation)
		if len(c.Machines) > 0 {
			fmt.Fprintf(w, "    machines: %s\n", strings.Join(c.Machines, ", "))
		}
	}
	return nil
}

// RenderTimeline writes the bundle rollout timeline.
func RenderTimeline(w io.Writer, t Timeline, f Format) error {
	if f.Structured() {
		return encode(w, f, t)
	}
	if t.Count == 0 {
		_, err := fmt.Fprintln(w, "No rollout events recorded.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if f == FormatWide {
		fmt.Fprintln(tw, "POS\tTIME\tOUTCOME\tMACHINE\tGEN\tREASON")
		for _, e := range t.Events {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n",
				e.Position, e.At, e.Outcome, orDash(e.MachineID), genStr(e.Generation), orDash(e.Reason))
		}
	} else {
		fmt.Fprintln(tw, "TIME\tOUTCOME\tMACHINE\tGEN")
		for _, e := range t.Events {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.At, e.Outcome, orDash(e.MachineID), genStr(e.Generation))
		}
	}
	return tw.Flush()
}

// RenderHistory writes the generation adoption history.
func RenderHistory(w io.Writer, h History, f Format) error {
	if f.Structured() {
		return encode(w, f, h)
	}
	if len(h.Generations) == 0 {
		_, err := fmt.Fprintln(w, "No generation history recorded.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "GENERATION\tLATEST\tMACHINES\tAPPLIES\tFIRST APPLIED\tLAST APPLIED")
	for _, g := range h.Generations {
		fmt.Fprintf(tw, "%d\t%s\t%d\t%d\t%s\t%s\n",
			g.Generation, yesNo(g.IsLatest), g.MachinesOnGeneration, g.TotalApplies,
			orDash(g.FirstAppliedAt), orDash(g.LastAppliedAt))
	}
	return tw.Flush()
}

func genStr(p *int64) string {
	if p == nil {
		return "-"
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
