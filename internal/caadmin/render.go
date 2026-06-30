package caadmin

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// Format selects how CA data is rendered.
type Format string

const (
	// FormatTable is the default, compact human table.
	FormatTable Format = "table"
	// FormatWide is the table plus extra columns (id, age, public key).
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

// RenderCAs writes a list of CAs in the requested format.
func RenderCAs(w io.Writer, cas []CA, f Format) error {
	if f.Structured() {
		return encode(w, f, cas)
	}
	if len(cas) == 0 {
		_, err := fmt.Fprintln(w, "No certificate authorities configured.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if f == FormatWide {
		fmt.Fprintln(tw, "KEY ID\tID\tSTATUS\tIN BUNDLE\tISSUED\tGEN\tFINGERPRINT\tCREATED\tLAST USED")
		for _, c := range cas {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n",
				c.KeyID, c.ID, c.Status, yesNo(c.InCurrentBundle), c.IssuedCertificates,
				c.BundleGeneration, shortFingerprint(c.Fingerprint), c.CreatedAt, orNever(c.LastUsedAt))
		}
	} else {
		fmt.Fprintln(tw, "KEY ID\tSTATUS\tIN BUNDLE\tISSUED\tFINGERPRINT\tLAST USED")
		for _, c := range cas {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
				c.KeyID, c.Status, yesNo(c.InCurrentBundle), c.IssuedCertificates,
				shortFingerprint(c.Fingerprint), orNever(c.LastUsedAt))
		}
	}
	return tw.Flush()
}

// RenderCA writes a single CA's detail in the requested format.
func RenderCA(w io.Writer, c CA, f Format) error {
	if f.Structured() {
		return encode(w, f, c)
	}
	p := func(k, v string) { fmt.Fprintf(w, "  %-20s %s\n", k+":", v) }
	fmt.Fprintf(w, "CA %s\n", c.KeyID)
	p("id", c.ID)
	p("status", c.Status)
	p("in current bundle", yesNo(c.InCurrentBundle))
	p("fingerprint", c.Fingerprint)
	p("issued certificates", strconv.FormatInt(c.IssuedCertificates, 10))
	p("bundle generation", strconv.FormatInt(c.BundleGeneration, 10))
	p("created at", c.CreatedAt)
	p("enabled at", orDash(c.EnabledAt))
	p("disabled at", orDash(c.DisabledAt))
	p("last used at", orNever(c.LastUsedAt))
	if len(c.ActivationHistory) > 0 {
		fmt.Fprintln(w, "  activation history:")
		for _, e := range c.ActivationHistory {
			gen := ""
			if e.Generation != nil {
				gen = fmt.Sprintf(" (generation %d)", *e.Generation)
			}
			fmt.Fprintf(w, "    %-10s %s%s\n", e.Event, e.At, gen)
		}
	}
	fmt.Fprintln(w, "  public key:")
	fmt.Fprintf(w, "    %s\n", c.PublicKey)
	return nil
}

// RenderStats writes aggregate signing statistics in the requested format.
func RenderStats(w io.Writer, s Stats, f Format) error {
	if f.Structured() {
		return encode(w, f, s)
	}
	p := func(k, v string) { fmt.Fprintf(w, "  %-24s %s\n", k+":", v) }
	fmt.Fprintln(w, "CA statistics")
	p("total cas", strconv.FormatInt(s.TotalCAs, 10))
	p("enabled / disabled", fmt.Sprintf("%d / %d", s.EnabledCAs, s.DisabledCAs))
	p("total issued certs", strconv.FormatInt(s.TotalIssuedCertificates, 10))
	p("generation", strconv.FormatInt(s.Generation, 10))
	p("bundle fingerprint", s.BundleFingerprint)
	if len(s.PerCA) > 0 {
		fmt.Fprintln(w, "  per-ca:")
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "    KEY ID\tENABLED\tISSUED\tLAST USED")
		for _, u := range s.PerCA {
			fmt.Fprintf(tw, "    %s\t%s\t%d\t%s\n", u.KeyID, yesNo(u.Enabled), u.IssuedCertificates, orNever(u.LastUsedAt))
		}
		return tw.Flush()
	}
	return nil
}

// RenderBundle writes the public trust bundle (active CAs) in the requested format.
func RenderBundle(w io.Writer, b PublicBundle, f Format) error {
	if f.Structured() {
		return encode(w, f, b)
	}
	fmt.Fprintf(w, "Active CA bundle (generation %d)\n", b.Generation)
	fmt.Fprintf(w, "  fingerprint: %s\n", b.Fingerprint)
	if len(b.Keys) == 0 {
		_, err := fmt.Fprintln(w, "  (no enabled CAs)")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "  KEY ID\tFINGERPRINT")
	for _, k := range b.Keys {
		fmt.Fprintf(tw, "  %s\t%s\n", k.KeyID, k.Fingerprint)
	}
	return tw.Flush()
}

// RenderPublicKey writes an exported public key in the requested format. In
// table/wide form it prints the raw OpenSSH key line (suitable for piping).
func RenderPublicKey(w io.Writer, k PublicKey, f Format) error {
	if f.Structured() {
		return encode(w, f, k)
	}
	_, err := fmt.Fprintln(w, k.PublicKey)
	return err
}

// RenderFingerprint writes just a fingerprint line (or the structured object).
func RenderFingerprint(w io.Writer, k PublicKey, f Format) error {
	if f.Structured() {
		return encode(w, f, k)
	}
	_, err := fmt.Fprintf(w, "%s  %s\n", k.Fingerprint, k.KeyID)
	return err
}

// RenderRollout writes the fleet rollout status in the requested format.
func RenderRollout(w io.Writer, r Rollout, f Format) error {
	if f.Structured() {
		return encode(w, f, r)
	}
	p := func(k, v string) { fmt.Fprintf(w, "  %-22s %s\n", k+":", v) }
	fmt.Fprintln(w, "CA rollout status")
	p("latest generation", strconv.FormatInt(r.LatestGeneration, 10))
	p("total machines", strconv.FormatInt(r.TotalMachines, 10))
	p("online", strconv.FormatInt(r.Online, 10))
	p("stale", strconv.FormatInt(r.Stale, 10))
	p("offline", strconv.FormatInt(r.Offline, 10))
	p("rollout", fmt.Sprintf("%.1f%%", r.RolloutPercentage))
	if len(r.Generations) > 0 {
		fmt.Fprintln(w, "  generations:")
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "    GENERATION\tMACHINES")
		for _, g := range r.Generations {
			fmt.Fprintf(tw, "    %d\t%d\n", g.Generation, g.Count)
		}
		return tw.Flush()
	}
	return nil
}

// RenderRotation writes the guided rotation result in the requested format.
func RenderRotation(w io.Writer, r RotationResult, f Format) error {
	if f.Structured() {
		return encode(w, f, r)
	}
	fmt.Fprintln(w, "Guided CA rotation")
	fmt.Fprintf(w, "  new active CA:   %s (%s)\n", r.NewCA.KeyID, r.NewCA.Fingerprint)
	if len(r.PreviousActive) > 0 {
		names := make([]string, 0, len(r.PreviousActive))
		for _, c := range r.PreviousActive {
			names = append(names, c.KeyID)
		}
		fmt.Fprintf(w, "  previous active: %s\n", strings.Join(names, ", "))
	} else {
		fmt.Fprintln(w, "  previous active: (none)")
	}
	behind := behindCount(r.Rollout)
	fmt.Fprintf(w, "  fleet rollout:   %.1f%% on generation %d (%d machine(s) behind)\n",
		r.Rollout.RolloutPercentage, r.Rollout.LatestGeneration, behind)
	if len(r.Warnings) > 0 {
		fmt.Fprintln(w, "\n  warnings:")
		for _, msg := range r.Warnings {
			fmt.Fprintf(w, "    ! %s\n", msg)
		}
	}
	fmt.Fprintln(w, "\nNext: watch `mayfly ca rollout`; once 100% converged, "+
		"`mayfly ca disable <old>` then `mayfly ca retire <old>`.")
	return nil
}

// RenderDelete writes the outcome of a delete in the requested format.
func RenderDelete(w io.Writer, r DeleteResult, f Format) error {
	if f.Structured() {
		return encode(w, f, r)
	}
	_, err := fmt.Fprintf(w, "Deleted CA %s (%s)\n", r.KeyID, r.ID)
	return err
}

// behindCount returns the number of machines not yet on the latest generation.
func behindCount(r Rollout) int64 {
	var onLatest int64
	for _, g := range r.Generations {
		if g.Generation == r.LatestGeneration {
			onLatest += g.Count
		}
	}
	behind := r.TotalMachines - onLatest
	if behind < 0 {
		return 0
	}
	return behind
}

func shortFingerprint(fp string) string {
	const max = 23 // "SHA256:" + 16 chars
	if len(fp) > max {
		return fp[:max] + "…"
	}
	return fp
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func orNever(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
