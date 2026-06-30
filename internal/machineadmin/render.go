package machineadmin

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// Format selects how machine data is rendered.
type Format string

const (
	// FormatTable is the default, compact human table.
	FormatTable Format = "table"
	// FormatWide is the table plus extra columns (ids, os/arch, ip, fingerprint).
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

// RenderMachines writes a list of machines in the requested format.
func RenderMachines(w io.Writer, machines []Machine, f Format) error {
	if f.Structured() {
		return encode(w, f, machines)
	}
	if len(machines) == 0 {
		_, err := fmt.Fprintln(w, "No machines enrolled.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if f == FormatWide {
		fmt.Fprintln(tw, "HOSTNAME\tMACHINE ID\tSTATUS\tLIVENESS\tGEN\tSYNCED\tUP-TO-DATE\tOS/ARCH\tAGENT\tIP\tFINGERPRINT\tLAST SEEN")
		for _, m := range machines {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				m.Hostname, m.MachineID, m.Status, m.Liveness, m.CurrentGeneration,
				syncedCol(m), yesNo(m.UpToDate), m.OS+"/"+m.Arch, m.AgentVersion,
				orDash(m.IP), shortFingerprint(m.Fingerprint), orNever(m.LastSeen))
		}
	} else {
		fmt.Fprintln(tw, "HOSTNAME\tSTATUS\tLIVENESS\tGEN\tSYNCED\tUP-TO-DATE\tAGENT\tLAST SEEN")
		for _, m := range machines {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
				m.Hostname, m.Status, m.Liveness, m.CurrentGeneration,
				syncedCol(m), yesNo(m.UpToDate), m.AgentVersion, orNever(m.LastSeen))
		}
	}
	return tw.Flush()
}

// RenderMachine writes a single machine's detail in the requested format.
func RenderMachine(w io.Writer, m Machine, f Format) error {
	if f.Structured() {
		return encode(w, f, m)
	}
	p := func(k, v string) { fmt.Fprintf(w, "  %-20s %s\n", k+":", v) }
	fmt.Fprintf(w, "Machine %s\n", m.Hostname)
	p("machine id", m.MachineID)
	p("status", m.Status)
	p("liveness", m.Liveness)
	p("fingerprint", m.Fingerprint)
	p("os/arch", m.OS+"/"+m.Arch)
	p("agent version", m.AgentVersion)
	p("ip", orDash(m.IP))
	p("current generation", strconv.FormatInt(m.CurrentGeneration, 10))
	p("synced generation", syncedCol(m))
	p("up to date", yesNo(m.UpToDate))
	p("bundle fingerprint", shortFingerprint(orDash(m.BundleFingerprint)))
	p("last seen", orNever(m.LastSeen))
	p("last sync", orNever(m.LastSync))
	p("enrolled at", m.EnrolledAt)
	return nil
}

// RenderFleet writes the fleet summary in the requested format.
func RenderFleet(w io.Writer, fleet Fleet, f Format) error {
	if f.Structured() {
		return encode(w, f, fleet)
	}
	p := func(k, v string) { fmt.Fprintf(w, "  %-22s %s\n", k+":", v) }
	fmt.Fprintln(w, "Fleet status")
	p("latest generation", strconv.FormatInt(fleet.LatestGeneration, 10))
	p("total machines", strconv.FormatInt(fleet.TotalMachines, 10))
	p("online", strconv.FormatInt(fleet.Online, 10))
	p("stale", strconv.FormatInt(fleet.Stale, 10))
	p("offline", strconv.FormatInt(fleet.Offline, 10))
	p("rollout", fmt.Sprintf("%.1f%%", fleet.RolloutPercentage))
	if len(fleet.Generations) > 0 {
		fmt.Fprintln(w, "  generations:")
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "    GENERATION\tMACHINES")
		for _, g := range fleet.Generations {
			fmt.Fprintf(tw, "    %d\t%d\n", g.Generation, g.Count)
		}
		return tw.Flush()
	}
	return nil
}

// RenderDelete writes the outcome of a delete in the requested format.
func RenderDelete(w io.Writer, r DeleteResult, f Format) error {
	if f.Structured() {
		return encode(w, f, r)
	}
	_, err := fmt.Fprintf(w, "Deleted machine %s (%s)\n", r.Hostname, r.MachineID)
	return err
}

// RenderToken writes a freshly minted enrollment token in the requested format.
// The plaintext token is shown exactly once.
func RenderToken(w io.Writer, action string, t EnrollmentToken, f Format) error {
	if f.Structured() {
		return encode(w, f, t)
	}
	fmt.Fprintf(w, "%s: a new single-use enrollment token was issued.\n", action)
	fmt.Fprintf(w, "  token:       %s\n", t.Token)
	fmt.Fprintf(w, "  token id:    %s\n", t.ID)
	fmt.Fprintf(w, "  expires at:  %s\n", t.ExpiresAt)
	fmt.Fprintln(w, "\nRe-provision the host with this token; it generates a fresh identity on enroll.")
	return nil
}

func syncedCol(m Machine) string {
	synced := "-"
	if m.SyncedGeneration != nil {
		synced = strconv.FormatInt(*m.SyncedGeneration, 10)
	}
	if m.LatestGeneration != nil {
		return synced + "/" + strconv.FormatInt(*m.LatestGeneration, 10)
	}
	return synced
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
