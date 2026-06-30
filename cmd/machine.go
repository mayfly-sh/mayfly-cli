package cmd

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mayfly-ssh/mayfly-cli/internal/client"
	"github.com/mayfly-ssh/mayfly-cli/internal/machineadmin"
)

const machineAPIBase = "/api/v1/admin/machines"

// machineClient builds an authenticated API client for the active account. All
// machine administration endpoints require an authorized operator token.
func (a *App) machineClient() (*client.Client, error) {
	acct, err := a.requireActiveAccount()
	if err != nil {
		return nil, err
	}
	provider, err := a.provider(acct.Provider)
	if err != nil {
		return nil, err
	}
	return a.apiClient(a.activeTokenSource(acct, provider))
}

func newMachineCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "machine",
		Short: "Administer enrolled machines (the fleet control plane)",
		Long: "List, inspect, and manage the lifecycle of enrolled machines. " +
			"Every operation is authorized (deny-by-default) and audited server-side. " +
			"This is the primary operator interface — no manual REST calls are required.",
		Aliases: []string{"machines", "m"},
	}
	cmd.AddCommand(
		newMachineListCommand(),
		newMachineShowCommand(),
		newMachineStatusCommand(),
		newMachineLifecycleCommand("approve", "Approve a pending machine (pending → active)", "approve"),
		newMachineLifecycleCommand("disable", "Disable a machine (blocks it until re-enabled)", "disable"),
		newMachineLifecycleCommand("enable", "Re-enable a disabled machine", "enable"),
		newMachineLifecycleCommand("revoke", "Revoke a machine (permanently blocks it)", "revoke"),
		newMachineDeleteCommand(),
		newMachineReissueCommand("reenroll", "Revoke a machine and mint a fresh enrollment token", "reenroll"),
		newMachineReissueCommand("rotate-identity", "Rotate a machine's identity (revoke + new enrollment token)", "rotate-identity"),
		newMachineHeartbeatCommand(),
		newMachineSyncCommand(),
	)
	return cmd
}

// outputFlag registers and reads the shared -o/--output flag.
func addOutputFlag(cmd *cobra.Command, out *string) {
	cmd.Flags().StringVarP(out, "output", "o", "table", "output format: table|wide|json|yaml")
}

// addWatchFlags registers the shared --watch / --interval flags.
func addWatchFlags(cmd *cobra.Command, watch *bool, interval *time.Duration) {
	cmd.Flags().BoolVarP(watch, "watch", "w", false, "continuously refresh until interrupted")
	cmd.Flags().DurationVar(interval, "interval", 2*time.Second, "refresh interval in --watch mode")
}

func newMachineListCommand() *cobra.Command {
	var (
		output   string
		watch    bool
		interval time.Duration
		f        listFilters
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List enrolled machines (filterable)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := machineadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			query, err := f.query()
			if err != nil {
				return err
			}
			api, err := app.machineClient()
			if err != nil {
				return err
			}
			render := func() error {
				var machines []machineadmin.Machine
				if derr := api.Do(cmd.Context(), "GET", machineAPIBase+query, nil, &machines); derr != nil {
					return derr
				}
				return machineadmin.RenderMachines(cmd.OutOrStdout(), machines, format)
			}
			return runMaybeWatch(cmd, watch, interval, format, render)
		},
	}
	addOutputFlag(cmd, &output)
	addWatchFlags(cmd, &watch, &interval)
	f.register(cmd)
	return cmd
}

func newMachineShowCommand() *cobra.Command {
	var (
		output   string
		watch    bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "show <machine-id>",
		Short: "Show a machine's full detail",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := machineadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.machineClient()
			if err != nil {
				return err
			}
			render := func() error {
				var m machineadmin.Machine
				if derr := api.Do(cmd.Context(), "GET", machineAPIBase+"/"+url.PathEscape(args[0]), nil, &m); derr != nil {
					return derr
				}
				return machineadmin.RenderMachine(cmd.OutOrStdout(), m, format)
			}
			return runMaybeWatch(cmd, watch, interval, format, render)
		},
	}
	addOutputFlag(cmd, &output)
	addWatchFlags(cmd, &watch, &interval)
	return cmd
}

func newMachineStatusCommand() *cobra.Command {
	var (
		output   string
		watch    bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show fleet rollout status (generations, liveness, rollout %)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := machineadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.machineClient()
			if err != nil {
				return err
			}
			render := func() error {
				var fleet machineadmin.Fleet
				if derr := api.Do(cmd.Context(), "GET", "/api/v1/admin/bundle/status", nil, &fleet); derr != nil {
					return derr
				}
				return machineadmin.RenderFleet(cmd.OutOrStdout(), fleet, format)
			}
			return runMaybeWatch(cmd, watch, interval, format, render)
		},
	}
	addOutputFlag(cmd, &output)
	addWatchFlags(cmd, &watch, &interval)
	return cmd
}

// newMachineLifecycleCommand builds approve/disable/enable/revoke, which all
// POST to .../{id}/{action} and return the updated machine.
func newMachineLifecycleCommand(use, short, action string) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   use + " <machine-id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := machineadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.machineClient()
			if err != nil {
				return err
			}
			var m machineadmin.Machine
			path := fmt.Sprintf("%s/%s/%s", machineAPIBase, url.PathEscape(args[0]), action)
			if derr := api.Do(cmd.Context(), "POST", path, nil, &m); derr != nil {
				return derr
			}
			out := cmd.OutOrStdout()
			if !format.Structured() {
				fmt.Fprintf(out, "%s: %s is now %s.\n", action, m.Hostname, m.Status)
			}
			return machineadmin.RenderMachine(out, m, format)
		},
	}
	addOutputFlag(cmd, &output)
	return cmd
}

func newMachineDeleteCommand() *cobra.Command {
	var (
		output string
		yes    bool
	)
	cmd := &cobra.Command{
		Use:   "delete <machine-id>",
		Short: "Permanently delete a machine record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := machineadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			if !yes && !format.Structured() {
				return fmt.Errorf("refusing to delete %q without --yes (this is irreversible)", args[0])
			}
			api, err := app.machineClient()
			if err != nil {
				return err
			}
			var r machineadmin.DeleteResult
			if derr := api.Do(cmd.Context(), "DELETE", machineAPIBase+"/"+url.PathEscape(args[0]), nil, &r); derr != nil {
				return derr
			}
			return machineadmin.RenderDelete(cmd.OutOrStdout(), r, format)
		},
	}
	addOutputFlag(cmd, &output)
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the irreversible delete")
	return cmd
}

// newMachineReissueCommand builds reenroll/rotate-identity, which revoke the
// existing machine and return a fresh single-use enrollment token.
func newMachineReissueCommand(use, short, action string) *cobra.Command {
	var (
		output string
		yes    bool
	)
	cmd := &cobra.Command{
		Use:   use + " <machine-id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := machineadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			if !yes && !format.Structured() {
				return fmt.Errorf("refusing to %s %q without --yes (the old identity is destroyed)", action, args[0])
			}
			api, err := app.machineClient()
			if err != nil {
				return err
			}
			var t machineadmin.EnrollmentToken
			path := fmt.Sprintf("%s/%s/%s", machineAPIBase, url.PathEscape(args[0]), action)
			if derr := api.Do(cmd.Context(), "POST", path, nil, &t); derr != nil {
				return derr
			}
			return machineadmin.RenderToken(cmd.OutOrStdout(), action, t, format)
		},
	}
	addOutputFlag(cmd, &output)
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm: destroys the current identity")
	return cmd
}

// newMachineHeartbeatCommand shows (and optionally awaits) a machine's heartbeat
// liveness. Agents heartbeat on their own pull cadence; Mayfly cannot push, so
// this observes rather than forces (ADR-0022).
func newMachineHeartbeatCommand() *cobra.Command {
	var (
		output   string
		watch    bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "heartbeat <machine-id>",
		Short: "Show a machine's heartbeat/liveness (agents heartbeat on their own cadence)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := machineadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.machineClient()
			if err != nil {
				return err
			}
			render := func() error {
				var m machineadmin.Machine
				if derr := api.Do(cmd.Context(), "GET", machineAPIBase+"/"+url.PathEscape(args[0]), nil, &m); derr != nil {
					return derr
				}
				if format.Structured() {
					return machineadmin.RenderMachine(cmd.OutOrStdout(), m, format)
				}
				out := cmd.OutOrStdout()
				fmt.Fprintf(out, "  hostname:   %s\n", m.Hostname)
				fmt.Fprintf(out, "  liveness:   %s\n", m.Liveness)
				fmt.Fprintf(out, "  last seen:  %s\n", orNever(m.LastSeen))
				fmt.Fprintf(out, "  generation: %d\n", m.CurrentGeneration)
				return nil
			}
			return runMaybeWatch(cmd, watch, interval, format, render)
		},
	}
	addOutputFlag(cmd, &output)
	addWatchFlags(cmd, &watch, &interval)
	return cmd
}

// newMachineSyncCommand shows (and optionally awaits) a machine's CA-bundle sync
// convergence. Like heartbeat, this observes the pull-based agent, it does not
// push (ADR-0022).
func newMachineSyncCommand() *cobra.Command {
	var (
		output   string
		watch    bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "sync <machine-id>",
		Short: "Show a machine's CA-bundle sync convergence (agents sync on their own cadence)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := machineadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.machineClient()
			if err != nil {
				return err
			}
			render := func() error {
				var m machineadmin.Machine
				if derr := api.Do(cmd.Context(), "GET", machineAPIBase+"/"+url.PathEscape(args[0]), nil, &m); derr != nil {
					return derr
				}
				if format.Structured() {
					return machineadmin.RenderMachine(cmd.OutOrStdout(), m, format)
				}
				out := cmd.OutOrStdout()
				fmt.Fprintf(out, "  hostname:    %s\n", m.Hostname)
				fmt.Fprintf(out, "  synced:      %s\n", syncedDisplay(m))
				fmt.Fprintf(out, "  up to date:  %s\n", yesNoStr(m.UpToDate))
				fmt.Fprintf(out, "  last sync:   %s\n", orNever(m.LastSync))
				return nil
			}
			return runMaybeWatch(cmd, watch, interval, format, render)
		},
	}
	addOutputFlag(cmd, &output)
	addWatchFlags(cmd, &watch, &interval)
	return cmd
}

// runMaybeWatch renders once, or repeatedly when watch is set. Watch mode is
// disabled for structured output (json/yaml) where a single document is wanted.
func runMaybeWatch(cmd *cobra.Command, watch bool, interval time.Duration, format machineadmin.Format, render func() error) error {
	if !watch || format.Structured() {
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

// listFilters holds the `machine list` filter flags.
type listFilters struct {
	status       string
	liveness     string
	online       bool
	offline      bool
	stale        bool
	hostname     string
	generation   int64
	os           string
	arch         string
	agentVersion string
}

func (f *listFilters) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.status, "status", "", "filter by status: pending|active|disabled|revoked")
	fl.StringVar(&f.liveness, "liveness", "", "filter by liveness: online|stale|offline")
	fl.BoolVar(&f.online, "online", false, "only online machines")
	fl.BoolVar(&f.offline, "offline", false, "only offline machines")
	fl.BoolVar(&f.stale, "stale", false, "only stale machines")
	fl.StringVar(&f.hostname, "hostname", "", "filter by hostname substring")
	fl.Int64Var(&f.generation, "generation", -1, "filter by current/synced generation")
	fl.StringVar(&f.os, "os", "", "filter by operating system")
	fl.StringVar(&f.arch, "arch", "", "filter by architecture")
	fl.StringVar(&f.agentVersion, "agent-version", "", "filter by agent version")
}

// query builds the server query string from the filter flags, validating that
// the liveness shortcuts are not mutually contradictory.
func (f *listFilters) query() (string, error) {
	liveness := strings.ToLower(strings.TrimSpace(f.liveness))
	count := 0
	for _, b := range []bool{f.online, f.offline, f.stale} {
		if b {
			count++
		}
	}
	if count > 1 || (count == 1 && liveness != "") {
		return "", fmt.Errorf("choose only one of --online/--offline/--stale/--liveness")
	}
	switch {
	case f.online:
		liveness = "online"
	case f.offline:
		liveness = "offline"
	case f.stale:
		liveness = "stale"
	}

	q := url.Values{}
	add := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			q.Set(k, v)
		}
	}
	add("status", f.status)
	add("liveness", liveness)
	add("hostname", f.hostname)
	add("os", f.os)
	add("arch", f.arch)
	add("agent_version", f.agentVersion)
	if f.generation >= 0 {
		q.Set("generation", strconv.FormatInt(f.generation, 10))
	}
	if len(q) == 0 {
		return "", nil
	}
	return "?" + q.Encode(), nil
}

func orNever(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

func yesNoStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func syncedDisplay(m machineadmin.Machine) string {
	synced := "-"
	if m.SyncedGeneration != nil {
		synced = strconv.FormatInt(*m.SyncedGeneration, 10)
	}
	if m.LatestGeneration != nil {
		return synced + "/" + strconv.FormatInt(*m.LatestGeneration, 10)
	}
	return synced
}
