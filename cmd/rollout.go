package cmd

import (
	"net/url"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/mayfly-ssh/mayfly-cli/internal/rolloutadmin"
)

// rolloutFlags holds the flags shared by the rollout subcommands.
type rolloutFlags struct {
	output   string
	watch    bool
	interval time.Duration
}

func addRolloutFlags(cmd *cobra.Command, f *rolloutFlags) {
	cmd.Flags().StringVarP(&f.output, "output", "o", "table", "output format: table|wide|json|yaml")
	cmd.Flags().BoolVarP(&f.watch, "watch", "w", false, "continuously refresh until interrupted")
	cmd.Flags().DurationVar(&f.interval, "interval", 2*time.Second, "refresh interval in --watch mode")
}

// newRolloutCommand assembles the `mayfly rollout` command group: the operator's
// complete console for observing and managing CA-bundle rollouts (013D).
func newRolloutCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rollout",
		Short: "Observe and manage CA-bundle rollouts across the fleet",
		Long: "The rollout console: track CA-bundle rollout progress, completion %, and ETA " +
			"across the fleet; drill into per-generation and per-machine state; find stuck " +
			"machines; score rollout health; and explain why a rollout is incomplete — all from " +
			"the CLI, no REST required.",
	}
	cmd.AddCommand(
		newRolloutStatusCommand(),
		newRolloutWatchCommand(),
		newRolloutSummaryCommand(),
		newRolloutGenerationsCommand(),
		newRolloutMachinesCommand(),
		newRolloutStuckCommand(),
		newRolloutHealthCommand(),
		newRolloutExplainCommand(),
		newRolloutTimelineCommand(),
		newRolloutHistoryCommand(),
	)
	return cmd
}

// fetchStatus is shared by status/watch/summary.
func renderStatus(cmd *cobra.Command, f *rolloutFlags, summary bool) error {
	app := FromContext(cmd.Context())
	format, err := rolloutadmin.ParseFormat(f.output)
	if err != nil {
		return err
	}
	api, err := app.adminClient()
	if err != nil {
		return err
	}
	render := func() error {
		var s rolloutadmin.Status
		if derr := api.Do(cmd.Context(), "GET", "/api/v1/admin/rollout", nil, &s); derr != nil {
			return derr
		}
		if summary {
			return rolloutadmin.RenderSummary(cmd.OutOrStdout(), s, format)
		}
		return rolloutadmin.RenderStatus(cmd.OutOrStdout(), s, format)
	}
	return runMaybeWatchOps(cmd, f.watch, f.interval, format.Structured(), render)
}

func newRolloutStatusCommand() *cobra.Command {
	f := &rolloutFlags{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show rollout progress, completion %, ETA, and health",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return renderStatus(cmd, f, false) },
	}
	addRolloutFlags(cmd, f)
	return cmd
}

func newRolloutWatchCommand() *cobra.Command {
	f := &rolloutFlags{}
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Live rollout dashboard (progress bar, %, ETA, breakdown)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f.watch = true
			return renderStatus(cmd, f, false)
		},
	}
	cmd.Flags().StringVarP(&f.output, "output", "o", "table", "output format: table|wide|json|yaml")
	cmd.Flags().DurationVar(&f.interval, "interval", 2*time.Second, "refresh interval")
	return cmd
}

func newRolloutSummaryCommand() *cobra.Command {
	f := &rolloutFlags{}
	cmd := &cobra.Command{
		Use:   "summary",
		Short: "Rich one-screen rollout summary with health reasons",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return renderStatus(cmd, f, true) },
	}
	addRolloutFlags(cmd, f)
	return cmd
}

func newRolloutGenerationsCommand() *cobra.Command {
	f := &rolloutFlags{}
	cmd := &cobra.Command{
		Use:   "generations",
		Short: "Show machine population per CA generation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := rolloutadmin.ParseFormat(f.output)
			if err != nil {
				return err
			}
			api, err := app.adminClient()
			if err != nil {
				return err
			}
			render := func() error {
				var g rolloutadmin.GenerationsResponse
				if derr := api.Do(cmd.Context(), "GET", "/api/v1/admin/rollout/generations", nil, &g); derr != nil {
					return derr
				}
				return rolloutadmin.RenderGenerations(cmd.OutOrStdout(), g, format)
			}
			return runMaybeWatchOps(cmd, f.watch, f.interval, format.Structured(), render)
		},
	}
	addRolloutFlags(cmd, f)
	return cmd
}

func newRolloutMachinesCommand() *cobra.Command {
	f := &rolloutFlags{}
	var (
		state      string
		generation int64
	)
	cmd := &cobra.Command{
		Use:   "machines",
		Short: "List machines and their rollout state (filterable)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := rolloutadmin.ParseFormat(f.output)
			if err != nil {
				return err
			}
			api, err := app.adminClient()
			if err != nil {
				return err
			}
			q := url.Values{}
			if state != "" {
				q.Set("state", state)
			}
			if generation >= 0 {
				q.Set("generation", strconv.FormatInt(generation, 10))
			}
			path := "/api/v1/admin/rollout/machines"
			if encoded := q.Encode(); encoded != "" {
				path += "?" + encoded
			}
			render := func() error {
				var m rolloutadmin.MachinesResponse
				if derr := api.Do(cmd.Context(), "GET", path, nil, &m); derr != nil {
					return derr
				}
				return rolloutadmin.RenderMachines(cmd.OutOrStdout(), m, format)
			}
			return runMaybeWatchOps(cmd, f.watch, f.interval, format.Structured(), render)
		},
	}
	addRolloutFlags(cmd, f)
	cmd.Flags().StringVar(&state, "state", "", "filter by rollout state: all|current|lagging|stuck")
	cmd.Flags().Int64Var(&generation, "generation", -1, "filter by synced generation")
	return cmd
}

func newRolloutStuckCommand() *cobra.Command {
	f := &rolloutFlags{}
	cmd := &cobra.Command{
		Use:   "stuck",
		Short: "Show machines that cannot make progress, with remediation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := rolloutadmin.ParseFormat(f.output)
			if err != nil {
				return err
			}
			api, err := app.adminClient()
			if err != nil {
				return err
			}
			render := func() error {
				var r rolloutadmin.StuckReport
				if derr := api.Do(cmd.Context(), "GET", "/api/v1/admin/rollout/stuck", nil, &r); derr != nil {
					return derr
				}
				return rolloutadmin.RenderStuck(cmd.OutOrStdout(), r, format)
			}
			return runMaybeWatchOps(cmd, f.watch, f.interval, format.Structured(), render)
		},
	}
	addRolloutFlags(cmd, f)
	return cmd
}

func newRolloutHealthCommand() *cobra.Command {
	f := &rolloutFlags{}
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Score rollout health (Healthy|Degraded|Blocked|Failed)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := rolloutadmin.ParseFormat(f.output)
			if err != nil {
				return err
			}
			api, err := app.adminClient()
			if err != nil {
				return err
			}
			render := func() error {
				var h rolloutadmin.Health
				if derr := api.Do(cmd.Context(), "GET", "/api/v1/admin/rollout/health", nil, &h); derr != nil {
					return derr
				}
				return rolloutadmin.RenderHealth(cmd.OutOrStdout(), h, format)
			}
			return runMaybeWatchOps(cmd, f.watch, f.interval, format.Structured(), render)
		},
	}
	addRolloutFlags(cmd, f)
	return cmd
}

func newRolloutExplainCommand() *cobra.Command {
	f := &rolloutFlags{}
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Explain why the rollout is incomplete, by category",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := rolloutadmin.ParseFormat(f.output)
			if err != nil {
				return err
			}
			api, err := app.adminClient()
			if err != nil {
				return err
			}
			render := func() error {
				var e rolloutadmin.Explanation
				if derr := api.Do(cmd.Context(), "GET", "/api/v1/admin/rollout/explain", nil, &e); derr != nil {
					return derr
				}
				return rolloutadmin.RenderExplain(cmd.OutOrStdout(), e, format)
			}
			return runMaybeWatchOps(cmd, f.watch, f.interval, format.Structured(), render)
		},
	}
	addRolloutFlags(cmd, f)
	return cmd
}

func newRolloutTimelineCommand() *cobra.Command {
	f := &rolloutFlags{}
	var limit int
	cmd := &cobra.Command{
		Use:   "timeline",
		Short: "Show recent bundle rollout events (apply/rollback/verify)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := rolloutadmin.ParseFormat(f.output)
			if err != nil {
				return err
			}
			api, err := app.adminClient()
			if err != nil {
				return err
			}
			q := url.Values{}
			if limit > 0 {
				q.Set("limit", strconv.Itoa(limit))
			}
			path := "/api/v1/admin/rollout/timeline"
			if encoded := q.Encode(); encoded != "" {
				path += "?" + encoded
			}
			render := func() error {
				var t rolloutadmin.Timeline
				if derr := api.Do(cmd.Context(), "GET", path, nil, &t); derr != nil {
					return derr
				}
				return rolloutadmin.RenderTimeline(cmd.OutOrStdout(), t, format)
			}
			return runMaybeWatchOps(cmd, f.watch, f.interval, format.Structured(), render)
		},
	}
	addRolloutFlags(cmd, f)
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum events to return (max 500)")
	return cmd
}

func newRolloutHistoryCommand() *cobra.Command {
	f := &rolloutFlags{}
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show generation adoption history across the fleet",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := rolloutadmin.ParseFormat(f.output)
			if err != nil {
				return err
			}
			api, err := app.adminClient()
			if err != nil {
				return err
			}
			render := func() error {
				var h rolloutadmin.History
				if derr := api.Do(cmd.Context(), "GET", "/api/v1/admin/rollout/history", nil, &h); derr != nil {
					return derr
				}
				return rolloutadmin.RenderHistory(cmd.OutOrStdout(), h, format)
			}
			return runMaybeWatchOps(cmd, f.watch, f.interval, format.Structured(), render)
		},
	}
	addRolloutFlags(cmd, f)
	return cmd
}
