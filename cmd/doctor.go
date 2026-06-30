package cmd

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mayfly-ssh/mayfly-cli/internal/opsadmin"
)

// clockDriftWarn/Fail bound the tolerated difference between the client clock
// and the server's `Date` header. The server rejects signed requests beyond
// ±60s skew, so drift approaching that is a hard failure.
const (
	clockDriftWarn = 5 * time.Second
	clockDriftFail = 60 * time.Second
)

func newDoctorCommand() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:     "doctor",
		Aliases: []string{"diagnose"},
		Short:   "Diagnose connectivity, auth, CA, bundle, and fleet health (PASS/WARN/FAIL)",
		Long: "Run a suite of health checks against the local environment and the configured " +
			"Mayfly server — connectivity, TLS, certificate chain, clock drift, OAuth session, " +
			"provider availability, machine enrollment, CA consistency, bundle generation, helper " +
			"and agent status — each reported as PASS/WARN/FAIL with actionable guidance.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			if app == nil {
				return fmt.Errorf("internal: app not initialized")
			}
			format, err := opsadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			report := runDoctor(cmd.Context(), app)
			if rerr := opsadmin.RenderDoctor(cmd.OutOrStdout(), report, format); rerr != nil {
				return rerr
			}
			if report.Overall == opsadmin.CheckFail {
				return fmt.Errorf("doctor found failing checks")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table|wide|json|yaml")
	return cmd
}

// runDoctor performs all diagnostic checks and folds them into a report.
func runDoctor(ctx context.Context, app *App) opsadmin.DoctorReport {
	var checks []opsadmin.CheckResult
	add := func(name, status, detail, guidance string) {
		checks = append(checks, opsadmin.CheckResult{Name: name, Status: status, Detail: detail, Guidance: guidance})
	}

	// --- Connectivity + clock drift (unauthenticated /health) ---
	health, meta, herr := app.fetchServerInfo(ctx)
	if herr != nil {
		add("server connectivity", opsadmin.CheckFail,
			fmt.Sprintf("could not reach %s: %v", app.Config.ServerURL, herr),
			"check --server / MAYFLY_SERVER_URL and that the server is running")
	} else {
		add("server connectivity", opsadmin.CheckPass,
			fmt.Sprintf("%s reachable (%s, %s)", app.Config.ServerURL, health.Version, meta.Latency.Round(time.Millisecond)), "")
	}

	// --- TLS + certificate chain ---
	addTLSChecks(add, app.Config.ServerURL, herr == nil)

	// --- Clock drift ---
	if herr == nil && !meta.Date.IsZero() {
		drift := time.Since(meta.Date)
		abs := time.Duration(math.Abs(float64(drift)))
		switch {
		case abs >= clockDriftFail:
			add("clock drift", opsadmin.CheckFail,
				fmt.Sprintf("local clock differs from server by %s", abs.Round(time.Second)),
				"sync the clock (NTP); the server rejects requests beyond ±60s skew")
		case abs >= clockDriftWarn:
			add("clock drift", opsadmin.CheckWarn,
				fmt.Sprintf("local clock differs from server by %s", abs.Round(time.Second)),
				"consider enabling NTP time sync")
		default:
			add("clock drift", opsadmin.CheckPass, fmt.Sprintf("within %s of server", abs.Round(time.Millisecond)), "")
		}
	} else {
		add("clock drift", opsadmin.CheckSkip, "server time unavailable", "")
	}

	// --- OAuth session ---
	addSessionCheck(ctx, app, add)

	// --- Provider availability ---
	if providers := app.Providers.List(); len(providers) == 0 {
		add("provider availability", opsadmin.CheckFail, "no auth providers registered", "check the CLI build/config")
	} else if _, perr := app.provider(""); perr != nil {
		add("provider availability", opsadmin.CheckWarn, perr.Error(), "set --provider or a default provider")
	} else {
		ids := make([]string, 0, len(providers))
		for _, p := range providers {
			ids = append(ids, p.ID)
		}
		add("provider availability", opsadmin.CheckPass, strings.Join(ids, ", "), "")
	}

	// --- Server-side checks (require admin authorization) ---
	addServerChecks(ctx, app, add)

	// --- Helper status (local, best-effort) ---
	if path, err := exec.LookPath("mayfly-helper"); err == nil {
		add("helper status", opsadmin.CheckPass, path, "")
	} else {
		add("helper status", opsadmin.CheckSkip, "mayfly-helper not found on PATH",
			"install mayfly-helper if you use privileged SSH config management")
	}

	return opsadmin.DoctorReport{Overall: opsadmin.OverallStatus(checks), Checks: checks}
}

func addTLSChecks(add func(name, status, detail, guidance string), serverURL string, reachable bool) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme == "" {
		add("TLS", opsadmin.CheckWarn, "server URL not parseable", "set a valid https:// server URL")
		add("certificate chain", opsadmin.CheckSkip, "TLS not established", "")
		return
	}
	switch u.Scheme {
	case "https":
		add("TLS", opsadmin.CheckPass, "https endpoint", "")
		if reachable {
			add("certificate chain", opsadmin.CheckPass, "verified by system trust store", "")
		} else {
			add("certificate chain", opsadmin.CheckWarn, "could not complete TLS handshake", "see server connectivity")
		}
	default:
		add("TLS", opsadmin.CheckWarn, fmt.Sprintf("plaintext %s endpoint", u.Scheme),
			"use https:// in production (Mayfly is HTTPS-only by policy)")
		add("certificate chain", opsadmin.CheckSkip, "no TLS on a plaintext endpoint", "")
	}
}

func addSessionCheck(ctx context.Context, app *App, add func(name, status, detail, guidance string)) {
	acct, err := app.requireActiveAccount()
	if err != nil {
		add("oauth session", opsadmin.CheckWarn, "not logged in", "run 'mayfly login'")
		return
	}
	p, err := app.provider(acct.Provider)
	if err != nil {
		add("oauth session", opsadmin.CheckWarn, err.Error(), "run 'mayfly login'")
		return
	}
	tok, err := app.loadToken(ctx, acct, p)
	if err != nil {
		add("oauth session", opsadmin.CheckWarn, err.Error(), fmt.Sprintf("run 'mayfly login %s'", acct.Provider))
		return
	}
	detail := fmt.Sprintf("%s (%s)", acct.Subject, acct.Provider)
	if !tok.Expiry.IsZero() {
		detail += fmt.Sprintf(", expires %s", tok.Expiry.UTC().Format(time.RFC3339))
	}
	add("oauth session", opsadmin.CheckPass, detail, "")
}

func addServerChecks(ctx context.Context, app *App, add func(name, status, detail, guidance string)) {
	api, err := app.adminClient()
	if err != nil {
		add("machine enrollment", opsadmin.CheckWarn, "not logged in", "run 'mayfly login'")
		add("ca consistency", opsadmin.CheckWarn, "not logged in", "run 'mayfly login'")
		add("bundle generation", opsadmin.CheckWarn, "not logged in", "run 'mayfly login'")
		add("agent status", opsadmin.CheckWarn, "not logged in", "run 'mayfly login'")
		return
	}

	var status opsadmin.Status
	if serr := api.Do(ctx, "GET", "/api/v1/admin/status", nil, &status); serr != nil {
		warn := "ensure your account is authorized (server allowlist)"
		add("ca consistency", opsadmin.CheckWarn, serr.Error(), warn)
		add("bundle generation", opsadmin.CheckWarn, serr.Error(), warn)
	} else {
		addCAChecks(add, status)
	}

	var health opsadmin.Health
	if herr := api.Do(ctx, "GET", "/api/v1/admin/health", nil, &health); herr != nil {
		warn := "ensure your account is authorized (server allowlist)"
		add("machine enrollment", opsadmin.CheckWarn, herr.Error(), warn)
		add("agent status", opsadmin.CheckWarn, herr.Error(), warn)
		return
	}
	addFleetChecks(add, health)
}

func addCAChecks(add func(name, status, detail, guidance string), status opsadmin.Status) {
	if !status.CertificateAuthority.Configured {
		add("ca consistency", opsadmin.CheckFail, "no certificate authority configured",
			"configure a CA: 'mayfly ca create <key-id>'")
	} else if !status.Audit.Verified {
		add("ca consistency", opsadmin.CheckFail, "audit chain failed verification",
			"investigate possible audit tampering immediately")
	} else {
		add("ca consistency", opsadmin.CheckPass,
			fmt.Sprintf("%d CA(s), %d enabled, audit verified",
				status.CertificateAuthority.Total, status.CertificateAuthority.Enabled), "")
	}

	if !status.Bundle.Configured {
		add("bundle generation", opsadmin.CheckWarn, "bundle distribution not configured",
			"configure the bundle signing key so agents can sync")
	} else {
		gen := "?"
		if status.Bundle.Generation != nil {
			gen = fmt.Sprintf("%d", *status.Bundle.Generation)
		}
		add("bundle generation", opsadmin.CheckPass, "generation "+gen, "")
	}
}

func addFleetChecks(add func(name, status, detail, guidance string), health opsadmin.Health) {
	if health.Machines.Total == 0 {
		add("machine enrollment", opsadmin.CheckWarn, "no machines enrolled",
			"enroll hosts: 'mayfly machine' + agent enrollment")
	} else {
		add("machine enrollment", opsadmin.CheckPass,
			fmt.Sprintf("%d machine(s) enrolled", health.Machines.Total), "")
	}

	switch {
	case health.Machines.Total == 0:
		add("agent status", opsadmin.CheckSkip, "no agents to report", "")
	case health.Machines.Offline > 0:
		add("agent status", opsadmin.CheckWarn,
			fmt.Sprintf("%d offline / %d online", health.Machines.Offline, health.Machines.Online),
			"check offline hosts: 'mayfly machine list'")
	default:
		add("agent status", opsadmin.CheckPass,
			fmt.Sprintf("%d online, none offline", health.Machines.Online), "")
	}
}
