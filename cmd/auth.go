package cmd

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/mayfly-ssh/mayfly-cli/internal/account"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth"
)

func newAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication: status, providers, accounts",
	}
	cmd.AddCommand(
		newAuthStatusCommand(),
		newAuthProvidersCommand(),
		newAuthAccountsCommand(),
		newAuthUseCommand(),
		newAuthRemoveCommand(),
		newAuthRenameCommand(),
	)
	return cmd
}

// ---- auth status ----

type authStatusReport struct {
	Authenticated     bool       `json:"authenticated"`
	Account           string     `json:"account,omitempty"`
	Provider          string     `json:"provider,omitempty"`
	Server            string     `json:"server"`
	Profile           string     `json:"profile"`
	TokenValid        bool       `json:"token_valid"`
	TokenExpired      bool       `json:"token_expired"`
	RefreshAvailable  bool       `json:"refresh_available"`
	CredentialBackend string     `json:"credential_backend"`
	ServerReachable   bool       `json:"server_reachable"`
	ServerVersion     string     `json:"server_version,omitempty"`
	ClockDriftMs      *int64     `json:"clock_drift_ms,omitempty"`
	RequestLatencyMs  *int64     `json:"request_latency_ms,omitempty"`
	LastLogin         *time.Time `json:"last_login,omitempty"`
}

func newAuthStatusCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show authentication status, token validity, and server reachability",
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			rep := authStatusReport{
				Server:            app.Config.ServerURL,
				Profile:           app.ProfileName,
				CredentialBackend: app.Creds.Name(),
			}

			if acct, err := app.requireActiveAccount(); err == nil {
				rep.Authenticated = true
				rep.Account = acct.Display()
				rep.Provider = acct.Provider
				ll := acct.LastUsedAt
				if !ll.IsZero() {
					rep.LastLogin = &ll
				}
				if provider, perr := app.provider(acct.Provider); perr == nil {
					if tok, terr := app.loadToken(ctx, acct, provider); terr == nil {
						rep.TokenExpired = tok.Expired()
						rep.TokenValid = !tok.Expired()
						rep.RefreshAvailable = tok.RefreshToken != "" && isRefreshable(provider)
					}
				}
			}

			if info, meta, serr := app.fetchServerInfo(ctx); serr == nil {
				rep.ServerReachable = true
				rep.ServerVersion = info.Version
				if meta != nil {
					lat := meta.Latency.Milliseconds()
					rep.RequestLatencyMs = &lat
					if !meta.Date.IsZero() {
						drift := meta.Date.Sub(time.Now().Add(-meta.Latency / 2)).Milliseconds()
						rep.ClockDriftMs = &drift
					}
				}
			}

			if asJSON {
				return printJSON(out, rep)
			}
			writeAuthStatusText(out, rep)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func writeAuthStatusText(out io.Writer, r authStatusReport) {
	p := func(format string, a ...any) { fmt.Fprintf(out, format, a...) }
	p("authenticated:    %s\n", yesNo(r.Authenticated))
	if r.Authenticated {
		p("account:          %s\n", r.Account)
		p("provider:         %s\n", r.Provider)
		p("token valid:      %s\n", yesNo(r.TokenValid))
		p("refresh:          %s\n", yesNo(r.RefreshAvailable))
		if r.LastLogin != nil {
			p("last login:       %s\n", r.LastLogin.Format(time.RFC3339))
		}
	}
	p("profile:          %s\n", r.Profile)
	p("server:           %s\n", orDash(r.Server))
	p("credential store: %s\n", r.CredentialBackend)
	p("server reachable: %s\n", yesNo(r.ServerReachable))
	if r.ServerReachable {
		p("server version:   %s\n", orDash(r.ServerVersion))
		if r.RequestLatencyMs != nil {
			p("request latency:  %d ms\n", *r.RequestLatencyMs)
		}
		if r.ClockDriftMs != nil {
			p("clock drift:      %d ms\n", *r.ClockDriftMs)
		}
	}
}

// ---- auth providers ----

type providerReport struct {
	ID           string             `json:"id"`
	DisplayName  string             `json:"display_name"`
	Kind         string             `json:"kind"`
	Configured   bool               `json:"configured"`
	Enabled      bool               `json:"enabled"`
	Default      bool               `json:"default"`
	Capabilities oauth.Capabilities `json:"capabilities"`
}

func newAuthProvidersCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "providers",
		Short: "List configured identity providers and their capabilities",
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			out := cmd.OutOrStdout()
			def := app.ProviderID()

			var reports []providerReport
			for _, meta := range app.Providers.List() {
				p, ok := app.Providers.Get(meta.ID)
				if !ok {
					continue
				}
				reports = append(reports, providerReport{
					ID:           meta.ID,
					DisplayName:  meta.DisplayName,
					Kind:         string(meta.Kind),
					Configured:   oauth.IsConfigured(p),
					Enabled:      true,
					Default:      meta.ID == def,
					Capabilities: oauth.CapabilitiesOf(p),
				})
			}

			if asJSON {
				return printJSON(out, reports)
			}
			for _, r := range reports {
				marker := " "
				if r.Default {
					marker = "*"
				}
				fmt.Fprintf(out, "%s %s (%s)\n", marker, r.ID, r.DisplayName)
				fmt.Fprintf(out, "    kind:         %s\n", r.Kind)
				fmt.Fprintf(out, "    configured:   %s   enabled: %s   default: %s\n",
					yesNo(r.Configured), yesNo(r.Enabled), yesNo(r.Default))
				fmt.Fprintf(out, "    capabilities: device-flow=%s browser-flow=%s refresh=%s oidc-discovery=%s\n",
					yesNo(r.Capabilities.DeviceFlow), yesNo(r.Capabilities.BrowserFlow),
					yesNo(r.Capabilities.Refresh), yesNo(r.Capabilities.OIDCDiscovery))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

// ---- auth accounts ----

type accountReport struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	Username  string    `json:"username"`
	Display   string    `json:"display"`
	Email     string    `json:"email,omitempty"`
	Server    string    `json:"server"`
	Profile   string    `json:"profile"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

func newAuthAccountsCommand() *cobra.Command {
	var asJSON bool
	var allProfiles bool
	cmd := &cobra.Command{
		Use:   "accounts",
		Short: "List known accounts and the active one",
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			out := cmd.OutOrStdout()

			scope := app.ProfileName
			var accounts []accountReportSource
			if allProfiles {
				for _, a := range app.Accounts.List() {
					accounts = append(accounts, accountReportSource{a, app.activeID(a.Profile)})
				}
			} else {
				active := app.activeID(scope)
				for _, a := range app.Accounts.ListByProfile(scope) {
					accounts = append(accounts, accountReportSource{a, active})
				}
			}

			var reports []accountReport
			for _, s := range accounts {
				reports = append(reports, accountReport{
					ID:        s.acct.ID(),
					Provider:  s.acct.Provider,
					Username:  s.acct.Username,
					Display:   s.acct.Display(),
					Email:     s.acct.Email,
					Server:    s.acct.Server,
					Profile:   s.acct.Profile,
					Active:    s.acct.ID() == s.activeID,
					CreatedAt: s.acct.CreatedAt,
				})
			}

			if asJSON {
				return printJSON(out, reports)
			}
			if len(reports) == 0 {
				fmt.Fprintf(out, "No accounts (profile %q). Run 'mayfly login'.\n", scope)
				return nil
			}
			for _, r := range reports {
				marker := " "
				if r.Active {
					marker = "*"
				}
				fmt.Fprintf(out, "%s %-28s  %-10s  profile=%s\n", marker, r.Display, r.Provider, r.Profile)
			}
			fmt.Fprintln(out, "\n(* = active for its profile)")
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&allProfiles, "all-profiles", false, "list accounts across all profiles")
	return cmd
}

type accountReportSource struct {
	acct     account.Account
	activeID string
}

// ---- auth use / remove / rename ----

func newAuthUseCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use <account>",
		Short: "Switch the active account for the current profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			acct, err := app.Accounts.Find(app.ProfileName, args[0])
			if err != nil {
				return err
			}
			if err := app.Accounts.SetActive(app.ProfileName, acct.ID()); err != nil {
				return err
			}
			_ = app.Accounts.Touch(acct.ID())
			fmt.Fprintf(cmd.OutOrStdout(), "Active account is now %s\n", acct.Display())
			return nil
		},
	}
	return cmd
}

func newAuthRemoveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <account>",
		Short: "Remove an account and its stored credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			acct, err := app.Accounts.Find(app.ProfileName, args[0])
			if err != nil {
				return err
			}
			if err := app.tokenStore().Delete(acct.Provider, acct.CredentialAccount()); err != nil {
				return fmt.Errorf("removing credential: %w", err)
			}
			if _, err := app.Accounts.Remove(acct.ID()); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", acct.Display())
			return nil
		},
	}
	return cmd
}

func newAuthRenameCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename <account> <alias>",
		Short: "Set a display alias for an account",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			acct, err := app.Accounts.Find(app.ProfileName, args[0])
			if err != nil {
				return err
			}
			if err := app.Accounts.Rename(acct.ID(), args[1]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Renamed %s → %s/%s\n", acct.ID(), acct.Provider, args[1])
			return nil
		},
	}
	return cmd
}
