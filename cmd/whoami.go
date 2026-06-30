package cmd

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mayfly-ssh/mayfly-cli/internal/config"
	"github.com/mayfly-ssh/mayfly-cli/internal/hardware"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth"
)

type whoamiReport struct {
	Authenticated     bool                  `json:"authenticated"`
	Provider          string                `json:"provider"`
	Username          string                `json:"username"`
	Email             string                `json:"email,omitempty"`
	Name              string                `json:"name,omitempty"`
	Subject           string                `json:"subject,omitempty"`
	Organizations     []string              `json:"organizations,omitempty"`
	Groups            []string              `json:"groups,omitempty"`
	Roles             []string              `json:"roles,omitempty"`
	Permissions       []string              `json:"permissions,omitempty"`
	SessionAgeSeconds int64                 `json:"session_age_seconds"`
	TokenExpiry       *time.Time            `json:"token_expiry,omitempty"`
	TokenExpired      bool                  `json:"token_expired"`
	RefreshAvailable  bool                  `json:"refresh_available"`
	CLIVersion        string                `json:"cli_version"`
	ServerVersion     string                `json:"server_version,omitempty"`
	Server            string                `json:"server"`
	Profile           string                `json:"profile"`
	CredentialBackend string                `json:"credential_backend"`
	Hardware          hardware.Capabilities `json:"hardware"`
	MachineID         string                `json:"machine_id"`
	Timezone          string                `json:"timezone"`
	ConfigSources     map[string]string     `json:"config_sources"`
}

func newWhoamiCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show the active identity and session details",
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			rep := whoamiReport{
				CLIVersion:        app.Context.Version.Version,
				Server:            app.Config.ServerURL,
				Profile:           app.ProfileName,
				CredentialBackend: app.Creds.Name(),
				Hardware:          app.Context.Hardware,
				MachineID:         app.Context.MachineID,
				Timezone:          app.Context.Platform.Timezone,
				ConfigSources:     originsToStrings(app.Origins),
			}

			acct, err := app.requireActiveAccount()
			if err != nil {
				if asJSON {
					return printJSON(out, rep)
				}
				return err
			}

			rep.Authenticated = true
			rep.Provider = acct.Provider
			rep.Username = acct.Username
			rep.Email = acct.Email
			rep.Name = acct.Name
			rep.Subject = acct.Subject
			rep.SessionAgeSeconds = int64(time.Since(acct.CreatedAt).Seconds())

			if provider, perr := app.provider(acct.Provider); perr == nil {
				// Best-effort: refresh live identity and read token state. Failures
				// degrade gracefully to stored metadata.
				if tok, terr := app.loadToken(ctx, acct, provider); terr == nil {
					if !tok.Expiry.IsZero() {
						e := tok.Expiry
						rep.TokenExpiry = &e
					}
					rep.TokenExpired = tok.Expired()
					rep.RefreshAvailable = tok.RefreshToken != "" && isRefreshable(provider)
					if id, ierr := provider.FetchIdentity(ctx, tok); ierr == nil {
						rep.Username, rep.Email, rep.Name = id.Username, id.Email, id.Name
					}
				}
			}

			if info, _, serr := app.fetchServerInfo(ctx); serr == nil {
				rep.ServerVersion = info.Version
			}

			if asJSON {
				return printJSON(out, rep)
			}
			writeWhoamiText(out, rep)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func isRefreshable(p oauth.Provider) bool {
	_, ok := p.(oauth.RefreshableProvider)
	return ok
}

func originsToStrings(o config.Origins) map[string]string {
	out := make(map[string]string, len(o))
	for k, v := range o {
		out[k] = string(v)
	}
	return out
}

func writeWhoamiText(out io.Writer, r whoamiReport) {
	p := func(format string, a ...any) { fmt.Fprintf(out, format, a...) }
	if !r.Authenticated {
		p("Not logged in (profile %q).\n", r.Profile)
		return
	}
	p("Identity\n")
	p("  provider:        %s\n", r.Provider)
	p("  user:            %s\n", r.Username)
	p("  email:           %s\n", orDash(r.Email))
	p("  name:            %s\n", orDash(r.Name))
	p("  organizations:   %s\n", orDashList(r.Organizations))
	p("  groups:          %s\n", orDashList(r.Groups))
	p("  roles:           %s\n", orDashList(r.Roles))
	p("  permissions:     %s\n", orDashList(r.Permissions))
	p("Session\n")
	p("  age:             %s\n", time.Duration(r.SessionAgeSeconds*int64(time.Second)).String())
	if r.TokenExpiry != nil {
		p("  token expiry:    %s (%s)\n", r.TokenExpiry.Format(time.RFC3339), expiryState(r.TokenExpired))
	} else {
		p("  token expiry:    none\n")
	}
	p("  refresh:         %s\n", yesNo(r.RefreshAvailable))
	p("Environment\n")
	p("  cli version:     %s\n", r.CLIVersion)
	p("  server version:  %s\n", orDash(r.ServerVersion))
	p("  server:          %s\n", orDash(r.Server))
	p("  profile:         %s\n", r.Profile)
	p("  credential store:%s\n", " "+r.CredentialBackend)
	p("  machine id:      %s\n", r.MachineID)
	p("  timezone:        %s\n", r.Timezone)
	p("  hardware:        keychain=%t secret-service=%t tpm=%t secure-enclave=%t\n",
		r.Hardware.Keychain, r.Hardware.SecretService, r.Hardware.TPM, r.Hardware.SecureEnclave)
	p("  config sources:  server=%s provider=%s\n", r.ConfigSources["server_url"], r.ConfigSources["provider"])
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func orDashList(s []string) string {
	if len(s) == 0 {
		return "—"
	}
	return strings.Join(s, ", ")
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func expiryState(expired bool) string {
	if expired {
		return "EXPIRED"
	}
	return "valid"
}
