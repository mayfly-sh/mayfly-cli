package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// newDiagnosticsCommand prints the assembled client foundation. It exercises
// every shared subsystem (config, context, hardware, providers, credentials)
// without performing authentication or SSH — useful for verifying an install
// and demonstrating the SDK. It is NOT a login or SSH command.
func newDiagnosticsCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "diagnostics",
		Short: "Show resolved client context, configuration, and capabilities",
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			if app == nil {
				return fmt.Errorf("internal: app not initialized")
			}

			report := map[string]any{
				"version":            app.Context.Version,
				"platform":           app.Context.Platform,
				"hardware":           app.Context.Hardware,
				"machine_id":         app.Context.MachineID,
				"session_id":         app.Context.SessionID,
				"credential_backend": app.Creds.Name(),
				"config":             app.Config,
				"config_origins":     app.Origins,
				"providers":          app.Providers.List(),
			}

			out := cmd.OutOrStdout()
			if asJSON {
				data, err := json.MarshalIndent(report, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(out, string(data))
				return nil
			}

			fmt.Fprintf(out, "Mayfly client diagnostics\n")
			fmt.Fprintf(out, "  cli:        %s %s\n", app.Context.Version.Name, app.Context.Version.Version)
			fmt.Fprintf(out, "  platform:   %s/%s (%s)\n", app.Context.Platform.OS, app.Context.Platform.Arch, app.Context.Platform.PlatformVersion)
			fmt.Fprintf(out, "  timezone:   %s (%s)\n", app.Context.Platform.Timezone, app.Context.Platform.UTCOffset)
			fmt.Fprintf(out, "  machine id: %s\n", app.Context.MachineID)
			fmt.Fprintf(out, "  session id: %s\n", app.Context.SessionID)
			fmt.Fprintf(out, "  storage:    %s\n", app.Creds.Name())
			fmt.Fprintf(out, "  ci:         %t  container: %t\n", app.Context.Platform.IsCI, app.Context.Platform.IsContainer)
			fmt.Fprintf(out, "  hardware:   keychain=%t secret-service=%t tpm=%t secure-enclave=%t\n",
				app.Context.Hardware.Keychain, app.Context.Hardware.SecretService,
				app.Context.Hardware.TPM, app.Context.Hardware.SecureEnclave)
			fmt.Fprintf(out, "  server:     %q (from %s)\n", app.Config.ServerURL, app.Origins["server_url"])
			fmt.Fprintf(out, "  provider:   %q (from %s)\n", app.Config.Provider, app.Origins["provider"])
			fmt.Fprintf(out, "  providers registered:\n")
			for _, p := range app.Providers.List() {
				fmt.Fprintf(out, "    - %s (%s, %s)\n", p.ID, p.DisplayName, p.Kind)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}
