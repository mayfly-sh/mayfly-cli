package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/mayfly-ssh/mayfly-cli/internal/authflow"
	"github.com/mayfly-ssh/mayfly-cli/internal/performance"
)

func newLoginCommand() *cobra.Command {
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "login [provider]",
		Short: "Authenticate with an identity provider (default: configured provider)",
		Long: "Log in via the provider's device-authorization flow and securely store the " +
			"credential. With no argument the effective default provider is used; pass " +
			"'github' or 'keycloak' to choose explicitly.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())

			providerID := ""
			if len(args) == 1 {
				providerID = args[0]
			}
			provider, err := app.provider(providerID)
			if err != nil {
				return err
			}

			// Cancellable on Ctrl-C / SIGTERM so device-flow polling can be aborted.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			openBrowser := !noBrowser && app.Context.Platform.Interactive

			var acct any
			err = app.Profiler.Measure(performance.PhaseOAuth, func() error {
				a, lerr := authflow.Login(ctx, authflow.Options{
					Provider:    provider,
					Tokens:      app.tokenStore(),
					Accounts:    app.Accounts,
					Profile:     app.ProfileName,
					Server:      app.Config.ServerURL,
					Profiler:    app.Profiler,
					Out:         cmd.OutOrStdout(),
					OpenBrowser: openBrowser,
					MaxAttempts: 2,
				})
				acct = a
				return lerr
			})
			if err != nil {
				if errors.Is(err, authflow.ErrCancelled) {
					return fmt.Errorf("login cancelled")
				}
				return err
			}
			_ = acct
			return nil
		},
	}
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "do not attempt to open a browser; print the URL only")
	return cmd
}
