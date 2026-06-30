package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mayfly-ssh/mayfly-cli/internal/account"
)

func newLogoutCommand() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "logout [account]",
		Short: "Log out: remove stored credentials for an account",
		Long: "Removes the stored token and account entry. With no argument logs out the " +
			"active account for the current profile; pass an account selector to target a " +
			"specific one, or --all to log out every account in the profile.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			out := cmd.OutOrStdout()

			var targets []account.Account
			switch {
			case all:
				targets = app.Accounts.ListByProfile(app.ProfileName)
				if len(targets) == 0 {
					return fmt.Errorf("no accounts to log out in profile %q", app.ProfileName)
				}
			case len(args) == 1:
				acct, err := app.Accounts.Find(app.ProfileName, args[0])
				if err != nil {
					return err
				}
				targets = []account.Account{acct}
			default:
				acct, err := app.requireActiveAccount()
				if err != nil {
					return err
				}
				targets = []account.Account{acct}
			}

			for _, acct := range targets {
				if err := app.tokenStore().Delete(acct.Provider, acct.CredentialAccount()); err != nil {
					return fmt.Errorf("removing credential for %s: %w", acct.Display(), err)
				}
				if _, err := app.Accounts.Remove(acct.ID()); err != nil {
					return fmt.Errorf("removing account %s: %w", acct.Display(), err)
				}
				fmt.Fprintf(out, "Logged out %s\n", acct.Display())
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "log out all accounts in the current profile")
	return cmd
}
