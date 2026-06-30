package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/mayfly-ssh/mayfly-cli/internal/account"
	"github.com/mayfly-ssh/mayfly-cli/internal/authflow"
	"github.com/mayfly-ssh/mayfly-cli/internal/certs"
	"github.com/mayfly-ssh/mayfly-cli/internal/performance"
	"github.com/mayfly-ssh/mayfly-cli/internal/ssh"
)

const sshUsage = `Usage: mayfly ssh [mayfly flags] [ssh options] [user@]host [command]

Connect to a host using a Mayfly-issued SSH certificate. The CLI authenticates,
reuses or renews a certificate as needed, then launches the system ssh client.
All OpenSSH options (-v, -p, -i, -J, -o, -L, -R, -D, -A, -F, ...) are passed
through unchanged.

Mayfly flags:
  --profile <name>   configuration profile to use
  --server <url>     Mayfly server URL
  --ttl <seconds>    requested certificate lifetime (server clamps 60–3600)
  --no-cache         force a fresh certificate even if a valid one is cached
  --dev              print developer timing diagnostics
  --dry-run          print the resolved ssh command without connecting
`

func newSSHCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "ssh [ssh options] [user@]host [command]",
		Short:              "Connect to a host using a Mayfly-issued certificate",
		Long:               "Authenticate, obtain/reuse a short-lived SSH certificate, and launch the system ssh client with full OpenSSH option passthrough.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())

			parsed, err := ssh.ParseArgs(args)
			if err != nil {
				return err
			}
			if parsed.Help {
				fmt.Fprint(cmd.OutOrStdout(), sshUsage)
				return nil
			}
			if parsed.Target == "" {
				fmt.Fprint(cmd.ErrOrStderr(), sshUsage)
				return fmt.Errorf("a target host is required")
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			acct, err := app.ensureAccount(ctx, cmd)
			if err != nil {
				return err
			}
			provider, err := app.provider(acct.Provider)
			if err != nil {
				return err
			}
			api, err := app.apiClient(app.activeTokenSource(acct, provider))
			if err != nil {
				return err
			}

			ttl := app.Config.CertLifetimeSec
			if parsed.HasTTL {
				ttl = parsed.TTL
			}
			res, err := app.certManager().Ensure(ctx, api, certs.EnsureOptions{
				Identity:       app.identityFor(acct),
				Hostname:       parsed.Host,
				TTLSeconds:     ttl,
				RenewThreshold: app.renewThreshold(),
				ForceRenew:     parsed.NoCache,
			})
			if err != nil {
				return err
			}
			_ = app.Accounts.Touch(acct.ID())

			sshArgs := app.buildSSHArgs(parsed, res)

			bin, err := ssh.BinaryPath()
			if err != nil {
				return fmt.Errorf("system ssh client not found: %w", err)
			}

			if parsed.DryRun {
				fmt.Fprintln(cmd.OutOrStdout(), ssh.RenderCommand(bin, sshArgs))
				return nil
			}

			if isVerbose(parsed.Options) {
				app.printSSHDiagnostics(cmd, acct, res, bin, sshArgs)
			}

			var runErr error
			_ = app.Profiler.Measure(performance.PhaseConnection, func() error {
				runErr = ssh.Exec(ctx, bin, sshArgs)
				return nil
			})
			var ee *ssh.ExitError
			if errors.As(runErr, &ee) {
				// The ssh client ran; propagate its exit code without treating it
				// as a CLI error (so dev-mode timing still prints).
				exitCode = ee.Code
				return nil
			}
			return runErr
		},
	}
}

// buildSSHArgs assembles the OpenSSH argument vector: configured default options,
// the user's passthrough options, Mayfly's injected identity + certificate, an
// optional preferred login user, then the target and any remote command.
func (a *App) buildSSHArgs(p *ssh.Parsed, res *certs.Result) []string {
	var args []string
	for _, opt := range a.Config.DefaultSSHOptions {
		args = append(args, "-o", opt)
	}
	args = append(args, p.Options...)
	args = append(args,
		"-i", res.KeyPath,
		"-o", "CertificateFile="+res.CertPath,
		"-o", "IdentitiesOnly=yes",
	)
	if p.User == "" && a.Config.PreferredUsername != "" {
		args = append(args, "-l", a.Config.PreferredUsername)
	}
	args = append(args, p.Target)
	args = append(args, p.Command...)
	return args
}

// ensureAccount returns the active account, transparently logging in via the
// default provider's device flow when no account exists and the session is
// interactive.
func (a *App) ensureAccount(ctx context.Context, cmd *cobra.Command) (account.Account, error) {
	if acct, ok := a.Accounts.Active(a.ProfileName); ok {
		return acct, nil
	}
	if !a.Context.Platform.Interactive {
		return account.Account{}, fmt.Errorf("not logged in (profile %q); run 'mayfly login'", a.ProfileName)
	}
	provider, err := a.provider("")
	if err != nil {
		return account.Account{}, err
	}
	acct, err := authflow.Login(ctx, authflow.Options{
		Provider:    provider,
		Tokens:      a.tokenStore(),
		Accounts:    a.Accounts,
		Profile:     a.ProfileName,
		Server:      a.Config.ServerURL,
		Profiler:    a.Profiler,
		Out:         cmd.OutOrStdout(),
		OpenBrowser: true,
		MaxAttempts: 2,
	})
	if err != nil {
		return account.Account{}, err
	}
	return *acct, nil
}

func (a *App) printSSHDiagnostics(cmd *cobra.Command, acct account.Account, res *certs.Result, bin string, args []string) {
	w := cmd.ErrOrStderr()
	fmt.Fprintln(w, "mayfly: certificate ready")
	fmt.Fprintf(w, "mayfly:   account=%s action=%s\n", acct.Display(), res.Action)
	fmt.Fprintf(w, "mayfly:   principal=%s serial=%d expires_in=%s\n", res.Entry.Principal, res.Entry.Serial, remainingString(res.Entry.Expiry))
	fmt.Fprintf(w, "mayfly:   exec: %s\n", ssh.RenderCommand(bin, args))
	fmt.Fprintln(w, "mayfly: handing off to OpenSSH")
}

func isVerbose(opts []string) bool {
	for _, o := range opts {
		switch o {
		case "-v", "-vv", "-vvv":
			return true
		}
	}
	return false
}
