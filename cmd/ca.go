package cmd

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mayfly-ssh/mayfly-cli/internal/caadmin"
	"github.com/mayfly-ssh/mayfly-cli/internal/client"
)

const caAPIBase = "/api/v1/admin/ca"

// caPassphraseEnv is consulted when --passphrase is not given, so the secret
// never has to appear in shell history.
const caPassphraseEnv = "MAYFLY_CA_PASSPHRASE"

// caClient builds an authenticated API client for the active account. All CA
// administration endpoints require an authorized operator token.
func (a *App) caClient() (*client.Client, error) {
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

func newCACommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Administer SSH Certificate Authorities (the signing control plane)",
		Long: "Create, inspect, rotate, and retire the SSH User CAs Mayfly signs with. " +
			"Every mutation is authorized (deny-by-default) and audited server-side. " +
			"This is the only interface an operator needs — no manual REST calls are required.",
		Aliases: []string{"certificate-authority", "authorities"},
	}
	cmd.AddCommand(
		newCAListCommand(),
		newCAShowCommand(),
		newCACreateCommand(),
		newCAImportCommand(),
		newCAExportCommand(),
		newCARotateCommand(),
		newCALifecycleCommand("enable", "Enable a CA (adds it to the signing set + bundle)"),
		newCALifecycleCommand("disable", "Disable a CA (removes it from the signing set + bundle)"),
		newCARetireCommand(),
		newCADeleteCommand(),
		newCAStatsCommand(),
		newCARolloutCommand(),
		newCACurrentCommand(),
		newCAPublicKeyCommand(),
		newCAFingerprintCommand(),
	)
	return cmd
}

// caPassphrase resolves the storage passphrase from the flag or the env var.
func caPassphrase(flag string) (string, error) {
	if strings.TrimSpace(flag) != "" {
		return flag, nil
	}
	if v := os.Getenv(caPassphraseEnv); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("a passphrase is required: pass --passphrase or set %s", caPassphraseEnv)
}

func newCAListCommand() *cobra.Command {
	var (
		output   string
		watch    bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List certificate authorities",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			render := func() error {
				var cas []caadmin.CA
				if derr := api.Do(cmd.Context(), "GET", caAPIBase, nil, &cas); derr != nil {
					return derr
				}
				return caadmin.RenderCAs(cmd.OutOrStdout(), cas, format)
			}
			return runMaybeWatchCA(cmd, watch, interval, format.Structured(), render)
		},
	}
	addCAOutputFlag(cmd, &output)
	addCAWatchFlags(cmd, &watch, &interval)
	return cmd
}

func newCAShowCommand() *cobra.Command {
	var (
		output   string
		watch    bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "show <ca-id>",
		Short: "Show a CA's full detail (incl. activation history)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			render := func() error {
				var c caadmin.CA
				if derr := api.Do(cmd.Context(), "GET", caAPIBase+"/"+url.PathEscape(args[0]), nil, &c); derr != nil {
					return derr
				}
				return caadmin.RenderCA(cmd.OutOrStdout(), c, format)
			}
			return runMaybeWatchCA(cmd, watch, interval, format.Structured(), render)
		},
	}
	addCAOutputFlag(cmd, &output)
	addCAWatchFlags(cmd, &watch, &interval)
	return cmd
}

func newCACreateCommand() *cobra.Command {
	var (
		output     string
		passphrase string
	)
	cmd := &cobra.Command{
		Use:   "create <key-id>",
		Short: "Generate a new Ed25519 CA",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			pass, err := caPassphrase(passphrase)
			if err != nil {
				return err
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			body := map[string]string{"key_id": args[0], "passphrase": pass}
			var c caadmin.CA
			if derr := api.Do(cmd.Context(), "POST", caAPIBase+"/generate", body, &c); derr != nil {
				return derr
			}
			if !format.Structured() {
				fmt.Fprintf(cmd.OutOrStdout(), "Created CA %s.\n", c.KeyID)
			}
			return caadmin.RenderCA(cmd.OutOrStdout(), c, format)
		},
	}
	addCAOutputFlag(cmd, &output)
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "storage passphrase (or set "+caPassphraseEnv+")")
	return cmd
}

func newCAImportCommand() *cobra.Command {
	var (
		output     string
		passphrase string
		keyFile    string
	)
	cmd := &cobra.Command{
		Use:   "import <key-id>",
		Short: "Import an existing OpenSSH private key as a CA",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			if strings.TrimSpace(keyFile) == "" {
				return fmt.Errorf("--private-key-file is required")
			}
			keyBytes, err := os.ReadFile(keyFile)
			if err != nil {
				return fmt.Errorf("reading private key: %w", err)
			}
			pass, err := caPassphrase(passphrase)
			if err != nil {
				return err
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			body := map[string]string{
				"key_id":      args[0],
				"private_key": string(keyBytes),
				"passphrase":  pass,
			}
			var c caadmin.CA
			if derr := api.Do(cmd.Context(), "POST", caAPIBase+"/import", body, &c); derr != nil {
				return derr
			}
			if !format.Structured() {
				fmt.Fprintf(cmd.OutOrStdout(), "Imported CA %s.\n", c.KeyID)
			}
			return caadmin.RenderCA(cmd.OutOrStdout(), c, format)
		},
	}
	addCAOutputFlag(cmd, &output)
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "passphrase that decrypts the imported key (or set "+caPassphraseEnv+")")
	cmd.Flags().StringVar(&keyFile, "private-key-file", "", "path to the OpenSSH private key to import")
	return cmd
}

func newCAExportCommand() *cobra.Command {
	var (
		output string
		all    bool
	)
	cmd := &cobra.Command{
		Use:   "export [ca-id]",
		Short: "Export a CA public key (or the whole active bundle with --all)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			if all || len(args) == 0 {
				var b caadmin.PublicBundle
				if derr := api.Do(cmd.Context(), "GET", caAPIBase+"/bundle", nil, &b); derr != nil {
					return derr
				}
				if format.Structured() {
					return caadmin.RenderBundle(cmd.OutOrStdout(), b, format)
				}
				out := cmd.OutOrStdout()
				for _, k := range b.Keys {
					fmt.Fprintln(out, k.PublicKey)
				}
				return nil
			}
			var k caadmin.PublicKey
			if derr := api.Do(cmd.Context(), "GET", caAPIBase+"/"+url.PathEscape(args[0])+"/public-key", nil, &k); derr != nil {
				return derr
			}
			return caadmin.RenderPublicKey(cmd.OutOrStdout(), k, format)
		},
	}
	addCAOutputFlag(cmd, &output)
	cmd.Flags().BoolVar(&all, "all", false, "export every active CA public key")
	return cmd
}

func newCARotateCommand() *cobra.Command {
	var (
		output     string
		passphrase string
		keyID      string
	)
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Guided rotation: generate a new CA and report fleet rollout",
		Long: "Generates a new active CA (so the fleet starts trusting it) and reports the " +
			"current active CA, the new CA, the fleet rollout percentage, and the machines still " +
			"on the previous generation. The previous CA(s) stay active during overlap; retire " +
			"them only after the fleet converges on the new generation.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			pass, err := caPassphrase(passphrase)
			if err != nil {
				return err
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			body := map[string]string{"passphrase": pass}
			if strings.TrimSpace(keyID) != "" {
				body["key_id"] = keyID
			}
			var r caadmin.RotationResult
			if derr := api.Do(cmd.Context(), "POST", caAPIBase+"/rotate", body, &r); derr != nil {
				return derr
			}
			return caadmin.RenderRotation(cmd.OutOrStdout(), r, format)
		},
	}
	addCAOutputFlag(cmd, &output)
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "storage passphrase (or set "+caPassphraseEnv+")")
	cmd.Flags().StringVar(&keyID, "key-id", "", "key id for the new CA (default: timestamped)")
	return cmd
}

// newCALifecycleCommand builds enable/disable, which POST to .../{id}/{action}
// and return the updated CA.
func newCALifecycleCommand(action, short string) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   action + " <ca-id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			var c caadmin.CA
			path := fmt.Sprintf("%s/%s/%s", caAPIBase, url.PathEscape(args[0]), action)
			if derr := api.Do(cmd.Context(), "POST", path, nil, &c); derr != nil {
				return derr
			}
			if !format.Structured() {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s is now %s.\n", action, c.KeyID, c.Status)
			}
			return caadmin.RenderCA(cmd.OutOrStdout(), c, format)
		},
	}
	addCAOutputFlag(cmd, &output)
	return cmd
}

func newCARetireCommand() *cobra.Command {
	var (
		output string
		force  bool
		yes    bool
	)
	cmd := &cobra.Command{
		Use:   "retire <ca-id>",
		Short: "Retire a disabled CA (destroys key material; keeps history)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			if !yes && !format.Structured() {
				return fmt.Errorf("refusing to retire %q without --yes (this destroys the key material)", args[0])
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			body := map[string]bool{"force": force}
			var c caadmin.CA
			path := fmt.Sprintf("%s/%s/retire", caAPIBase, url.PathEscape(args[0]))
			if derr := api.Do(cmd.Context(), "POST", path, body, &c); derr != nil {
				return derr
			}
			if !format.Structured() {
				fmt.Fprintf(cmd.OutOrStdout(), "Retired CA %s.\n", c.KeyID)
			}
			return caadmin.RenderCA(cmd.OutOrStdout(), c, format)
		},
	}
	addCAOutputFlag(cmd, &output)
	cmd.Flags().BoolVar(&force, "force", false, "retire even if machines may still depend on the key")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the irreversible retirement")
	return cmd
}

func newCADeleteCommand() *cobra.Command {
	var (
		output string
		force  bool
		yes    bool
	)
	cmd := &cobra.Command{
		Use:   "delete <ca-id>",
		Short: "Permanently delete an unused (disabled) CA",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			if !yes && !format.Structured() {
				return fmt.Errorf("refusing to delete %q without --yes (this is irreversible)", args[0])
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			path := caAPIBase + "/" + url.PathEscape(args[0])
			if force {
				path += "?force=true"
			}
			var r caadmin.DeleteResult
			if derr := api.Do(cmd.Context(), "DELETE", path, nil, &r); derr != nil {
				return derr
			}
			return caadmin.RenderDelete(cmd.OutOrStdout(), r, format)
		},
	}
	addCAOutputFlag(cmd, &output)
	cmd.Flags().BoolVar(&force, "force", false, "delete even if machines may still depend on the key")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the irreversible delete")
	return cmd
}

func newCAStatsCommand() *cobra.Command {
	var (
		output   string
		watch    bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show aggregate signing statistics (issued counts per CA)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			render := func() error {
				var s caadmin.Stats
				if derr := api.Do(cmd.Context(), "GET", caAPIBase+"/stats", nil, &s); derr != nil {
					return derr
				}
				return caadmin.RenderStats(cmd.OutOrStdout(), s, format)
			}
			return runMaybeWatchCA(cmd, watch, interval, format.Structured(), render)
		},
	}
	addCAOutputFlag(cmd, &output)
	addCAWatchFlags(cmd, &watch, &interval)
	return cmd
}

func newCARolloutCommand() *cobra.Command {
	var (
		output   string
		watch    bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "rollout",
		Short: "Show machine rollout status across CA generations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			render := func() error {
				var r caadmin.Rollout
				if derr := api.Do(cmd.Context(), "GET", "/api/v1/admin/bundle/status", nil, &r); derr != nil {
					return derr
				}
				return caadmin.RenderRollout(cmd.OutOrStdout(), r, format)
			}
			return runMaybeWatchCA(cmd, watch, interval, format.Structured(), render)
		},
	}
	addCAOutputFlag(cmd, &output)
	addCAWatchFlags(cmd, &watch, &interval)
	return cmd
}

func newCACurrentCommand() *cobra.Command {
	var (
		output   string
		watch    bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "current",
		Short: "Show the currently active CA bundle (enabled CAs)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			render := func() error {
				var b caadmin.PublicBundle
				if derr := api.Do(cmd.Context(), "GET", caAPIBase+"/bundle", nil, &b); derr != nil {
					return derr
				}
				return caadmin.RenderBundle(cmd.OutOrStdout(), b, format)
			}
			return runMaybeWatchCA(cmd, watch, interval, format.Structured(), render)
		},
	}
	addCAOutputFlag(cmd, &output)
	addCAWatchFlags(cmd, &watch, &interval)
	return cmd
}

func newCAPublicKeyCommand() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "public-key <ca-id>",
		Short: "Print a CA's public key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			var k caadmin.PublicKey
			if derr := api.Do(cmd.Context(), "GET", caAPIBase+"/"+url.PathEscape(args[0])+"/public-key", nil, &k); derr != nil {
				return derr
			}
			return caadmin.RenderPublicKey(cmd.OutOrStdout(), k, format)
		},
	}
	addCAOutputFlag(cmd, &output)
	return cmd
}

func newCAFingerprintCommand() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "fingerprint [ca-id]",
		Short: "Print a CA's fingerprint, or the bundle fingerprint with no id",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			format, err := caadmin.ParseFormat(output)
			if err != nil {
				return err
			}
			api, err := app.caClient()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				var b caadmin.PublicBundle
				if derr := api.Do(cmd.Context(), "GET", caAPIBase+"/bundle", nil, &b); derr != nil {
					return derr
				}
				if format.Structured() {
					return caadmin.RenderBundle(cmd.OutOrStdout(), b, format)
				}
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s  (bundle, generation %d)\n", b.Fingerprint, b.Generation)
				return err
			}
			var k caadmin.PublicKey
			if derr := api.Do(cmd.Context(), "GET", caAPIBase+"/"+url.PathEscape(args[0])+"/public-key", nil, &k); derr != nil {
				return derr
			}
			return caadmin.RenderFingerprint(cmd.OutOrStdout(), k, format)
		},
	}
	addCAOutputFlag(cmd, &output)
	return cmd
}

// addCAOutputFlag registers and reads the shared -o/--output flag.
func addCAOutputFlag(cmd *cobra.Command, out *string) {
	cmd.Flags().StringVarP(out, "output", "o", "table", "output format: table|wide|json|yaml")
}

// addCAWatchFlags registers the shared --watch / --interval flags.
func addCAWatchFlags(cmd *cobra.Command, watch *bool, interval *time.Duration) {
	cmd.Flags().BoolVarP(watch, "watch", "w", false, "continuously refresh until interrupted")
	cmd.Flags().DurationVar(interval, "interval", 2*time.Second, "refresh interval in --watch mode")
}

// runMaybeWatchCA renders once, or repeatedly when watch is set. Watch mode is
// disabled for structured output (json/yaml) where a single document is wanted.
func runMaybeWatchCA(cmd *cobra.Command, watch bool, interval time.Duration, structured bool, render func() error) error {
	if !watch || structured {
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
