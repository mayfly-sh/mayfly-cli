// Package cmd wires the Mayfly CLI's commands onto the reusable foundation:
// layered config, client context, structured logging, the developer-mode
// profiler, the OAuth provider registry, and the credential store. Commands
// added later inherit all of this by reading the *App from the command context.
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/mayfly-ssh/mayfly-cli/internal/account"
	"github.com/mayfly-ssh/mayfly-cli/internal/clientcontext"
	"github.com/mayfly-ssh/mayfly-cli/internal/config"
	"github.com/mayfly-ssh/mayfly-cli/internal/credentials"
	"github.com/mayfly-ssh/mayfly-cli/internal/logging"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth/providers/mayflyserver"
	"github.com/mayfly-ssh/mayfly-cli/internal/performance"
	"github.com/mayfly-ssh/mayfly-cli/internal/profile"
	"github.com/mayfly-ssh/mayfly-cli/internal/version"
)

// App is the fully-assembled CLI runtime shared by every command.
type App struct {
	Config      config.Config
	Origins     config.Origins
	Context     *clientcontext.ClientContext
	Logger      *slog.Logger
	Profiler    *performance.Profiler
	Providers   *oauth.Registry
	Creds       credentials.Store
	Accounts    *account.Store
	Profiles    *profile.Store
	ProfileName string
}

// ProviderID returns the effective default provider id.
func (a *App) ProviderID() string { return a.Config.Provider }

type appKey struct{}

// FromContext retrieves the *App attached by the root command.
func FromContext(ctx context.Context) *App {
	app, _ := ctx.Value(appKey{}).(*App)
	return app
}

// globalFlags holds the parsed persistent flags, used to override config.
type globalFlags struct {
	dev          bool
	verbose      int
	server       string
	provider     string
	profile      string
	logLevel     string
	logFormat    string
	credBackend  string
	timeoutSec   int
	retries      int
	startupBegin time.Time
}

// Execute is the CLI entrypoint.
func Execute() {
	root := NewRootCommand()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// NewRootCommand builds the root cobra command and registers subcommands.
func NewRootCommand() *cobra.Command {
	gf := &globalFlags{startupBegin: time.Now()}

	root := &cobra.Command{
		Use:           "mayfly",
		Short:         "Mayfly — zero-trust SSH access CLI",
		Long:          "Mayfly issues short-lived SSH certificates via OAuth-authenticated, deny-by-default access.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			app, err := buildApp(cmd, gf)
			if err != nil {
				return err
			}
			cmd.SetContext(context.WithValue(cmd.Context(), appKey{}, app))
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, _ []string) {
			app := FromContext(cmd.Context())
			if app != nil && app.Profiler.Enabled() {
				app.Profiler.Record(performance.PhaseOverall, time.Since(gf.startupBegin))
				fmt.Fprintln(os.Stderr, "\n=== developer timing ===")
				fmt.Fprint(os.Stderr, app.Profiler.Table())
			}
		},
	}

	flags := root.PersistentFlags()
	flags.BoolVar(&gf.dev, "dev", false, "developer mode: measure and print per-phase timings")
	flags.CountVarP(&gf.verbose, "verbose", "v", "increase log verbosity (-v, -vv, -vvv)")
	flags.StringVar(&gf.server, "server", "", "Mayfly server URL (overrides config)")
	flags.StringVar(&gf.provider, "provider", "", "OAuth provider id (e.g. github, keycloak)")
	flags.StringVar(&gf.profile, "profile", "", "configuration profile to use")
	flags.StringVar(&gf.logLevel, "log-level", "", "log level: debug|info|warn|error")
	flags.StringVar(&gf.logFormat, "log-format", "", "log format: text|json")
	flags.StringVar(&gf.credBackend, "credential-backend", "", "credential backend: auto|keyring|file")
	flags.IntVar(&gf.timeoutSec, "timeout", 0, "request timeout in seconds")
	flags.IntVar(&gf.retries, "retries", -1, "max request retries")

	root.AddCommand(newVersionCommand())
	root.AddCommand(newDiagnosticsCommand())
	root.AddCommand(newLoginCommand())
	root.AddCommand(newLogoutCommand())
	root.AddCommand(newWhoamiCommand())
	root.AddCommand(newAuthCommand())
	return root
}

// buildApp resolves configuration and constructs every shared subsystem,
// measuring startup and config phases when developer mode is active.
func buildApp(cmd *cobra.Command, gf *globalFlags) (*App, error) {
	prof := performance.New(gf.dev)
	stopStartup := prof.Start(performance.PhaseStartup)
	defer stopStartup()

	profiles := profile.NewStore(profile.DefaultPath())

	var cfg config.Config
	var origins config.Origins
	var profileName string
	if err := prof.Measure(performance.PhaseConfig, func() error {
		loader := config.NewLoader()
		c, o, err := loader.Load()
		if err != nil {
			return err
		}
		if err := profiles.Load(); err != nil {
			return err
		}
		profileName = resolveProfileName(gf, profiles)
		// Profile overlay sits below flags but above env/config: a selected
		// profile's server/provider win unless an explicit flag overrides them.
		res := profiles.Resolve(profileName, c.ServerURL, c.Provider)
		if res.ServerFromProfile {
			c.ServerURL, o["server_url"] = res.Server, config.SourceProfile
		}
		if res.ProviderFromProfile {
			c.Provider, o["provider"] = res.Provider, config.SourceProfile
		}
		config.ApplyFlags(&c, o, flagOverrides(cmd, gf))
		cfg, origins = c, o
		return nil
	}); err != nil {
		return nil, err
	}

	logger := logging.New(logging.Options{
		Level:   logging.ParseLevel(cfg.LogLevel),
		Format:  logging.Format(cfg.LogFormat),
		Verbose: gf.verbose > 0,
	})

	var store credentials.Store
	if err := prof.Measure(performance.PhaseCredentialLoad, func() error {
		s, err := credentials.Open(credentials.Backend(cfg.CredentialBackend))
		if err != nil {
			return err
		}
		store = s
		return nil
	}); err != nil {
		return nil, err
	}

	cc := clientcontext.New(store.Name())

	var registry *oauth.Registry
	if err := prof.Measure(performance.PhaseProviderDiscovery, func() error {
		r, e := buildRegistry(cfg, cc, prof)
		registry = r
		return e
	}); err != nil {
		return nil, err
	}

	accounts := account.NewStore(account.DefaultPath())
	if err := accounts.Load(); err != nil {
		return nil, err
	}

	return &App{
		Config:      cfg,
		Origins:     origins,
		Context:     cc,
		Logger:      logger,
		Profiler:    prof,
		Providers:   registry,
		Creds:       store,
		Accounts:    accounts,
		Profiles:    profiles,
		ProfileName: profileName,
	}, nil
}

// resolveProfileName picks the active profile: --profile flag, else
// MAYFLY_PROFILE, else the configured default (or "default").
func resolveProfileName(gf *globalFlags, profiles *profile.Store) string {
	if gf.profile != "" {
		return gf.profile
	}
	if v := os.Getenv("MAYFLY_PROFILE"); v != "" {
		return v
	}
	return profiles.DefaultProfile()
}

// flagOverrides converts only the flags the user actually set into overrides,
// preserving lower-precedence layers for untouched flags.
func flagOverrides(cmd *cobra.Command, gf *globalFlags) config.FlagOverride {
	o := config.FlagOverride{}
	f := cmd.Flags()
	if f.Changed("server") {
		o.ServerURL = &gf.server
	}
	if f.Changed("provider") {
		o.Provider = &gf.provider
	}
	if f.Changed("log-level") {
		o.LogLevel = &gf.logLevel
	}
	if f.Changed("log-format") {
		o.LogFormat = &gf.logFormat
	}
	if f.Changed("credential-backend") {
		o.CredentialBackend = &gf.credBackend
	}
	if f.Changed("timeout") {
		o.RequestTimeoutSec = &gf.timeoutSec
	}
	if f.Changed("retries") {
		o.Retries = &gf.retries
	}
	return o
}

// buildRegistry registers the providers used for login. Login is brokered
// through the mayfly-server (the secure, canonical path: OAuth client secrets
// stay server-side and the server enforces authorization + audit), so each
// provider is a server-backed implementation distinguished only by the provider
// id the server resolves. Adding a future provider is one Register call here.
func buildRegistry(cfg config.Config, cc *clientcontext.ClientContext, prof *performance.Profiler) (*oauth.Registry, error) {
	reg := oauth.NewRegistry()
	timeout := time.Duration(cfg.RequestTimeoutSec) * time.Second

	specs := []struct {
		id, name string
		kind     oauth.Kind
	}{
		{"github", "GitHub", oauth.KindOAuth2Device},
		{"keycloak", "Keycloak", oauth.KindOIDCDevice},
	}
	for _, s := range specs {
		p := mayflyserver.New(mayflyserver.Config{
			ID:          s.id,
			DisplayName: s.name,
			Kind:        s.kind,
			Server:      cfg.ServerURL,
			Context:     cc,
			Profiler:    prof,
			Timeout:     timeout,
			Retries:     cfg.Retries,
		})
		if err := reg.Register(p); err != nil {
			return nil, err
		}
	}
	return reg, nil
}
