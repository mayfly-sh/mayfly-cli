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

	"github.com/mayfly-ssh/mayfly-cli/internal/clientcontext"
	"github.com/mayfly-ssh/mayfly-cli/internal/config"
	"github.com/mayfly-ssh/mayfly-cli/internal/credentials"
	"github.com/mayfly-ssh/mayfly-cli/internal/logging"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth/providers/github"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth/providers/keycloak"
	"github.com/mayfly-ssh/mayfly-cli/internal/performance"
	"github.com/mayfly-ssh/mayfly-cli/internal/version"
)

// App is the fully-assembled CLI runtime shared by every command.
type App struct {
	Config    config.Config
	Origins   config.Origins
	Context   *clientcontext.ClientContext
	Logger    *slog.Logger
	Profiler  *performance.Profiler
	Providers *oauth.Registry
	Creds     credentials.Store
}

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
	flags.StringVar(&gf.logLevel, "log-level", "", "log level: debug|info|warn|error")
	flags.StringVar(&gf.logFormat, "log-format", "", "log format: text|json")
	flags.StringVar(&gf.credBackend, "credential-backend", "", "credential backend: auto|keyring|file")
	flags.IntVar(&gf.timeoutSec, "timeout", 0, "request timeout in seconds")
	flags.IntVar(&gf.retries, "retries", -1, "max request retries")

	root.AddCommand(newVersionCommand())
	root.AddCommand(newDiagnosticsCommand())
	return root
}

// buildApp resolves configuration and constructs every shared subsystem,
// measuring startup and config phases when developer mode is active.
func buildApp(cmd *cobra.Command, gf *globalFlags) (*App, error) {
	prof := performance.New(gf.dev)
	stopStartup := prof.Start(performance.PhaseStartup)
	defer stopStartup()

	var cfg config.Config
	var origins config.Origins
	if err := prof.Measure(performance.PhaseConfig, func() error {
		loader := config.NewLoader()
		c, o, err := loader.Load()
		if err != nil {
			return err
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

	registry, err := buildRegistry(cfg)
	if err != nil {
		return nil, err
	}

	return &App{
		Config:    cfg,
		Origins:   origins,
		Context:   cc,
		Logger:    logger,
		Profiler:  prof,
		Providers: registry,
		Creds:     store,
	}, nil
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

// buildRegistry registers the providers compiled into this build. Adding a
// future provider is one Register call here plus its implementation package —
// no other code changes.
func buildRegistry(cfg config.Config) (*oauth.Registry, error) {
	reg := oauth.NewRegistry()

	gh := github.New(github.Config{
		ClientID: os.Getenv("MAYFLY_GITHUB_CLIENT_ID"),
		Scopes:   envOr("MAYFLY_GITHUB_SCOPES", "read:user user:email"),
	}, nil)
	if err := reg.Register(gh); err != nil {
		return nil, err
	}

	kc := keycloak.New(keycloak.Config{
		IssuerURL:    os.Getenv("MAYFLY_KEYCLOAK_ISSUER"),
		ClientID:     os.Getenv("MAYFLY_KEYCLOAK_CLIENT_ID"),
		ClientSecret: os.Getenv("MAYFLY_KEYCLOAK_CLIENT_SECRET"),
		Scopes:       os.Getenv("MAYFLY_KEYCLOAK_SCOPES"),
	}, nil)
	if err := reg.Register(kc); err != nil {
		return nil, err
	}

	return reg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
