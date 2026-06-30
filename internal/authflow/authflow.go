// Package authflow orchestrates the interactive device-authorization login on
// top of the 011A foundation (oauth provider + credential-backed token store +
// account index). It handles rendering, optional browser launch with a manual
// fallback, polling with progress, cancellation, retry-on-expiry, identity
// resolution, and credential persistence — and is profiled in developer mode.
//
// Security: it prints only the (non-secret) user code and verification URL. It
// NEVER prints access tokens, refresh tokens, or credential contents, and stores
// the token only through the credential-backed token store.
package authflow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mayfly-ssh/mayfly-cli/internal/account"
	"github.com/mayfly-ssh/mayfly-cli/internal/browser"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth"
	"github.com/mayfly-ssh/mayfly-cli/internal/performance"
)

// ErrCancelled is returned when the user cancels (e.g. Ctrl-C) during login.
var ErrCancelled = errors.New("login cancelled")

// Options configures a login.
type Options struct {
	Provider    oauth.Provider
	Tokens      oauth.TokenStore
	Accounts    *account.Store
	Profile     string
	Server      string
	Profiler    *performance.Profiler
	Out         io.Writer
	OpenBrowser bool
	// Opener launches a URL; defaults to browser.Open. Overridable for tests.
	Opener func(string) error
	// MaxAttempts bounds device-flow restarts on code expiry (default 1).
	MaxAttempts int
}

// Login runs the device-authorization flow and persists the resulting account.
func Login(ctx context.Context, o Options) (*account.Account, error) {
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.Opener == nil {
		o.Opener = browser.Open
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 1
	}
	prof := o.Profiler

	meta := o.Provider.Metadata()
	var approved *oauth.PollResult

attempts:
	for attempt := 0; attempt < o.MaxAttempts; attempt++ {
		stop := prof.Start(performance.PhaseDeviceAuth)
		session, err := oauth.StartSession(ctx, o.Provider)
		stop()
		if err != nil {
			return nil, fmt.Errorf("starting %s device authorization: %w", meta.DisplayName, err)
		}

		renderInstructions(o.Out, meta.DisplayName, session.Authorization)
		o.launchBrowser(session.Authorization)

		res, err := poll(ctx, prof, o.Out, session)
		switch {
		case err == nil:
			approved = res
			break attempts
		case errors.Is(err, errExpired):
			if attempt < o.MaxAttempts-1 {
				fmt.Fprintln(o.Out, "Code expired — requesting a new one...")
				continue
			}
			return nil, fmt.Errorf("the device code expired before authorization completed")
		default:
			return nil, err
		}
	}
	if approved == nil || approved.Token == nil {
		return nil, fmt.Errorf("login did not produce a token")
	}
	token := approved.Token

	// Resolve identity: prefer the identity returned alongside approval (server
	// flow returns it for every provider); otherwise fetch it explicitly.
	identity := approved.Identity
	if identity == nil {
		stop := prof.Start(performance.PhaseTokenExchange)
		id, err := o.Provider.FetchIdentity(ctx, token)
		stop()
		if err != nil {
			return nil, fmt.Errorf("resolving identity: %w", err)
		}
		identity = id
	}

	now := time.Now()
	acct := account.Account{
		Provider:   identity.Provider,
		Subject:    identity.Subject,
		Username:   identity.Username,
		Email:      identity.Email,
		Name:       identity.Name,
		Server:     o.Server,
		Profile:    o.Profile,
		CreatedAt:  now,
		LastUsedAt: now,
	}

	if err := prof.Measure(performance.PhaseCredentialStore, func() error {
		return o.Tokens.Save(acct.Provider, acct.CredentialAccount(), token)
	}); err != nil {
		return nil, fmt.Errorf("storing credentials: %w", err)
	}
	if err := o.Accounts.Upsert(acct); err != nil {
		return nil, fmt.Errorf("recording account: %w", err)
	}
	if err := o.Accounts.SetActive(o.Profile, acct.ID()); err != nil {
		return nil, fmt.Errorf("setting active account: %w", err)
	}

	fmt.Fprintf(o.Out, "\nLogged in as %s\n", acct.Display())
	return &acct, nil
}

func renderInstructions(out io.Writer, providerName string, auth *oauth.DeviceAuthorization) {
	uri := auth.VerificationURI
	fmt.Fprintf(out, "\nSign in to %s:\n", providerName)
	fmt.Fprintf(out, "  1. Open: %s\n", uri)
	fmt.Fprintf(out, "  2. Enter code: %s\n", auth.UserCode)
	if auth.VerificationURIComplete != "" {
		fmt.Fprintf(out, "  (or open the pre-filled URL: %s)\n", auth.VerificationURIComplete)
	}
}

func (o Options) launchBrowser(auth *oauth.DeviceAuthorization) {
	if !o.OpenBrowser {
		return
	}
	target := auth.VerificationURI
	if auth.VerificationURIComplete != "" {
		target = auth.VerificationURIComplete
	}
	stop := o.Profiler.Start(performance.PhaseBrowser)
	err := o.Opener(target)
	stop()
	if err != nil {
		fmt.Fprintln(o.Out, "  (could not open a browser automatically — please open the URL above)")
	}
}

// errExpired signals the device code expired, so the caller may retry.
var errExpired = errors.New("device code expired")

func poll(ctx context.Context, prof *performance.Profiler, out io.Writer, session *oauth.Session) (*oauth.PollResult, error) {
	stop := prof.Start(performance.PhasePolling)
	defer stop()

	interval := session.Interval()
	fmt.Fprint(out, "\nWaiting for authorization")
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(out)
			return nil, ErrCancelled
		case <-time.After(interval):
		}

		res, err := session.Poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				fmt.Fprintln(out)
				return nil, ErrCancelled
			}
			fmt.Fprintln(out)
			return nil, err
		}

		switch res.State {
		case oauth.PollPending:
			fmt.Fprint(out, ".")
		case oauth.PollSlowDown:
			interval += 5 * time.Second
			fmt.Fprint(out, ".")
		case oauth.PollApproved:
			fmt.Fprintln(out, " approved")
			return res, nil
		case oauth.PollExpired:
			return nil, errExpired
		case oauth.PollDenied:
			fmt.Fprintln(out)
			return nil, fmt.Errorf("authorization was denied")
		default:
			fmt.Fprintln(out)
			return nil, fmt.Errorf("unexpected poll state %q", res.State)
		}
	}
}
