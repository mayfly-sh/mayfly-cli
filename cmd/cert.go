package cmd

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mayfly-ssh/mayfly-cli/internal/certcache"
	"github.com/mayfly-ssh/mayfly-cli/internal/certs"
	"github.com/mayfly-ssh/mayfly-cli/internal/ssh"
)

func newCertCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage SSH certificates",
		Long: "Request, inspect, renew, and cache short-lived SSH user certificates. " +
			"Most users never need these commands directly — `mayfly ssh` manages " +
			"certificates automatically.",
	}
	cmd.AddCommand(
		newCertIssueCommand(),
		newCertInspectCommand(),
		newCertRenewCommand(),
		newCertCacheCommand(),
		newCertRemoveCommand(),
	)
	return cmd
}

const defaultIssueHostname = "unspecified"

// certSummary is the JSON/text view of an issued or cached certificate.
type certSummary struct {
	Action         string    `json:"action,omitempty"`
	Serial         uint64    `json:"serial"`
	Principal      string    `json:"principal"`
	Provider       string    `json:"provider"`
	Server         string    `json:"server"`
	Hostname       string    `json:"hostname"`
	KeyFingerprint string    `json:"key_fingerprint"`
	CAKeyID        string    `json:"ca_key_id"`
	CAFingerprint  string    `json:"ca_fingerprint"`
	IssuedAt       time.Time `json:"issued_at"`
	Expiry         time.Time `json:"expiry"`
	ExpiresIn      string    `json:"expires_in"`
}

func summaryFromEntry(e certcache.Entry, action string) certSummary {
	return certSummary{
		Action:         action,
		Serial:         e.Serial,
		Principal:      e.Principal,
		Provider:       e.Provider,
		Server:         e.Server,
		Hostname:       e.Hostname,
		KeyFingerprint: e.KeyFingerprint,
		CAKeyID:        e.CAKeyID,
		CAFingerprint:  e.CAFingerprint,
		IssuedAt:       e.IssuedAt.UTC(),
		Expiry:         e.Expiry.UTC(),
		ExpiresIn:      remainingString(e.Expiry),
	}
}

func remainingString(expiry time.Time) string {
	d := time.Until(expiry).Round(time.Second)
	if d <= 0 {
		return "expired"
	}
	return d.String()
}

func newCertIssueCommand() *cobra.Command {
	var jsonOut bool
	var ttl int
	cmd := &cobra.Command{
		Use:   "issue [host]",
		Short: "Issue a fresh SSH certificate for the active account",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			acct, err := app.requireActiveAccount()
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
			host := defaultIssueHostname
			if len(args) == 1 {
				host = args[0]
			}
			if ttl == 0 {
				ttl = app.Config.CertLifetimeSec
			}
			entry, err := app.certManager().Issue(cmd.Context(), api, app.identityFor(acct), host, ttl)
			if err != nil {
				return err
			}
			sum := summaryFromEntry(*entry, string(certs.ActionIssue))
			if jsonOut {
				return printJSON(cmd.OutOrStdout(), sum)
			}
			writeCertSummary(cmd.OutOrStdout(), sum)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "requested certificate lifetime in seconds (server clamps 60–3600)")
	return cmd
}

func newCertRenewCommand() *cobra.Command {
	var jsonOut bool
	var ttl int
	cmd := &cobra.Command{
		Use:   "renew [host]",
		Short: "Renew (reissue) the active account's certificate now",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app := FromContext(cmd.Context())
			acct, err := app.requireActiveAccount()
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
			host := defaultIssueHostname
			if len(args) == 1 {
				host = args[0]
			}
			if ttl == 0 {
				ttl = app.Config.CertLifetimeSec
			}
			entry, err := app.certManager().Issue(cmd.Context(), api, app.identityFor(acct), host, ttl)
			if err != nil {
				return err
			}
			sum := summaryFromEntry(*entry, string(certs.ActionRenew))
			if jsonOut {
				return printJSON(cmd.OutOrStdout(), sum)
			}
			writeCertSummary(cmd.OutOrStdout(), sum)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "requested certificate lifetime in seconds (server clamps 60–3600)")
	return cmd
}

func newCertInspectCommand() *cobra.Command {
	var jsonOut bool
	var file string
	cmd := &cobra.Command{
		Use:   "inspect [--file path]",
		Short: "Inspect the active account's cached certificate (or a file)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())

			var info *ssh.CertInfo
			var err error
			if file != "" {
				info, err = certs.InspectFile(file)
			} else {
				var acct, aerr = app.requireActiveAccount()
				if aerr != nil {
					return aerr
				}
				entry, lerr := app.certCache().Lookup(app.identityFor(acct))
				if lerr != nil {
					return lerr
				}
				if entry == nil {
					return fmt.Errorf("no cached certificate for %s; run 'mayfly cert issue'", acct.Display())
				}
				info, err = certs.InspectFile(entry.CertPath)
			}
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(cmd.OutOrStdout(), info)
			}
			writeCertInfo(cmd.OutOrStdout(), info)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	cmd.Flags().StringVar(&file, "file", "", "inspect a certificate file instead of the cache")
	return cmd
}

func newCertCacheCommand() *cobra.Command {
	var jsonOut bool
	var prune bool
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "List cached certificates (and optionally prune expired ones)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			cache := app.certCache()
			if prune {
				if _, err := cache.Prune(time.Now()); err != nil {
					return err
				}
			}
			entries, err := cache.List()
			if err != nil {
				return err
			}
			summaries := make([]certSummary, 0, len(entries))
			for _, e := range entries {
				summaries = append(summaries, summaryFromEntry(e, ""))
			}
			if jsonOut {
				return printJSON(cmd.OutOrStdout(), struct {
					Root         string        `json:"root"`
					Certificates []certSummary `json:"certificates"`
				}{Root: cache.Root(), Certificates: summaries})
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "cache: %s\n", cache.Root())
			if len(summaries) == 0 {
				fmt.Fprintln(out, "(no cached certificates)")
				return nil
			}
			for _, s := range summaries {
				fmt.Fprintf(out, "  %s/%s  serial=%d  expires_in=%s  server=%s\n",
					s.Provider, s.Principal, s.Serial, s.ExpiresIn, s.Server)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	cmd.Flags().BoolVar(&prune, "prune", false, "remove expired certificates before listing")
	return cmd
}

func newCertRemoveCommand() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove cached certificate material for the active account (or all)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			app := FromContext(cmd.Context())
			cache := app.certCache()
			out := cmd.OutOrStdout()
			if all {
				entries, err := cache.List()
				if err != nil {
					return err
				}
				for _, e := range entries {
					if _, err := cache.Remove(certcache.Identity{Profile: e.Profile, Provider: e.Provider, Subject: e.Subject, Server: e.Server}); err != nil {
						return err
					}
				}
				fmt.Fprintf(out, "Removed %d cached certificate(s)\n", len(entries))
				return nil
			}
			acct, err := app.requireActiveAccount()
			if err != nil {
				return err
			}
			removed, err := cache.Remove(app.identityFor(acct))
			if err != nil {
				return err
			}
			if !removed {
				fmt.Fprintf(out, "No cached certificate for %s\n", acct.Display())
				return nil
			}
			fmt.Fprintf(out, "Removed cached certificate for %s\n", acct.Display())
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "remove all cached certificates in the cache")
	return cmd
}

func writeCertSummary(w io.Writer, s certSummary) {
	if s.Action != "" {
		fmt.Fprintf(w, "Certificate %sd\n", s.Action)
	}
	fmt.Fprintf(w, "  principal:    %s\n", s.Principal)
	fmt.Fprintf(w, "  serial:       %d\n", s.Serial)
	fmt.Fprintf(w, "  fingerprint:  %s\n", s.KeyFingerprint)
	fmt.Fprintf(w, "  issuing CA:   %s (%s)\n", s.CAKeyID, s.CAFingerprint)
	fmt.Fprintf(w, "  valid:        %s → %s\n", s.IssuedAt.Format(time.RFC3339), s.Expiry.Format(time.RFC3339))
	fmt.Fprintf(w, "  expires in:   %s\n", s.ExpiresIn)
}

func writeCertInfo(w io.Writer, c *ssh.CertInfo) {
	fmt.Fprintf(w, "  type:               %s\n", c.Type)
	fmt.Fprintf(w, "  key id:             %s\n", c.KeyID)
	fmt.Fprintf(w, "  serial:             %d\n", c.Serial)
	fmt.Fprintf(w, "  principals:         %s\n", strings.Join(c.Principals, ", "))
	fmt.Fprintf(w, "  valid after:        %s\n", c.ValidAfter.Format(time.RFC3339))
	fmt.Fprintf(w, "  valid before:       %s\n", c.ValidBefore.Format(time.RFC3339))
	fmt.Fprintf(w, "  signature:          %s\n", c.SignatureFormat)
	fmt.Fprintf(w, "  key fingerprint:    %s\n", c.KeyFingerprint)
	fmt.Fprintf(w, "  issuing CA:         %s\n", c.CAFingerprint)
	fmt.Fprintf(w, "  critical options:   %s\n", orNone(c.CriticalOptions))
	fmt.Fprintf(w, "  extensions:         %s\n", orNone(c.Extensions))
}

func orNone(v []string) string {
	if len(v) == 0 {
		return "(none)"
	}
	return strings.Join(v, ", ")
}
