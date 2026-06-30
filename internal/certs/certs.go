// Package certs implements the certificate lifecycle the SSH experience depends
// on: requesting certificates from the server, caching them, and transparently
// deciding whether to reuse, renew, or reissue. It never hands an expired
// certificate to OpenSSH.
//
// The server issues principal-based user certificates (the principal is derived
// from the authenticated identity, not the request), so a single cached
// certificate is valid for every host the identity may reach; the cache is keyed
// by identity rather than by host. There is no server-side renewal endpoint, so
// "renew" is simply a fresh issuance.
package certs

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/mayfly-ssh/mayfly-cli/internal/certcache"
	"github.com/mayfly-ssh/mayfly-cli/internal/performance"
	"github.com/mayfly-ssh/mayfly-cli/internal/ssh"
	"github.com/mayfly-ssh/mayfly-cli/internal/sshkey"
)

// IssuePath is the server route that signs a user certificate.
const IssuePath = "/api/v1/certificates/issue"

// Doer is the subset of the HTTP client the manager needs (satisfied by
// *client.Client). Keeping it an interface makes the lifecycle unit-testable.
type Doer interface {
	Do(ctx context.Context, method, path string, reqBody, respOut any) error
}

// issueRequest mirrors the server's IssueCertificateRequest wire shape.
type issueRequest struct {
	PublicKey  string `json:"public_key"`
	Hostname   string `json:"hostname"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

// IssueResponse mirrors the server's CertificateResponse wire shape.
type IssueResponse struct {
	Certificate   string `json:"certificate"`
	Serial        uint64 `json:"serial"`
	ValidAfter    string `json:"valid_after"`
	ValidBefore   string `json:"valid_before"`
	TTLSeconds    uint32 `json:"ttl_seconds"`
	Principal     string `json:"principal"`
	Fingerprint   string `json:"fingerprint"`
	CAKeyID       string `json:"ca_key_id"`
	CAFingerprint string `json:"ca_fingerprint"`
}

// Action records what the lifecycle decided to do.
type Action string

const (
	ActionReuse Action = "reuse"
	ActionIssue Action = "issue"
	ActionRenew Action = "renew"
)

// Manager ties the cache and profiler together to implement the lifecycle.
type Manager struct {
	cache *certcache.Cache
	prof  *performance.Profiler
}

// NewManager returns a lifecycle manager over a cache.
func NewManager(cache *certcache.Cache, prof *performance.Profiler) *Manager {
	return &Manager{cache: cache, prof: prof}
}

// EnsureOptions configures a reuse/renew/issue decision.
type EnsureOptions struct {
	Identity       certcache.Identity
	Hostname       string
	TTLSeconds     int
	RenewThreshold time.Duration
	ForceRenew     bool
	// Now overrides the clock (tests). Defaults to time.Now.
	Now func() time.Time
}

// Result reports the outcome of Ensure.
type Result struct {
	Entry    certcache.Entry
	Action   Action
	KeyPath  string
	CertPath string
}

// Ensure returns usable key + certificate paths for the identity, reusing a
// cached certificate when it has more than RenewThreshold remaining, otherwise
// reissuing. An expired certificate is never returned for reuse.
func (m *Manager) Ensure(ctx context.Context, api Doer, o EnsureOptions) (*Result, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}

	var cached *certcache.Entry
	if err := m.prof.Measure(performance.PhaseCacheLookup, func() error {
		e, err := m.cache.Lookup(o.Identity)
		cached = e
		return err
	}); err != nil {
		return nil, fmt.Errorf("cache lookup: %w", err)
	}

	action := ActionIssue
	if cached != nil {
		switch {
		case o.ForceRenew:
			action = ActionRenew
		case cached.Expired(now()):
			action = ActionRenew
		case cached.Remaining(now()) <= o.RenewThreshold:
			action = ActionRenew
		default:
			// Reuse: verify it parses and is genuinely still valid before
			// presenting it to OpenSSH.
			if err := m.verify(cached, now()); err == nil {
				return &Result{Entry: *cached, Action: ActionReuse, KeyPath: cached.KeyPath, CertPath: cached.CertPath}, nil
			}
			action = ActionRenew
		}
	}

	entry, err := m.issue(ctx, api, o.Identity, o.Hostname, o.TTLSeconds)
	if err != nil {
		return nil, err
	}
	// A freshly minted certificate is verified against the real wall clock (the
	// server issued it just now); the injected clock only drives the cache
	// reuse/renew decision above.
	if err := m.verify(entry, time.Now()); err != nil {
		return nil, fmt.Errorf("issued certificate failed verification: %w", err)
	}
	return &Result{Entry: *entry, Action: action, KeyPath: entry.KeyPath, CertPath: entry.CertPath}, nil
}

// Issue always requests and caches a fresh certificate (used by `cert issue`
// and `cert renew`).
func (m *Manager) Issue(ctx context.Context, api Doer, id certcache.Identity, hostname string, ttl int) (*certcache.Entry, error) {
	return m.issue(ctx, api, id, hostname, ttl)
}

func (m *Manager) issue(ctx context.Context, api Doer, id certcache.Identity, hostname string, ttl int) (*certcache.Entry, error) {
	kp, err := sshkey.Generate(fmt.Sprintf("mayfly:%s/%s", id.Provider, id.Subject))
	if err != nil {
		return nil, err
	}

	var resp IssueResponse
	if err := m.prof.Measure(performance.PhaseCertRequest, func() error {
		return api.Do(ctx, "POST", IssuePath, issueRequest{
			PublicKey:  kp.PublicAuthorizedKey,
			Hostname:   hostname,
			TTLSeconds: ttl,
		}, &resp)
	}); err != nil {
		return nil, fmt.Errorf("requesting certificate: %w", err)
	}

	issuedAt, err := time.Parse(time.RFC3339, resp.ValidAfter)
	if err != nil {
		return nil, fmt.Errorf("parsing valid_after: %w", err)
	}
	expiry, err := time.Parse(time.RFC3339, resp.ValidBefore)
	if err != nil {
		return nil, fmt.Errorf("parsing valid_before: %w", err)
	}

	entry := certcache.Entry{
		Serial:         resp.Serial,
		Principal:      resp.Principal,
		KeyFingerprint: resp.Fingerprint,
		CAKeyID:        resp.CAKeyID,
		CAFingerprint:  resp.CAFingerprint,
		Hostname:       hostname,
		IssuedAt:       issuedAt,
		Expiry:         expiry,
	}
	stored, err := m.cache.Save(id, kp.PrivatePEM, kp.PublicAuthorizedKey, resp.Certificate, entry)
	if err != nil {
		return nil, fmt.Errorf("caching certificate: %w", err)
	}
	return stored, nil
}

// verify parses the cached certificate file and confirms it is currently valid.
func (m *Manager) verify(e *certcache.Entry, now time.Time) error {
	return m.prof.Measure(performance.PhaseCertVerify, func() error {
		if e.Expired(now) {
			return fmt.Errorf("certificate expired at %s", e.Expiry.Format(time.RFC3339))
		}
		info, err := InspectFile(e.CertPath)
		if err != nil {
			return err
		}
		if now.Before(info.ValidAfter) {
			return fmt.Errorf("certificate not yet valid")
		}
		if !now.Before(info.ValidBefore) {
			return fmt.Errorf("certificate expired")
		}
		return nil
	})
}

// Inspect parses an OpenSSH certificate (authorized_keys line) into a summary.
func Inspect(authorizedKey []byte) (*ssh.CertInfo, error) {
	return ssh.InspectCertificate(authorizedKey)
}

// InspectFile reads and parses a certificate file.
func InspectFile(path string) (*ssh.CertInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.InspectCertificate(data)
}
