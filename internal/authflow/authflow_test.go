package authflow

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mayfly-ssh/mayfly-cli/internal/account"
	"github.com/mayfly-ssh/mayfly-cli/internal/oauth"
	"github.com/mayfly-ssh/mayfly-cli/internal/performance"
)

type memTokenStore struct{ m map[string]*oauth.Token }

func (s *memTokenStore) Save(provider, acct string, t *oauth.Token) error {
	s.m[provider+"/"+acct] = t
	return nil
}
func (s *memTokenStore) Load(provider, acct string) (*oauth.Token, error) {
	if t, ok := s.m[provider+"/"+acct]; ok {
		return t, nil
	}
	return nil, oauth.ErrNoToken
}
func (s *memTokenStore) Delete(provider, acct string) error {
	delete(s.m, provider+"/"+acct)
	return nil
}

type stubProvider struct {
	states   []oauth.PollState
	i        int
	starts   int
	startErr error
}

func (p *stubProvider) Metadata() oauth.Metadata {
	return oauth.Metadata{ID: "stub", DisplayName: "Stub", Kind: oauth.KindOAuth2Device}
}
func (p *stubProvider) StartDeviceAuthorization(context.Context) (*oauth.DeviceAuthorization, error) {
	p.starts++
	if p.startErr != nil {
		return nil, p.startErr
	}
	return &oauth.DeviceAuthorization{
		DeviceCode: "dc", UserCode: "WXYZ-1234",
		VerificationURI: "https://example.test/device", Interval: 1,
	}, nil
}
func (p *stubProvider) PollToken(context.Context, string) (*oauth.PollResult, error) {
	st := oauth.PollApproved
	if p.i < len(p.states) {
		st = p.states[p.i]
		p.i++
	}
	if st == oauth.PollApproved {
		return &oauth.PollResult{State: st, Token: &oauth.Token{AccessToken: "secret-access"}}, nil
	}
	return &oauth.PollResult{State: st}, nil
}
func (p *stubProvider) FetchIdentity(context.Context, *oauth.Token) (*oauth.Identity, error) {
	return &oauth.Identity{Provider: "stub", Subject: "42", Username: "vasugarg", Email: "v@example.test"}, nil
}

func newAccounts(t *testing.T) *account.Store {
	t.Helper()
	s := account.NewStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLoginPersistsAccountTokenAndActive(t *testing.T) {
	tokens := &memTokenStore{m: map[string]*oauth.Token{}}
	accts := newAccounts(t)
	var out bytes.Buffer

	acct, err := Login(context.Background(), Options{
		Provider: &stubProvider{states: []oauth.PollState{oauth.PollApproved}},
		Tokens:   tokens,
		Accounts: accts,
		Profile:  "default",
		Server:   "https://srv",
		Profiler: performance.New(false),
		Out:      &out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if acct.Username != "vasugarg" || acct.Provider != "stub" {
		t.Fatalf("account = %+v", acct)
	}
	// Active account set.
	if a, ok := accts.Active("default"); !ok || a.ID() != "stub:42" {
		t.Fatalf("active = %+v ok=%v", a, ok)
	}
	// Token stored under the namespaced credential key.
	if _, err := tokens.Load("stub", acct.CredentialAccount()); err != nil {
		t.Fatalf("token not stored: %v", err)
	}
	// User-facing output shows the non-secret code/URL and never the token.
	s := out.String()
	if !strings.Contains(s, "WXYZ-1234") || !strings.Contains(s, "Logged in as stub/vasugarg") {
		t.Fatalf("output missing expected content: %q", s)
	}
	if strings.Contains(s, "secret-access") {
		t.Fatalf("output leaked the access token: %q", s)
	}
}

func TestLoginRetriesOnExpiry(t *testing.T) {
	tokens := &memTokenStore{m: map[string]*oauth.Token{}}
	accts := newAccounts(t)
	p := &stubProvider{states: []oauth.PollState{oauth.PollExpired, oauth.PollApproved}}

	_, err := Login(context.Background(), Options{
		Provider: p, Tokens: tokens, Accounts: accts, Profile: "default",
		Profiler: performance.New(false), Out: &bytes.Buffer{}, MaxAttempts: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.starts != 2 {
		t.Fatalf("expected 2 device-auth starts on expiry+retry, got %d", p.starts)
	}
}

func TestLoginCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before polling

	_, err := Login(ctx, Options{
		Provider: &stubProvider{states: []oauth.PollState{oauth.PollPending}},
		Tokens:   &memTokenStore{m: map[string]*oauth.Token{}},
		Accounts: newAccounts(t),
		Profile:  "default",
		Profiler: performance.New(false),
		Out:      &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	_ = time.Now
}
