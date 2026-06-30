package certs_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/mayfly-ssh/mayfly-cli/internal/certcache"
	"github.com/mayfly-ssh/mayfly-cli/internal/certs"
)

// fakeIssuer signs issuance requests with a throwaway CA and counts calls.
type fakeIssuer struct {
	ca    cryptossh.Signer
	calls int
	ttl   int
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeIssuer{ca: signer}
}

func (f *fakeIssuer) Do(_ context.Context, _, _ string, reqBody, respOut any) error {
	f.calls++
	raw, _ := json.Marshal(reqBody)
	var req struct {
		PublicKey  string `json:"public_key"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	_ = json.Unmarshal(raw, &req)
	userPub, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		return err
	}
	now := time.Now()
	ttl := f.ttl
	if ttl == 0 {
		ttl = 300
	}
	cert := &cryptossh.Certificate{
		Key:             userPub,
		Serial:          uint64(now.UnixNano()),
		CertType:        cryptossh.UserCert,
		KeyId:           "mayfly:test",
		ValidPrincipals: []string{"tester"},
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(time.Duration(ttl) * time.Second).Unix()),
		Permissions:     cryptossh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	if err := cert.SignCert(rand.Reader, f.ca); err != nil {
		return err
	}
	out := respOut.(*certs.IssueResponse)
	*out = certs.IssueResponse{
		Certificate:   string(cryptossh.MarshalAuthorizedKey(cert)),
		Serial:        cert.Serial,
		ValidAfter:    time.Unix(int64(cert.ValidAfter), 0).UTC().Format(time.RFC3339),
		ValidBefore:   time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339),
		TTLSeconds:    uint32(ttl),
		Principal:     "tester",
		Fingerprint:   cryptossh.FingerprintSHA256(userPub),
		CAKeyID:       "mayfly-ca",
		CAFingerprint: cryptossh.FingerprintSHA256(f.ca.PublicKey()),
	}
	return nil
}

func newManager(t *testing.T) (*certs.Manager, certcache.Identity) {
	t.Helper()
	cache := certcache.New(t.TempDir())
	id := certcache.Identity{Profile: "default", Provider: "github", Subject: "123", Server: "https://s"}
	return certs.NewManager(cache, nil), id
}

func TestEnsureIssuesThenReuses(t *testing.T) {
	mgr, id := newManager(t)
	iss := newFakeIssuer(t)
	ctx := context.Background()
	opts := certs.EnsureOptions{Identity: id, Hostname: "h", RenewThreshold: 60 * time.Second}

	first, err := mgr.Ensure(ctx, iss, opts)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	if first.Action != certs.ActionIssue {
		t.Fatalf("first action = %s, want issue", first.Action)
	}

	second, err := mgr.Ensure(ctx, iss, opts)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if second.Action != certs.ActionReuse {
		t.Fatalf("second action = %s, want reuse", second.Action)
	}
	if iss.calls != 1 {
		t.Fatalf("issuer called %d times, want 1 (second should reuse cache)", iss.calls)
	}
	if first.CertPath != second.CertPath {
		t.Errorf("reuse should return the same cert path")
	}
}

func TestEnsureRenewsNearExpiry(t *testing.T) {
	mgr, id := newManager(t)
	iss := newFakeIssuer(t)
	iss.ttl = 300
	ctx := context.Background()

	if _, err := mgr.Ensure(ctx, iss, certs.EnsureOptions{Identity: id, Hostname: "h", RenewThreshold: 60 * time.Second}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Advance the clock to within the renew threshold of expiry.
	near := time.Now().Add(280 * time.Second)
	res, err := mgr.Ensure(ctx, iss, certs.EnsureOptions{
		Identity: id, Hostname: "h", RenewThreshold: 60 * time.Second,
		Now: func() time.Time { return near },
	})
	if err != nil {
		t.Fatalf("renew ensure: %v", err)
	}
	if res.Action != certs.ActionRenew {
		t.Fatalf("action = %s, want renew", res.Action)
	}
	if iss.calls != 2 {
		t.Fatalf("issuer called %d times, want 2", iss.calls)
	}
}

func TestEnsureForceRenew(t *testing.T) {
	mgr, id := newManager(t)
	iss := newFakeIssuer(t)
	ctx := context.Background()
	if _, err := mgr.Ensure(ctx, iss, certs.EnsureOptions{Identity: id, RenewThreshold: time.Second}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	res, err := mgr.Ensure(ctx, iss, certs.EnsureOptions{Identity: id, RenewThreshold: time.Second, ForceRenew: true})
	if err != nil {
		t.Fatalf("force renew: %v", err)
	}
	if res.Action != certs.ActionRenew || iss.calls != 2 {
		t.Fatalf("action=%s calls=%d, want renew/2", res.Action, iss.calls)
	}
}

func TestEnsureExpiredNeverReused(t *testing.T) {
	mgr, id := newManager(t)
	iss := newFakeIssuer(t)
	iss.ttl = 60
	ctx := context.Background()
	if _, err := mgr.Ensure(ctx, iss, certs.EnsureOptions{Identity: id, RenewThreshold: 0}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	future := time.Now().Add(2 * time.Hour)
	res, err := mgr.Ensure(ctx, iss, certs.EnsureOptions{
		Identity: id, RenewThreshold: 0,
		Now: func() time.Time { return future },
	})
	if err != nil {
		t.Fatalf("ensure after expiry: %v", err)
	}
	if res.Action != certs.ActionRenew || iss.calls != 2 {
		t.Fatalf("expired cert must be reissued: action=%s calls=%d", res.Action, iss.calls)
	}
}

func TestInspectIssuedCertificate(t *testing.T) {
	mgr, id := newManager(t)
	iss := newFakeIssuer(t)
	res, err := mgr.Ensure(context.Background(), iss, certs.EnsureOptions{Identity: id, RenewThreshold: 60 * time.Second})
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	info, err := certs.InspectFile(res.CertPath)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if info.Type != "user" {
		t.Errorf("type=%s", info.Type)
	}
	if len(info.Principals) != 1 || info.Principals[0] != "tester" {
		t.Errorf("principals=%v", info.Principals)
	}
	if info.KeyFingerprint == "" || info.CAFingerprint == "" {
		t.Errorf("missing fingerprints: %+v", info)
	}
}
