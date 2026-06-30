package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

func TestVerbosityFlag(t *testing.T) {
	cases := map[Verbosity]string{
		VerbosityNone: "",
		VerbosityV:    "-v",
		VerbosityVV:   "-vv",
		VerbosityVVV:  "-vvv",
	}
	for v, want := range cases {
		if got := v.Flag(); got != want {
			t.Errorf("Verbosity(%d).Flag() = %q, want %q", v, got, want)
		}
	}
}

func TestBuildArgs(t *testing.T) {
	o := Options{
		User:           "ops",
		Host:           "host.example",
		Port:           2222,
		Verbosity:      VerbosityVV,
		ExtraOptions:   []string{"StrictHostKeyChecking=yes"},
		ConnectTimeout: 10 * time.Second,
	}
	got := o.BuildArgs()
	want := []string{
		"-vv", "-p", "2222",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=yes",
		"ops@host.example",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BuildArgs() = %v, want %v", got, want)
	}
}

func TestSupportedAlgorithmsNonEmpty(t *testing.T) {
	a := SupportedAlgorithms()
	if len(a.KeyExchanges) == 0 || len(a.Ciphers) == 0 || len(a.PublicKeyAuth) == 0 {
		t.Errorf("expected non-empty algorithm lists, got %+v", a)
	}
}

func TestInspectCertificate(t *testing.T) {
	// Build a CA and a user certificate to inspect.
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, err := cryptossh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshUserPub, err := cryptossh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}

	cert := &cryptossh.Certificate{
		Key:             sshUserPub,
		Serial:          42,
		CertType:        cryptossh.UserCert,
		KeyId:           "vasugarg",
		ValidPrincipals: []string{"ops", "deploy"},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Permissions: cryptossh.Permissions{
			Extensions: map[string]string{"permit-pty": ""},
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}

	authorized := cryptossh.MarshalAuthorizedKey(cert)
	info, err := InspectCertificate(authorized)
	if err != nil {
		t.Fatalf("InspectCertificate: %v", err)
	}
	if info.Type != "user" {
		t.Errorf("Type = %q, want user", info.Type)
	}
	if info.KeyID != "vasugarg" {
		t.Errorf("KeyID = %q", info.KeyID)
	}
	if info.Serial != 42 {
		t.Errorf("Serial = %d", info.Serial)
	}
	if !reflect.DeepEqual(info.Principals, []string{"ops", "deploy"}) {
		t.Errorf("Principals = %v", info.Principals)
	}
	if info.CAFingerprint == "" {
		t.Error("CAFingerprint should be set")
	}
}

func TestInspectCertificateRejectsPlainKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := cryptossh.NewPublicKey(pub)
	if _, err := InspectCertificate(cryptossh.MarshalAuthorizedKey(sshPub)); err == nil {
		t.Error("expected error for non-certificate key")
	}
}
