package sshkey

import (
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
)

func TestGenerateProducesUsableMaterial(t *testing.T) {
	kp, err := Generate("mayfly:test")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Private key parses as an OpenSSH Ed25519 signer.
	signer, err := cryptossh.ParsePrivateKey(kp.PrivatePEM)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	if signer.PublicKey().Type() != cryptossh.KeyAlgoED25519 {
		t.Fatalf("key type = %s, want ed25519", signer.PublicKey().Type())
	}

	// Public line parses and carries the comment.
	pub, comment, _, _, err := cryptossh.ParseAuthorizedKey([]byte(kp.PublicAuthorizedKey))
	if err != nil {
		t.Fatalf("parse public line: %v", err)
	}
	if comment != "mayfly:test" {
		t.Errorf("comment=%q", comment)
	}

	// Fingerprint matches the public key and the signer's key.
	if kp.Fingerprint != cryptossh.FingerprintSHA256(pub) {
		t.Errorf("fingerprint mismatch")
	}
	if !strings.HasPrefix(kp.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint=%q", kp.Fingerprint)
	}
	if cryptossh.FingerprintSHA256(signer.PublicKey()) != kp.Fingerprint {
		t.Errorf("signer public key fingerprint differs from public line")
	}
}

func TestGenerateUnique(t *testing.T) {
	a, _ := Generate("")
	b, _ := Generate("")
	if a.Fingerprint == b.Fingerprint {
		t.Fatal("two generated keys share a fingerprint")
	}
}
