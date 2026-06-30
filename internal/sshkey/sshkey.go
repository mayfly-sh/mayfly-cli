// Package sshkey generates and serializes the Ed25519 key material the CLI uses
// to request SSH user certificates. The private key is written in OpenSSH PEM
// format so the system `ssh` client can consume it directly via `-i`; the public
// key is emitted as a single authorized_keys line for the issuance request.
//
// Only Ed25519 is supported: it matches the server CA and the project's
// Ed25519-everywhere policy.
package sshkey

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	cryptossh "golang.org/x/crypto/ssh"
)

// KeyPair is a freshly generated or loaded Ed25519 SSH key pair.
type KeyPair struct {
	// PrivatePEM is the OpenSSH-format private key (write at mode 0600).
	PrivatePEM []byte
	// PublicAuthorizedKey is the single-line authorized_keys public key,
	// suitable as the `public_key` field of a certificate issuance request.
	PublicAuthorizedKey string
	// Fingerprint is the SHA256 fingerprint of the public key (SHA256:...).
	Fingerprint string
}

// Generate creates a new Ed25519 key pair. The comment is embedded in the
// OpenSSH private key and the public line (purely informational).
func Generate(comment string) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return fromKeys(pub, priv, comment)
}

func fromKeys(pub ed25519.PublicKey, priv ed25519.PrivateKey, comment string) (*KeyPair, error) {
	block, err := cryptossh.MarshalPrivateKey(crypto.PrivateKey(priv), comment)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	line := cryptossh.MarshalAuthorizedKey(sshPub) // includes trailing newline
	pubLine := string(line)
	if comment != "" {
		// MarshalAuthorizedKey emits "<type> <base64>\n"; append a comment.
		pubLine = fmt.Sprintf("%s %s\n", trimNewline(pubLine), comment)
	}
	return &KeyPair{
		PrivatePEM:          pem.EncodeToMemory(block),
		PublicAuthorizedKey: pubLine,
		Fingerprint:         cryptossh.FingerprintSHA256(sshPub),
	}, nil
}

// PublicFingerprint returns the SHA256 fingerprint of an authorized_keys line.
func PublicFingerprint(authorizedKey []byte) (string, error) {
	pub, _, _, _, err := cryptossh.ParseAuthorizedKey(authorizedKey)
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	return cryptossh.FingerprintSHA256(pub), nil
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
