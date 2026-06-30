// Package ssh provides reusable SSH diagnostics primitives that future SSH
// commands (ssh, proxy, ...) will build on. It deliberately implements NO
// commands: it only assembles argument lists, inspects certificates and
// algorithms, and times connection phases.
package ssh

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

// Verbosity mirrors OpenSSH's -v/-vv/-vvv levels.
type Verbosity int

const (
	VerbosityNone Verbosity = iota
	VerbosityV
	VerbosityVV
	VerbosityVVV
)

// Flag renders the verbosity as an OpenSSH flag ("", "-v", "-vv", "-vvv").
func (v Verbosity) Flag() string {
	switch {
	case v <= VerbosityNone:
		return ""
	case v == VerbosityV:
		return "-v"
	case v == VerbosityVV:
		return "-vv"
	default:
		return "-vvv"
	}
}

// Options describes an SSH invocation without executing it. ExtraOptions are
// passed through verbatim as `-o key=value` entries, giving full OpenSSH option
// compatibility to future commands.
type Options struct {
	User            string
	Host            string
	Port            int
	IdentityFile    string
	CertificateFile string
	Verbosity       Verbosity
	ExtraOptions    []string // raw "key=value" passthrough for -o
	ConnectTimeout  time.Duration
}

// BuildArgs assembles the argument list a future `ssh` command would exec. It
// does not run anything; it exists so verbosity and option passthrough are
// implemented once and tested in isolation.
func (o Options) BuildArgs() []string {
	var args []string
	if flag := o.Verbosity.Flag(); flag != "" {
		args = append(args, flag)
	}
	if o.Port != 0 {
		args = append(args, "-p", strconv.Itoa(o.Port))
	}
	if o.IdentityFile != "" {
		args = append(args, "-i", o.IdentityFile)
	}
	if o.CertificateFile != "" {
		args = append(args, "-o", "CertificateFile="+o.CertificateFile)
	}
	if o.ConnectTimeout > 0 {
		args = append(args, "-o", "ConnectTimeout="+strconv.Itoa(int(o.ConnectTimeout.Seconds())))
	}
	for _, opt := range o.ExtraOptions {
		args = append(args, "-o", opt)
	}
	if o.Host != "" {
		target := o.Host
		if o.User != "" {
			target = o.User + "@" + o.Host
		}
		args = append(args, target)
	}
	return args
}

// CertInfo is a parsed, non-secret view of an OpenSSH user/host certificate.
type CertInfo struct {
	Type            string    `json:"type"`
	KeyID           string    `json:"key_id"`
	Serial          uint64    `json:"serial"`
	Principals      []string  `json:"principals"`
	ValidAfter      time.Time `json:"valid_after"`
	ValidBefore     time.Time `json:"valid_before"`
	SignatureFormat string    `json:"signature_format"`
	CAFingerprint   string    `json:"ca_fingerprint"`
	Extensions      []string  `json:"extensions"`
}

// InspectCertificate parses an authorized_keys-format certificate line (e.g.
// "ssh-ed25519-cert-v01@openssh.com AAAA... comment") and summarizes it.
func InspectCertificate(authorizedKey []byte) (*CertInfo, error) {
	pub, _, _, _, err := cryptossh.ParseAuthorizedKey(authorizedKey)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	cert, ok := pub.(*cryptossh.Certificate)
	if !ok {
		return nil, fmt.Errorf("provided key is not an OpenSSH certificate")
	}

	certType := "user"
	if cert.CertType == cryptossh.HostCert {
		certType = "host"
	}

	exts := make([]string, 0, len(cert.Permissions.Extensions))
	for k := range cert.Permissions.Extensions {
		exts = append(exts, k)
	}

	return &CertInfo{
		Type:            certType,
		KeyID:           cert.KeyId,
		Serial:          cert.Serial,
		Principals:      cert.ValidPrincipals,
		ValidAfter:      time.Unix(int64(cert.ValidAfter), 0).UTC(),
		ValidBefore:     time.Unix(int64(cert.ValidBefore), 0).UTC(),
		SignatureFormat: cert.Signature.Format,
		CAFingerprint:   cryptossh.FingerprintSHA256(cert.SignatureKey),
		Extensions:      exts,
	}, nil
}

// Algorithms summarizes the SSH algorithms this build supports, for diagnostics.
type Algorithms struct {
	KeyExchanges  []string `json:"key_exchanges"`
	Ciphers       []string `json:"ciphers"`
	MACs          []string `json:"macs"`
	HostKeyAlgos  []string `json:"host_key_algorithms"`
	PublicKeyAuth []string `json:"public_key_auth_algorithms"`
}

// SupportedAlgorithms reports the algorithms negotiable by the underlying SSH
// implementation, for `-vv`-style algorithm inspection.
func SupportedAlgorithms() Algorithms {
	a := cryptossh.SupportedAlgorithms()
	return Algorithms{
		KeyExchanges:  a.KeyExchanges,
		Ciphers:       a.Ciphers,
		MACs:          a.MACs,
		HostKeyAlgos:  a.HostKeys,
		PublicKeyAuth: a.PublicKeyAuths,
	}
}

// Timer records connection phase durations for connection-timing diagnostics.
type Timer struct {
	phases []phase
}

type phase struct {
	name string
	dur  time.Duration
}

// Mark records a named phase duration.
func (t *Timer) Mark(name string, d time.Duration) {
	t.phases = append(t.phases, phase{name: name, dur: d})
}

// String renders the recorded phases as "name=duration" pairs.
func (t *Timer) String() string {
	parts := make([]string, 0, len(t.phases))
	for _, p := range t.phases {
		parts = append(parts, p.name+"="+p.dur.Round(time.Microsecond).String())
	}
	return strings.Join(parts, " ")
}
