// Package machine derives a stable, opaque, privacy-preserving machine
// identifier.
//
// The returned ID is a SHA-256 hash of an OS-provided stable identifier (or a
// persisted random fallback) namespaced to Mayfly. The raw OS identifier never
// leaves the host: only its hash is exposed, so the server can correlate
// requests from the same device without learning a hardware serial, MAC
// address, or any reversible machine fingerprint.
package machine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const namespace = "mayfly-machine-id:v1:"

var (
	once   sync.Once
	cached string
)

// ID returns the stable, namespaced machine identifier (64 hex chars). It is
// computed once per process and cached.
func ID() string {
	once.Do(func() {
		cached = hashed(rawSource())
	})
	return cached
}

func hashed(raw string) string {
	sum := sha256.Sum256([]byte(namespace + raw))
	return hex.EncodeToString(sum[:])
}

// rawSource returns the best available stable identifier without exposing it.
// It is only ever fed into a one-way hash.
func rawSource() string {
	if id := osMachineID(); id != "" {
		return id
	}
	return persistedFallback()
}

func osMachineID() string {
	switch runtime.GOOS {
	case "linux":
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if data, err := os.ReadFile(p); err == nil {
				if v := strings.TrimSpace(string(data)); v != "" {
					return v
				}
			}
		}
	}
	return ""
}

// persistedFallback reads, or creates once, a random identifier stored in the
// user config directory. This keeps the machine ID stable across runs on
// platforms without a readable OS machine-id, while revealing nothing about the
// hardware.
func persistedFallback() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		// Last resort: derive from hostname so the value is at least stable
		// within a session. Hostname is already shared in ClientContext.
		host, _ := os.Hostname()
		return "hostname:" + host
	}
	path := filepath.Join(dir, "mayfly", "machine-id")
	if data, err := os.ReadFile(path); err == nil {
		if v := strings.TrimSpace(string(data)); v != "" {
			return v
		}
	}
	id := randomHex()
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(id), 0o600)
	return id
}

func randomHex() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// rand.Read never returns an error on supported platforms; if it
		// somehow does, fall back to a fixed marker rather than panicking.
		return "fallback-no-entropy"
	}
	return hex.EncodeToString(buf)
}
