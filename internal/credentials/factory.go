package credentials

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/mayfly-ssh/mayfly-cli/internal/hardware"
)

// Backend selects which credential store to use.
type Backend string

const (
	// BackendAuto chooses the strongest backend available on the host.
	BackendAuto Backend = "auto"
	// BackendKeyring forces the OS keystore.
	BackendKeyring Backend = "keyring"
	// BackendFile forces the encrypted-file fallback.
	BackendFile Backend = "file"
)

// Open returns a Store for the requested backend. With BackendAuto it picks the
// OS keystore when one is expected to be available, otherwise the encrypted
// file. Callers can force a backend (e.g. headless CI) via configuration.
func Open(backend Backend) (Store, error) {
	switch backend {
	case BackendKeyring:
		return &keyringStore{name: keyringName()}, nil
	case BackendFile:
		return newFileStore(defaultFilePath()), nil
	case BackendAuto, "":
		if keystoreLikely() {
			return &keyringStore{name: keyringName()}, nil
		}
		return newFileStore(defaultFilePath()), nil
	default:
		return nil, fmt.Errorf("unknown credential backend %q", backend)
	}
}

// keystoreLikely reports whether an OS keystore is expected to work without an
// interactive prompt failure. This is a heuristic; if it is wrong, callers can
// override the backend explicitly.
func keystoreLikely() bool {
	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	case "linux":
		return hardware.Detect().SecretService
	default:
		return false
	}
}

// keyringName reports the human-facing backend name for the current OS.
func keyringName() string {
	switch runtime.GOOS {
	case "darwin":
		return "keychain"
	case "windows":
		return "windows-credential-manager"
	case "linux":
		return "secret-service"
	default:
		return "os-keystore"
	}
}

func defaultFilePath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "mayfly", "credentials.json")
	}
	return filepath.Join(dir, "mayfly", "credentials.json")
}
