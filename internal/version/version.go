// Package version exposes the CLI's build identity. The values are overridable
// at link time via -ldflags so release builds stamp real metadata while `go
// run` / tests get sensible defaults.
package version

import "runtime"

// Build metadata. Override with, e.g.:
//
//	go build -ldflags "\
//	  -X github.com/mayfly-ssh/mayfly-cli/internal/version.Version=1.2.3 \
//	  -X github.com/mayfly-ssh/mayfly-cli/internal/version.Commit=abcdef0 \
//	  -X github.com/mayfly-ssh/mayfly-cli/internal/version.Date=2026-06-30"
var (
	// Version is the semantic CLI version (e.g. "1.2.3" or "0.0.0-dev").
	Version = "0.0.0-dev"
	// Commit is the short git commit the binary was built from.
	Commit = "unknown"
	// Date is the RFC3339 build date.
	Date = "unknown"
)

// Name is the product binary name, used in user agents and credential keys.
const Name = "mayfly-cli"

// Info is an immutable snapshot of the build identity.
type Info struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
}

// Get returns the current build information.
func Get() Info {
	return Info{
		Name:      Name,
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
	}
}

// UserAgent renders the HTTP User-Agent string, e.g.
// "mayfly-cli/1.2.3 (darwin; arm64)".
func UserAgent() string {
	return Name + "/" + Version + " (" + runtime.GOOS + "; " + runtime.GOARCH + ")"
}
