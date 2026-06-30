// Package browser opens a URL in the user's default browser, best-effort.
//
// It is intentionally tiny and side-effect-isolated: callers always have a
// manual copy/paste fallback, so a launch failure (headless host, CI, SSH
// session) is never fatal.
package browser

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Command returns the launcher program and arguments for the current OS to open
// url. Exposed (and pure) so it can be unit-tested without spawning a process.
func Command(url string) (string, []string) {
	switch runtime.GOOS {
	case "darwin":
		return "open", []string{url}
	case "windows":
		// rundll32 avoids cmd.exe quoting pitfalls with URLs containing '&'.
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default: // linux, *bsd
		return "xdg-open", []string{url}
	}
}

// Open launches the default browser at url. Returns an error if the launcher is
// missing or fails to start; callers should fall back to manual instructions.
func Open(url string) error {
	name, args := Command(url)
	path, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("no browser launcher (%s) available: %w", name, err)
	}
	cmd := exec.Command(path, args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to launch browser: %w", err)
	}
	// Reap the child so it does not become a zombie; ignore its exit status.
	go func() { _ = cmd.Wait() }()
	return nil
}
