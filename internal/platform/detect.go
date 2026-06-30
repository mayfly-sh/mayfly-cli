package platform

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// isInteractive reports whether stdout is attached to a terminal. Works on all
// platforms via the file mode (no cgo, no build tags).
func isInteractive() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// osRelease returns a best-effort, non-identifying OS version string. It never
// errors: an unknown platform yields "".
func osRelease() string {
	switch runtime.GOOS {
	case "darwin":
		if out, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
			return "macOS " + strings.TrimSpace(string(out))
		}
	case "linux":
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			if v := parseOSReleaseField(string(data), "PRETTY_NAME"); v != "" {
				return v
			}
		}
	case "windows":
		if out, err := exec.Command("cmd", "/c", "ver").Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}

func parseOSReleaseField(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.Trim(rest, `"`)
		}
	}
	return ""
}
