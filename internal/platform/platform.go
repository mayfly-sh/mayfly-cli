// Package platform collects privacy-preserving facts about the host the CLI is
// running on. It deliberately gathers ONLY non-identifying environment context
// (OS, architecture, timezone, terminal, CI/container detection, ...). It never
// reads MAC addresses, serial numbers, browser data, or an installed-software
// inventory.
package platform

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Info is a snapshot of the runtime environment. Every field is non-identifying
// by construction.
type Info struct {
	OS              string `json:"os"`               // runtime.GOOS
	PlatformVersion string `json:"platform_version"` // kernel/OS release, best-effort
	Arch            string `json:"arch"`             // runtime.GOARCH
	Hostname        string `json:"hostname"`
	Timezone        string `json:"timezone"`     // IANA name, e.g. "Asia/Kolkata"
	UTCOffset       string `json:"utc_offset"`   // e.g. "+05:30"
	LocalTimestamp  string `json:"local_time"`   // RFC3339 with offset
	Locale          string `json:"locale"`       // from LANG/LC_ALL, e.g. "en_US.UTF-8"
	Terminal        string `json:"terminal"`     // TERM
	SSHVersion      string `json:"ssh_version"`  // `ssh -V`, best-effort
	IsCI            bool   `json:"is_ci"`        // CI environment detected
	IsContainer     bool   `json:"is_container"` // container runtime detected
	Interactive     bool   `json:"interactive"`  // stdout is a TTY
}

// Detect gathers the current environment snapshot. It never fails: unknown
// fields are returned empty rather than erroring.
func Detect() Info {
	now := time.Now()
	zone, offsetSecs := now.Zone()
	_ = zone

	host, _ := os.Hostname()

	return Info{
		OS:              runtime.GOOS,
		PlatformVersion: osRelease(),
		Arch:            runtime.GOARCH,
		Hostname:        host,
		Timezone:        timezoneName(now),
		UTCOffset:       formatOffset(offsetSecs),
		LocalTimestamp:  now.Format(time.RFC3339),
		Locale:          locale(),
		Terminal:        os.Getenv("TERM"),
		SSHVersion:      sshVersion(),
		IsCI:            detectCI(),
		IsContainer:     detectContainer(),
		Interactive:     isInteractive(),
	}
}

func timezoneName(t time.Time) string {
	// Prefer the IANA name from the local location; fall back to the abbrev.
	if loc := t.Location(); loc != nil && loc.String() != "" && loc.String() != "Local" {
		return loc.String()
	}
	name, _ := t.Zone()
	return name
}

func formatOffset(offsetSecs int) string {
	sign := "+"
	if offsetSecs < 0 {
		sign = "-"
		offsetSecs = -offsetSecs
	}
	h := offsetSecs / 3600
	m := (offsetSecs % 3600) / 60
	return sign + twoDigits(h) + ":" + twoDigits(m)
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + itoa(n)
	}
	return itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func locale() string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// sshVersion runs `ssh -V` (which prints to stderr) with a short timeout-free
// invocation. Best-effort: returns "" if ssh is absent.
func sshVersion() string {
	path, err := exec.LookPath("ssh")
	if err != nil {
		return ""
	}
	out, err := exec.Command(path, "-V").CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// detectCI recognizes the generic CI signal and a few common providers. We only
// need a boolean; we never record which provider.
func detectCI() bool {
	for _, k := range []string{
		"CI", "CONTINUOUS_INTEGRATION", "GITHUB_ACTIONS", "GITLAB_CI",
		"BUILDKITE", "CIRCLECI", "JENKINS_URL", "TEAMCITY_VERSION",
	} {
		if v := os.Getenv(k); v != "" && v != "false" && v != "0" {
			return true
		}
	}
	return false
}

// detectContainer uses well-known container markers. Best-effort and may be
// false on hardened/minimal images; that is acceptable for informational use.
func detectContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if v := os.Getenv("container"); v != "" {
		return true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		for _, marker := range []string{"docker", "containerd", "kubepods", "libpod"} {
			if strings.Contains(s, marker) {
				return true
			}
		}
	}
	return false
}
