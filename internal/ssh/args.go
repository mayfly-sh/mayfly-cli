package ssh

import (
	"fmt"
	"strconv"
	"strings"
)

// Parsed is the result of splitting a `mayfly ssh` invocation into Mayfly
// control flags and the OpenSSH passthrough (options + target + remote command).
//
// Mayfly long flags are intercepted only for an explicit, collision-free set
// (--profile, --server, --ttl, --dev, --dry-run, --no-cache). Every other token
// — including all single-dash OpenSSH options and unknown future options — is
// forwarded verbatim so OpenSSH compatibility is preserved.
type Parsed struct {
	Profile string
	Server  string
	TTL     int
	HasTTL  bool
	Dev     bool
	DryRun  bool
	NoCache bool
	Help    bool

	Options []string // OpenSSH options/flags appearing before the target
	Target  string   // [user@]host
	User    string
	Host    string
	Command []string // remote command tokens after the target
}

// valueOpts are the OpenSSH single-dash options that consume a following value.
var valueOpts = map[string]bool{
	"-B": true, "-b": true, "-c": true, "-D": true, "-E": true, "-e": true,
	"-F": true, "-I": true, "-i": true, "-J": true, "-L": true, "-l": true,
	"-m": true, "-O": true, "-o": true, "-p": true, "-Q": true, "-R": true,
	"-S": true, "-W": true, "-w": true,
}

// ParseArgs splits raw `mayfly ssh` args. It returns an error only for malformed
// Mayfly flags (e.g. a non-integer --ttl); OpenSSH option validation is left to
// OpenSSH itself.
func ParseArgs(args []string) (*Parsed, error) {
	p := &Parsed{}
	for i := 0; i < len(args); i++ {
		a := args[i]

		// Once a target is found, the remainder is the remote command, passed
		// through untouched (so e.g. `mayfly ssh host -- ls -la` works).
		if p.Target != "" {
			p.Command = append(p.Command, args[i:]...)
			break
		}

		name, val, hasVal := splitFlag(a)
		switch name {
		case "--help", "-h":
			p.Help = true
		case "--dev":
			p.Dev = true
		case "--dry-run":
			p.DryRun = true
		case "--no-cache":
			p.NoCache = true
		case "--profile":
			v, ni, err := flagValue(name, val, hasVal, args, i)
			if err != nil {
				return nil, err
			}
			p.Profile, i = v, ni
		case "--server":
			v, ni, err := flagValue(name, val, hasVal, args, i)
			if err != nil {
				return nil, err
			}
			p.Server, i = v, ni
		case "--ttl":
			v, ni, err := flagValue(name, val, hasVal, args, i)
			if err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("--ttl must be an integer number of seconds: %q", v)
			}
			p.TTL, p.HasTTL, i = n, true, ni
		default:
			if strings.HasPrefix(a, "-") && len(a) > 1 {
				p.Options = append(p.Options, a)
				if valueOpts[a] {
					if i+1 >= len(args) {
						return nil, fmt.Errorf("option %s requires a value", a)
					}
					i++
					p.Options = append(p.Options, args[i])
				}
				continue
			}
			// First bare token is the SSH target.
			p.Target = a
			if u, h, ok := splitTarget(a); ok {
				p.User, p.Host = u, h
			} else {
				p.Host = a
			}
		}
	}
	return p, nil
}

// splitFlag separates "--name=value" into ("--name", "value", true); otherwise
// returns (token, "", false).
func splitFlag(a string) (name, val string, hasVal bool) {
	if !strings.HasPrefix(a, "--") {
		return a, "", false
	}
	if eq := strings.IndexByte(a, '='); eq >= 0 {
		return a[:eq], a[eq+1:], true
	}
	return a, "", false
}

func flagValue(name, val string, hasVal bool, args []string, i int) (string, int, error) {
	if hasVal {
		return val, i, nil
	}
	if i+1 >= len(args) {
		return "", i, fmt.Errorf("flag %s requires a value", name)
	}
	return args[i+1], i + 1, nil
}

func splitTarget(t string) (user, host string, ok bool) {
	if at := strings.LastIndexByte(t, '@'); at > 0 {
		return t[:at], t[at+1:], true
	}
	return "", "", false
}
