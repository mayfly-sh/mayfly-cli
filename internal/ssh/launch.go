package ssh

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
)

// ExitError carries the exit code of the launched OpenSSH process so the CLI can
// propagate it faithfully.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return "ssh exited with code " + itoa(e.Code)
}

// BinaryPath resolves the system OpenSSH client, returning the discovered path.
func BinaryPath() (string, error) {
	return exec.LookPath("ssh")
}

// Exec runs the system OpenSSH client with args, inheriting the parent's stdio
// so OpenSSH controls the terminal and its output is unchanged. A non-zero exit
// is returned as *ExitError; the CLI maps that to the same process exit code.
func Exec(ctx context.Context, name string, args []string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return &ExitError{Code: ee.ExitCode()}
	}
	return err
}

// RenderCommand renders a copy-pasteable command line for --dry-run / diagnostics.
// It quotes any argument containing whitespace.
func RenderCommand(name string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, name)
	for _, a := range args {
		if strings.ContainsAny(a, " \t") {
			parts = append(parts, "'"+a+"'")
		} else {
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, " ")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
