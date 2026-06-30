package browser

import (
	"runtime"
	"testing"
)

func TestCommandPerOS(t *testing.T) {
	name, args := Command("https://example.test/x?a=1&b=2")
	if len(args) == 0 {
		t.Fatal("expected at least one argument")
	}
	switch runtime.GOOS {
	case "darwin":
		if name != "open" {
			t.Fatalf("darwin launcher = %q", name)
		}
	case "windows":
		if name != "rundll32" {
			t.Fatalf("windows launcher = %q", name)
		}
	default:
		if name != "xdg-open" {
			t.Fatalf("default launcher = %q", name)
		}
	}
	// The URL must always be the final argument, untouched.
	if args[len(args)-1] != "https://example.test/x?a=1&b=2" {
		t.Fatalf("url arg = %q", args[len(args)-1])
	}
}
