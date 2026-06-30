package machine

import (
	"regexp"
	"testing"
)

func TestIDIsStableAndHashed(t *testing.T) {
	a := ID()
	b := ID()
	if a != b {
		t.Errorf("ID not stable: %q != %q", a, b)
	}
	if matched, _ := regexp.MatchString(`^[0-9a-f]{64}$`, a); !matched {
		t.Errorf("ID is not 64 hex chars: %q", a)
	}
}

func TestHashedHidesRawSource(t *testing.T) {
	h := hashed("super-secret-machine-id")
	if h == "super-secret-machine-id" {
		t.Error("hashed returned the raw value")
	}
	if hashed("a") == hashed("b") {
		t.Error("hashed collisions for distinct inputs")
	}
}
