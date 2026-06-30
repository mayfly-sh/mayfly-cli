package clientcontext

import (
	"net/http"
	"testing"
)

func TestApplySetsHeadersAndOmitsEmpty(t *testing.T) {
	cc := New("encrypted-file")
	cc.SessionID = "session-123"

	h := http.Header{}
	cc.Apply(h, "request-456")

	if got := h.Get(HeaderRequestID); got != "request-456" {
		t.Errorf("%s = %q", HeaderRequestID, got)
	}
	if got := h.Get(HeaderSessionID); got != "session-123" {
		t.Errorf("%s = %q", HeaderSessionID, got)
	}
	if got := h.Get(HeaderSecureStorage); got != "encrypted-file" {
		t.Errorf("%s = %q", HeaderSecureStorage, got)
	}
	if got := h.Get(HeaderMachineID); got == "" {
		t.Errorf("%s should be set", HeaderMachineID)
	}
	if got := h.Get(HeaderClientVersion); got == "" {
		t.Errorf("%s should be set", HeaderClientVersion)
	}
}

func TestApplyBoolHeadersOnlyWhenTrue(t *testing.T) {
	cc := New("file")
	cc.Platform.IsCI = false
	cc.Platform.IsContainer = true

	h := http.Header{}
	cc.Apply(h, "rid")

	if _, ok := h[http.CanonicalHeaderKey(HeaderCI)]; ok {
		t.Errorf("%s should be omitted when false", HeaderCI)
	}
	if got := h.Get(HeaderContainer); got != "true" {
		t.Errorf("%s = %q, want true", HeaderContainer, got)
	}
}

func TestNewIDIsUnique(t *testing.T) {
	if NewID() == NewID() {
		t.Error("NewID returned duplicate values")
	}
}

func TestPrivacyHeadersAbsent(t *testing.T) {
	// Guard against accidental privacy regressions: no header name should hint
	// at MAC / serial / browser collection.
	cc := New("file")
	h := http.Header{}
	cc.Apply(h, "rid")
	for name := range h {
		for _, banned := range []string{"Mac", "Serial", "Browser"} {
			if name == "X-Mayfly-"+banned {
				t.Errorf("privacy-sensitive header present: %s", name)
			}
		}
	}
}
