// Package clientcontext assembles the privacy-preserving metadata that every
// CLI request carries to the server.
//
// A ClientContext is built once per CLI invocation and is stable for the life
// of the process. A fresh Request ID is generated per HTTP request, while the
// Session ID is shared across all requests in one invocation, so a single
// command (which may make several calls) is traceable end-to-end in server
// audit logs.
//
// Privacy: only non-identifying environment context is collected. MAC
// addresses, serial numbers, browser data, and installed-software inventories
// are never gathered.
package clientcontext

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/mayfly-ssh/mayfly-cli/internal/hardware"
	"github.com/mayfly-ssh/mayfly-cli/internal/machine"
	"github.com/mayfly-ssh/mayfly-cli/internal/platform"
	"github.com/mayfly-ssh/mayfly-cli/internal/version"
)

// Canonical header names. These are the wire contract with mayfly-server and
// must stay byte-for-byte in sync with the server's extractor.
const (
	HeaderRequestID       = "X-Mayfly-Request-Id"
	HeaderSessionID       = "X-Mayfly-Session-Id"
	HeaderClientVersion   = "X-Mayfly-Client-Version"
	HeaderClientBuild     = "X-Mayfly-Client-Build"
	HeaderPlatform        = "X-Mayfly-Platform"
	HeaderPlatformVersion = "X-Mayfly-Platform-Version"
	HeaderArch            = "X-Mayfly-Arch"
	HeaderHostname        = "X-Mayfly-Hostname"
	HeaderTimezone        = "X-Mayfly-Timezone"
	HeaderUTCOffset       = "X-Mayfly-UTC-Offset"
	HeaderClientTime      = "X-Mayfly-Client-Timestamp"
	HeaderLocale          = "X-Mayfly-Locale"
	HeaderMachineID       = "X-Mayfly-Machine-Id"
	HeaderSecureStorage   = "X-Mayfly-Secure-Storage"
	HeaderSSHVersion      = "X-Mayfly-SSH-Version"
	HeaderTerminal        = "X-Mayfly-Terminal"
	HeaderCI              = "X-Mayfly-CI"
	HeaderContainer       = "X-Mayfly-Container"
	HeaderHWTPM           = "X-Mayfly-HW-TPM"
	HeaderHWSecureEnclave = "X-Mayfly-HW-Secure-Enclave"
	HeaderHWKeychain      = "X-Mayfly-HW-Keychain"
	HeaderHWSecretService = "X-Mayfly-HW-Secret-Service"
)

// ClientContext is the per-invocation, privacy-preserving client identity.
type ClientContext struct {
	Version        version.Info
	Platform       platform.Info
	Hardware       hardware.Capabilities
	MachineID      string
	SessionID      string
	StorageBackend string // resolved secure-storage backend name
}

// New builds a ClientContext for the current invocation. The session ID is
// generated here; storageBackend names the credential backend in effect.
func New(storageBackend string) *ClientContext {
	return &ClientContext{
		Version:        version.Get(),
		Platform:       platform.Detect(),
		Hardware:       hardware.Detect(),
		MachineID:      machine.ID(),
		SessionID:      NewID(),
		StorageBackend: storageBackend,
	}
}

// NewID returns a fresh UUIDv4 string, used for session and request IDs.
func NewID() string { return uuid.NewString() }

// Apply writes the full client context plus the given per-request ID onto an
// outgoing request's headers. Empty values are omitted so the wire stays clean.
func (c *ClientContext) Apply(h http.Header, requestID string) {
	set := func(k, v string) {
		if v != "" {
			h.Set(k, v)
		}
	}
	setBool := func(k string, v bool) {
		if v {
			h.Set(k, "true")
		}
	}

	set(HeaderRequestID, requestID)
	set(HeaderSessionID, c.SessionID)
	set(HeaderClientVersion, c.Version.Version)
	set(HeaderClientBuild, c.Version.Commit)
	set(HeaderPlatform, c.Platform.OS)
	set(HeaderPlatformVersion, c.Platform.PlatformVersion)
	set(HeaderArch, c.Platform.Arch)
	set(HeaderHostname, c.Platform.Hostname)
	set(HeaderTimezone, c.Platform.Timezone)
	set(HeaderUTCOffset, c.Platform.UTCOffset)
	set(HeaderClientTime, c.Platform.LocalTimestamp)
	set(HeaderLocale, c.Platform.Locale)
	set(HeaderMachineID, c.MachineID)
	set(HeaderSecureStorage, c.StorageBackend)
	set(HeaderSSHVersion, c.Platform.SSHVersion)
	set(HeaderTerminal, c.Platform.Terminal)
	setBool(HeaderCI, c.Platform.IsCI)
	setBool(HeaderContainer, c.Platform.IsContainer)
	setBool(HeaderHWTPM, c.Hardware.TPM)
	setBool(HeaderHWSecureEnclave, c.Hardware.SecureEnclave)
	setBool(HeaderHWKeychain, c.Hardware.Keychain)
	setBool(HeaderHWSecretService, c.Hardware.SecretService)
}
