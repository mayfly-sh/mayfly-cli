// Package hardware reports, informationally, which secure-hardware and
// secure-storage capabilities are present on the host.
//
// Detection is best-effort and never required: Mayfly always functions with a
// software fallback. The capabilities are surfaced in ClientContext so the
// server (and operators) can reason about a fleet's hardware posture, and so
// future hardware-backed key implementations (TPM, Secure Enclave, HSM) can be
// selected without changing calling code.
package hardware

import (
	"os"
	"runtime"
)

// Capabilities is a snapshot of detected secure-hardware/storage features.
type Capabilities struct {
	Keychain      bool `json:"keychain"`       // macOS Keychain available
	SecretService bool `json:"secret_service"` // Linux Secret Service (DBus) available
	TPM           bool `json:"tpm"`            // TPM 2.0 device present
	SecureEnclave bool `json:"secure_enclave"` // Apple Secure Enclave likely present
}

// Detect probes the host for secure-hardware/storage capabilities. It never
// fails; absent features are reported as false.
func Detect() Capabilities {
	return Capabilities{
		Keychain:      keychainAvailable(),
		SecretService: secretServiceAvailable(),
		TPM:           tpmAvailable(),
		SecureEnclave: secureEnclaveLikely(),
	}
}

func keychainAvailable() bool {
	return runtime.GOOS == "darwin"
}

func secretServiceAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	// The Secret Service is reached over the DBus session bus; its presence is
	// a reliable, side-effect-free signal that a provider may be available.
	return os.Getenv("DBUS_SESSION_BUS_ADDRESS") != ""
}

func tpmAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	for _, dev := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if _, err := os.Stat(dev); err == nil {
			return true
		}
	}
	return false
}

// secureEnclaveLikely reports whether a Secure Enclave is probably present.
// Apple Silicon Macs always have one; Intel Macs have one only with a T2 chip,
// which we cannot detect cheaply, so we report based on architecture.
func secureEnclaveLikely() bool {
	return runtime.GOOS == "darwin" && runtime.GOARCH == "arm64"
}
