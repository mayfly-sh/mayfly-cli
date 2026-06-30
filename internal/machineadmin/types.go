// Package machineadmin holds the client-side types and renderers for the
// `mayfly machine` administration commands. It mirrors the mayfly-server
// `MachineView` / `FleetStatus` JSON shapes and turns them into the table,
// wide, JSON, and YAML output the CLI prints. Rendering is pure and
// io.Writer-based so it is fully unit-testable (golden output).
package machineadmin

// Machine is the client view of a server `MachineView`. Field tags match the
// server JSON byte-for-byte so the same struct decodes the response and encodes
// the `--output json` form.
type Machine struct {
	MachineID         string `json:"machine_id" yaml:"machine_id"`
	Hostname          string `json:"hostname" yaml:"hostname"`
	Status            string `json:"status" yaml:"status"`
	Liveness          string `json:"liveness" yaml:"liveness"`
	OS                string `json:"os" yaml:"os"`
	Arch              string `json:"arch" yaml:"arch"`
	AgentVersion      string `json:"agent_version" yaml:"agent_version"`
	Fingerprint       string `json:"fingerprint" yaml:"fingerprint"`
	IP                string `json:"ip,omitempty" yaml:"ip,omitempty"`
	CurrentGeneration int64  `json:"current_generation" yaml:"current_generation"`
	SyncedGeneration  *int64 `json:"synced_generation,omitempty" yaml:"synced_generation,omitempty"`
	LatestGeneration  *int64 `json:"latest_generation,omitempty" yaml:"latest_generation,omitempty"`
	UpToDate          bool   `json:"up_to_date" yaml:"up_to_date"`
	BundleFingerprint string `json:"bundle_fingerprint,omitempty" yaml:"bundle_fingerprint,omitempty"`
	LastSeen          string `json:"last_seen,omitempty" yaml:"last_seen,omitempty"`
	LastSync          string `json:"last_sync,omitempty" yaml:"last_sync,omitempty"`
	EnrolledAt        string `json:"enrolled_at" yaml:"enrolled_at"`
}

// GenerationCount mirrors the server `GenerationCount`.
type GenerationCount struct {
	Generation int64 `json:"generation" yaml:"generation"`
	Count      int64 `json:"count" yaml:"count"`
}

// Fleet is the client view of the server `FleetStatus`.
type Fleet struct {
	LatestGeneration  int64             `json:"latest_generation" yaml:"latest_generation"`
	TotalMachines     int64             `json:"total_machines" yaml:"total_machines"`
	Online            int64             `json:"online" yaml:"online"`
	Stale             int64             `json:"stale" yaml:"stale"`
	Offline           int64             `json:"offline" yaml:"offline"`
	RolloutPercentage float64           `json:"rollout_percentage" yaml:"rollout_percentage"`
	OldestGeneration  *int64            `json:"oldest_generation,omitempty" yaml:"oldest_generation,omitempty"`
	NewestGeneration  *int64            `json:"newest_generation,omitempty" yaml:"newest_generation,omitempty"`
	Generations       []GenerationCount `json:"generations" yaml:"generations"`
}

// DeleteResult mirrors the server delete response.
type DeleteResult struct {
	Deleted   bool   `json:"deleted" yaml:"deleted"`
	MachineID string `json:"machine_id" yaml:"machine_id"`
	Hostname  string `json:"hostname" yaml:"hostname"`
}

// EnrollmentToken mirrors the server re-enroll / rotate-identity response. The
// plaintext token is shown exactly once.
type EnrollmentToken struct {
	Token     string `json:"token" yaml:"token"`
	ID        string `json:"id" yaml:"id"`
	ExpiresAt string `json:"expires_at" yaml:"expires_at"`
	SingleUse bool   `json:"single_use" yaml:"single_use"`
}
