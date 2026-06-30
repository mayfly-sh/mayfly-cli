// Package caadmin holds the client-side types and renderers for the
// `mayfly ca` certificate-authority administration commands. It mirrors the
// mayfly-server `CaView` / `CaStats` / `RotationResult` / `PublicBundle` JSON
// shapes and turns them into the table, wide, JSON, and YAML output the CLI
// prints. Rendering is pure and io.Writer-based so it is fully unit-testable
// (golden output).
package caadmin

// CA is the client view of a server `CaView`. Field tags match the server JSON
// byte-for-byte so the same struct decodes the response and encodes the
// `--output json` form. Private key material is never present.
type CA struct {
	ID                 string            `json:"id" yaml:"id"`
	KeyID              string            `json:"key_id" yaml:"key_id"`
	PublicKey          string            `json:"public_key" yaml:"public_key"`
	Fingerprint        string            `json:"fingerprint" yaml:"fingerprint"`
	Enabled            bool              `json:"enabled" yaml:"enabled"`
	CreatedAt          string            `json:"created_at" yaml:"created_at"`
	EnabledAt          string            `json:"enabled_at,omitempty" yaml:"enabled_at,omitempty"`
	DisabledAt         string            `json:"disabled_at,omitempty" yaml:"disabled_at,omitempty"`
	LastUsedAt         string            `json:"last_used_at,omitempty" yaml:"last_used_at,omitempty"`
	IssuedCertificates int64             `json:"issued_certificates" yaml:"issued_certificates"`
	DisabledGeneration *int64            `json:"disabled_generation,omitempty" yaml:"disabled_generation,omitempty"`
	Status             string            `json:"status" yaml:"status"`
	InCurrentBundle    bool              `json:"in_current_bundle" yaml:"in_current_bundle"`
	AgeSeconds         int64             `json:"age_seconds" yaml:"age_seconds"`
	BundleGeneration   int64             `json:"bundle_generation" yaml:"bundle_generation"`
	ActivationHistory  []ActivationEvent `json:"activation_history" yaml:"activation_history"`
}

// ActivationEvent mirrors the server `CaActivationEvent`.
type ActivationEvent struct {
	Event      string `json:"event" yaml:"event"`
	At         string `json:"at" yaml:"at"`
	Generation *int64 `json:"generation,omitempty" yaml:"generation,omitempty"`
}

// Usage mirrors the server `CaUsage` line in stats.
type Usage struct {
	ID                 string `json:"id" yaml:"id"`
	KeyID              string `json:"key_id" yaml:"key_id"`
	Enabled            bool   `json:"enabled" yaml:"enabled"`
	IssuedCertificates int64  `json:"issued_certificates" yaml:"issued_certificates"`
	LastUsedAt         string `json:"last_used_at,omitempty" yaml:"last_used_at,omitempty"`
}

// Stats mirrors the server `CaStats`.
type Stats struct {
	TotalCAs                int64   `json:"total_cas" yaml:"total_cas"`
	EnabledCAs              int64   `json:"enabled_cas" yaml:"enabled_cas"`
	DisabledCAs             int64   `json:"disabled_cas" yaml:"disabled_cas"`
	TotalIssuedCertificates int64   `json:"total_issued_certificates" yaml:"total_issued_certificates"`
	Generation              int64   `json:"generation" yaml:"generation"`
	BundleFingerprint       string  `json:"bundle_fingerprint" yaml:"bundle_fingerprint"`
	PerCA                   []Usage `json:"per_ca" yaml:"per_ca"`
}

// BundleKey mirrors the server `CaPublicKeyEntry` published in the bundle.
type BundleKey struct {
	KeyID       string `json:"key_id" yaml:"key_id"`
	PublicKey   string `json:"public_key" yaml:"public_key"`
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
}

// PublicBundle mirrors the server `PublicBundle` (active CAs).
type PublicBundle struct {
	Generation  int64       `json:"generation" yaml:"generation"`
	Fingerprint string      `json:"fingerprint" yaml:"fingerprint"`
	Keys        []BundleKey `json:"keys" yaml:"keys"`
}

// PublicKey mirrors the server export response (`CaPublicKeyEntry`).
type PublicKey struct {
	KeyID       string `json:"key_id" yaml:"key_id"`
	PublicKey   string `json:"public_key" yaml:"public_key"`
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
}

// GenerationCount mirrors the server `GenerationCount`.
type GenerationCount struct {
	Generation int64 `json:"generation" yaml:"generation"`
	Count      int64 `json:"count" yaml:"count"`
}

// Rollout mirrors the server `FleetStatus` (machine rollout per generation).
type Rollout struct {
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

// RotationResult mirrors the server `RotationResult` returned by `ca rotate`.
type RotationResult struct {
	NewCA          CA       `json:"new_ca" yaml:"new_ca"`
	PreviousActive []CA     `json:"previous_active" yaml:"previous_active"`
	Rollout        Rollout  `json:"rollout" yaml:"rollout"`
	Warnings       []string `json:"warnings" yaml:"warnings"`
}

// DeleteResult mirrors the server delete response.
type DeleteResult struct {
	Deleted bool   `json:"deleted" yaml:"deleted"`
	ID      string `json:"id" yaml:"id"`
	KeyID   string `json:"key_id" yaml:"key_id"`
}
